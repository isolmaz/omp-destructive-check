// Policy layers: protection modes, rule actions, coverage, target classification.
// Every probe loads a fresh module instance (verdict caches are module-global).
import { loadExt, makeCtx, callTool, bash, mkHome, fakeRegistry, installFetch, checkerRequests, check, report, results } from "./harness.mjs";

const HOME = mkHome("static");
const CWD = "C:\\scratch\\proj";
const TEMP_DIR = "C:\\Users\\dev\\AppData\\Local\\Temp\\dc-scratch";
const REG = fakeRegistry([["opencode-go", "deepseek-v4.1-flash"]]);

const cfg = (extra = {}) => ({
  enabled: true,
  mode: "medium",
  provider: "opencode-go",
  providers: { "opencode-go": { model: "deepseek-v4.1-flash" } },
  ...extra,
});

// Each probe loads a fresh module instance and threads one ctx through the handler.
async function run(event, { config = cfg(), cwd = CWD, selects = [], hasUI = true } = {}) {
  installFetch(() => ({ ok: true, status: 200, json: async () => ({ choices: [{ message: { content: "ALLOW: stub" } }] }) }));
  const ext = await loadExt({ home: HOME, config, registry: REG });
  const ctx = makeCtx({ cwd, hasUI, selects: [...selects], registry: REG });
  const result = await callTool(ext, event, ctx);
  return { ctx, result, completions: checkerRequests().length, blocked: result?.block === true };
}

const cmd = (command) => bash(command, "cleanup");

// ------------------------------------------------------- outside-project ---
for (const [command, label] of [
  ["rm -rf C:\\other\\project\\data", "absolute path outside the project"],
  ["rm -rf ../../outside", "relative path leaving the project"],
  ["rm -rf /etc", "posix system directory"],
  ["rm -rf C:\\Windows\\System32", "windows system directory"],
  ["rm -rf ~/.ssh", "credential directory"],
  ["del /f /s /q C:\\Users\\dev\\Documents", "cmd delete outside the project"],
  ['bash -c "cd / && rm -rf boot"', "shell payload outside the project"],
  ["sudo -u root rm -rf /var/log", "wrapper args outside the project"],
]) {
  for (const mode of ["simple", "medium", "hard"]) {
    const p = await run(cmd(command), { config: cfg({ mode }) });
    check(`[${mode}] outside delete blocked: ${label}`, p.blocked && p.completions === 0, JSON.stringify(p.result)?.slice(0, 200));
  }
}

// -------------------------------------------------------- inside-project ---
const INSIDE = [
  ["rm -rf src", "project source directory"],
  ["rm -rf ../proj/src", "project source via parent hop"],
  ["rm -rf components tests", "two project directories"],
];
for (const [command, label] of INSIDE) {
  const simple = await run(cmd(command), { config: cfg({ mode: "simple" }) });
  check(`[simple] inside delete allowed, no model: ${label}`, !simple.blocked && simple.completions === 0, JSON.stringify(simple.result)?.slice(0, 160));
  for (const mode of ["medium", "hard"]) {
    const p = await run(cmd(command), { config: cfg({ mode }) });
    check(`[${mode}] inside delete blocked: ${label}`, p.blocked && p.completions === 0, JSON.stringify(p.result)?.slice(0, 200));
  }
}

// -------------------------------------------------------------- artifacts ---
for (const [command, label] of [
  ["rm -rf node_modules", "node_modules"],
  ["rm -rf dist build .next", "build outputs"],
  ["rm -rf src/dist", "nested artifact"],
  [`rm -rf "${TEMP_DIR}"`, "os temp directory"],
  ["rmdir /s /q build", "cmd rmdir on a build dir"],
  ["npx rimraf dist", "package runner on an artifact"],
  ["rm -rf node_modules/*", "wildcard under an artifact"],
]) {
  for (const mode of ["simple", "medium", "hard"]) {
    const p = await run(cmd(command), { config: cfg({ mode }) });
    check(`[${mode}] artifact delete allowed without a model: ${label}`, !p.blocked && p.completions === 0, JSON.stringify(p.result)?.slice(0, 160));
  }
}

// Artifact-named targets OUTSIDE the project are not artifacts.
for (const command of ["rm -rf D:\\userdata\\out", "rm -rf C:\\Users\\dev\\.cache\\puppeteer"]) {
  for (const mode of ["medium", "hard"]) {
    const p = await run(cmd(command), { config: cfg({ mode }) });
    check(`[${mode}] artifact-named target outside the project blocked: ${command}`, p.blocked, JSON.stringify(p.result)?.slice(0, 160));
  }
}

// ---------------------------------------------------------------- dynamic ---
{
  const medium = await run(cmd('rm -rf "$UNSET_VAR/data"'), { config: cfg({ mode: "medium" }) });
  check("medium: dynamic target escalates to the model", medium.completions === 1 && !medium.blocked, JSON.stringify(medium.result));
  const hard = await run(cmd('rm -rf "$UNSET_VAR/data"'), { config: cfg({ mode: "hard" }) });
  check("hard: dynamic target blocked", hard.blocked && hard.completions === 0, JSON.stringify(hard.result));
}

// -------------------------------------------------------------------- git ---
for (const [command, label] of [
  ["git clean -fdx", "git clean"],
  ["git reset --hard HEAD~1", "git reset --hard"],
  ["git push --force origin main", "git push --force"],
  ["git branch -D feature", "git branch -D"],
  ["git stash drop", "git stash drop"],
]) {
  for (const mode of ["simple", "medium"]) {
    const p = await run(cmd(command), { config: cfg({ mode }) });
    check(`[${mode}] git command allowed: ${label}`, !p.blocked && p.completions === 0, JSON.stringify(p.result)?.slice(0, 160));
  }
  const hard = await run(cmd(command), { config: cfg({ mode: "hard" }) });
  check(`[hard] git command blocked: ${label}`, hard.blocked, JSON.stringify(hard.result)?.slice(0, 160));
}
{
  const p = await run(cmd("git status --porcelain"), { config: cfg({ mode: "hard" }) });
  check("[hard] read-only git command allowed", !p.blocked && p.completions === 0);
  const q = await run(cmd("git push --force-with-lease origin main"), { config: cfg({ mode: "hard" }) });
  check("[hard] force-with-lease is not a plain force push", !q.blocked, JSON.stringify(q.result)?.slice(0, 160));
}

// ----------------------------------------------------------------- scripts --
{
  for (const mode of ["simple", "medium"]) {
    const p = await run(cmd("bash deploy.cmd"), { config: cfg({ mode }) });
    check(`[${mode}] script execution allowed`, !p.blocked, JSON.stringify(p.result)?.slice(0, 160));
  }
  const asked = await run(cmd("bash deploy.cmd"), { config: cfg({ mode: "hard" }), selects: ["Allow once"] });
  check("[hard] script execution asks the user (allow once)", !asked.blocked, JSON.stringify(asked.result)?.slice(0, 160));
  const denied = await run(cmd("bash deploy.cmd"), { config: cfg({ mode: "hard" }), selects: ["Block"] });
  check("[hard] script execution asks the user (block)", denied.blocked, JSON.stringify(denied.result)?.slice(0, 160));
  const headless = await run(cmd("bash deploy.cmd"), { config: cfg({ mode: "hard" }), hasUI: false });
  check("[hard] script execution fails closed without a UI", headless.blocked, JSON.stringify(headless.result)?.slice(0, 160));
}

// ------------------------------------------------------------------ moves ---
for (const [command, expected] of [
  ["mv src C:\\other\\place", true],
  ["mv C:\\other\\thing src", true],
  ["mv a.ts b.ts", false],
  ["mv build /tmp/scratch", false],
]) {
  const p = await run(cmd(command), { config: cfg({ mode: "medium" }) });
  check(`move ${expected ? "blocked" : "allowed"}: ${command}`, p.blocked === expected, JSON.stringify(p.result)?.slice(0, 160));
}

// ------------------------------------------------------------------- eval ---
const evalEvent = (code, language = "py") => ({ toolName: "eval", input: { language, code, i: "delete files" } });
{
  const incident = `import shutil, os\np = r"${CWD}\\.bunusil"\nshutil.rmtree(p)\nprint("exists after:", os.path.exists(p))`;
  const p = await run(evalEvent(incident), { config: cfg({ mode: "medium" }) });
  check("eval: project-internal rmtree blocked in medium (incident repro)", p.blocked, JSON.stringify(p.result)?.slice(0, 200));

  const simple = await run(evalEvent(incident), { config: cfg({ mode: "simple" }) });
  check("eval: allowed in simple mode", !simple.blocked && simple.completions === 0, JSON.stringify(simple.result)?.slice(0, 160));

  const sys = await run(evalEvent('import shutil\nshutil.rmtree("/etc/nginx")'), { config: cfg({ mode: "simple" }) });
  check("eval: system target blocked in every mode", sys.blocked, JSON.stringify(sys.result)?.slice(0, 200));

  const art = await run(evalEvent('import shutil\nshutil.rmtree("node_modules")'), { config: cfg({ mode: "hard" }) });
  check("eval: artifact target allowed", !art.blocked && art.completions === 0, JSON.stringify(art.result)?.slice(0, 160));

  const computed = await run(evalEvent("import shutil\nshutil.rmtree(target_dir)"), { config: cfg({ mode: "hard" }) });
  check("eval: computed target blocked in hard", computed.blocked && computed.completions === 0, JSON.stringify(computed.result)?.slice(0, 160));

  const js = await run(evalEvent('const fs = require("fs");\nfs.rmSync("/etc/passwd");', "js"), { config: cfg({ mode: "simple" }) });
  check("eval js: system target blocked", js.blocked, JSON.stringify(js.result)?.slice(0, 200));

  const readOnly = await run(evalEvent("import os\nprint(os.getcwd())"), { config: cfg({ mode: "hard" }) });
  check("eval: read-only code passes untouched", !readOnly.blocked && readOnly.completions === 0);

  const ignored = await run(evalEvent(incident), { config: cfg({ mode: "hard", coverage: { eval: false } }) });
  check("coverage: eval can be turned off", !ignored.blocked, JSON.stringify(ignored.result)?.slice(0, 160));
}

// -------------------------------------------------------------- file tools --
{
  const rem = await run({ toolName: "edit", input: { input: "[src/app.ts#1A2B]\nREM", i: "drop file" } }, { config: cfg({ mode: "medium" }) });
  check("edit: REM of a project file blocked in medium", rem.blocked, JSON.stringify(rem.result)?.slice(0, 200));

  const mv = await run({ toolName: "edit", input: { input: `[a.ts#1A2B]\nMV C:\\other\\a.ts`, i: "move file" } }, { config: cfg({ mode: "medium" }) });
  check("edit: MV outside the project blocked", mv.blocked, JSON.stringify(mv.result)?.slice(0, 200));

  const patch = await run({ toolName: "apply_patch", input: { input: "*** Begin Patch\n*** Delete File: /etc/hosts\n*** End Patch", i: "drop hosts" } }, { config: cfg({ mode: "simple" }) });
  check("apply_patch: system delete blocked", patch.blocked, JSON.stringify(patch.result)?.slice(0, 200));

  const insideRem = await run({ toolName: "edit", input: { input: "[dist/bundle.js#1A2B]\nREM", i: "drop artifact" } }, { config: cfg({ mode: "hard" }) });
  check("edit: REM of an artifact allowed", !insideRem.blocked && insideRem.completions === 0, JSON.stringify(insideRem.result)?.slice(0, 160));

  const writing = await run({ toolName: "write", input: { path: `${CWD}\\src\\new.ts`, content: "export {}" } }, { config: cfg({ mode: "hard" }) });
  check("write: creating a file is never blocked", !writing.blocked);

  const off = await run({ toolName: "edit", input: { input: "[src/app.ts#1A2B]\nREM" } }, { config: cfg({ mode: "hard", coverage: { fileTools: false } }) });
  check("coverage: file tools can be turned off", !off.blocked);
}

// ------------------------------------------------------- custom rule modes --
{
  const custom = cfg({ mode: "custom", rules: { insideDelete: "ask" } });
  const allowed = await run(cmd("rm -rf src"), { config: custom, selects: ["Allow once"] });
  check("custom: insideDelete=ask allows when the user agrees", !allowed.blocked, JSON.stringify(allowed.result)?.slice(0, 160));
  const denied = await run(cmd("rm -rf src"), { config: custom, selects: ["Block"] });
  check("custom: insideDelete=ask blocks when the user declines", denied.blocked, JSON.stringify(denied.result)?.slice(0, 160));

  const modelRule = cfg({ mode: "custom", rules: { insideDelete: "model" } });
  const checked = await run(cmd("rm -rf src"), { config: modelRule });
  check("custom: insideDelete=model escalates to the checker", checked.completions === 1, `completions=${checked.completions}`);

  const freeRule = cfg({ mode: "custom", rules: { systemTarget: "allow" } });
  const free = await run(cmd("rm -rf /etc"), { config: freeRule });
  check("custom: systemTarget can be relaxed explicitly", !free.blocked, JSON.stringify(free.result)?.slice(0, 160));
}

// ------------------------------------------------------------- pass-through --
for (const command of ["ls -la", "npm test", 'grep -rn "rm -rf" src/', 'git commit -m "remove rm fallback"', "npm install rimraf", "cat build.cmd", "git status"]) {
  const p = await run(cmd(command), { config: cfg({ mode: "hard" }) });
  check(`untouched: ${command}`, !p.blocked && p.completions === 0, JSON.stringify(p.result)?.slice(0, 160));
}

// ------------------------------------------------------- status / disabled --
{
  const ext = await loadExt({ home: HOME, config: cfg({ enabled: false }), registry: REG });
  const ctx = makeCtx({ cwd: CWD });
  const r = await callTool(ext, cmd("rm -rf /etc"), ctx);
  check("enabled=false disables the guard", r === undefined);
}

const bad = report("policy modes");
process.exitCode = bad ? 1 : 0;
void results;