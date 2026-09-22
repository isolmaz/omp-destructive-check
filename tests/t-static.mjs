// Policy layers: protection modes, rule actions, coverage, target classification.
// Every probe loads a fresh module instance (verdict caches are module-global).
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { loadExt, makeCtx, callTool, bash, mkHome, fakeRegistry, installFetch, fetchResponse, checkerRequests, check, report, results } from "./harness.mjs";

const HOME = mkHome("static");
const CWD = "C:\\scratch\\proj";
const TEMP_DIR = path.join(os.tmpdir(), "dc-scratch");
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
  // Full Response shape: the checker reads the body with res.text(), and a stub
  // without it made the CLI fallback answer every test silently.
  installFetch(() => fetchResponse(200, { choices: [{ message: { content: "ALLOW: stub" } }] }));
  const ext = await loadExt({ home: HOME, config, registry: REG });
  const ctx = makeCtx({ cwd, hasUI, selects: [...selects], registry: REG });
  const result = await callTool(ext, event, ctx);
  return { ext, ctx, result, completions: checkerRequests().length, blocked: result?.block === true };
}

const cmd = (command) => bash(command, "cleanup");
const pick = (prefix) => (options) => options.map((o) => String(o?.label ?? o)).find((l) => l.startsWith(prefix));

// Every form below must be classified as an outside-the-project delete. The
// action for that rule is pinned once per mode, with a representative command:
// classification and preset action are independent knobs.
for (const [command, label] of [
  ["rm -rf C:\\other\\project\\data", "absolute path outside the project"],
  ["rm -rf ../../outside", "relative path leaving the project"],
  ["rm -rf /etc", "posix system directory"],
  ["rm -rf C:\\Windows\\System32", "windows system directory"],
  ["rm -rf ~/.ssh", "credential directory"],
  ['del /f /s /q C:\\Users\\dev\\Documents', "cmd delete outside the project"],
  ['bash -c "cd / && rm -rf boot"', "shell payload outside the project"],
  ["sudo -u root rm -rf /var/log", "wrapper args outside the project"],
]) {
  const p = await run(cmd(command), { config: cfg({ mode: "medium" }) });
  check(`outside delete blocked: ${label}`, p.blocked && p.completions === 0, JSON.stringify(p.result)?.slice(0, 200));
}
for (const mode of ["simple", "medium", "hard"]) {
  const p = await run(cmd("rm -rf C:\\other\\project\\data"), { config: cfg({ mode }) });
  check(`[${mode}] outside delete blocked without a model call`, p.blocked && p.completions === 0, JSON.stringify(p.result)?.slice(0, 200));
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

// Same split as above: artifact classification per form, preset action once.
for (const [command, label] of [
  ["rm -rf node_modules", "node_modules"],
  ["rm -rf dist build .next", "build outputs"],
  ["rm -rf src/dist", "nested artifact"],
  [`rm -rf "${TEMP_DIR}"`, "os temp directory"],
  ["rmdir /s /q build", "cmd rmdir on a build dir"],
  ["npx rimraf dist", "package runner on an artifact"],
  ["rm -rf node_modules/*", "wildcard under an artifact"],
]) {
  const p = await run(cmd(command), { config: cfg({ mode: "medium" }) });
  check(`artifact delete allowed without a model: ${label}`, !p.blocked && p.completions === 0, JSON.stringify(p.result)?.slice(0, 160));
}
for (const mode of ["simple", "medium", "hard"]) {
  const p = await run(cmd("rm -rf node_modules"), { config: cfg({ mode }) });
  check(`[${mode}] artifact delete allowed without a model call`, !p.blocked && p.completions === 0, JSON.stringify(p.result)?.slice(0, 160));
}

// Artifact-named targets OUTSIDE the project are not artifacts.
for (const command of ["rm -rf D:\\userdata\\out", "rm -rf C:\\Users\\dev\\.cache\\puppeteer"]) {
  for (const mode of ["medium", "hard"]) {
    const p = await run(cmd(command), { config: cfg({ mode }) });
    check(`[${mode}] artifact-named target outside the project blocked: ${command}`, p.blocked, JSON.stringify(p.result)?.slice(0, 160));
  }
}

// macOS exposes homes as /Users/<name>. A project inside one must be classified by
// scope (artifact / inside the project), not rejected up front as a filesystem root:
// `~` expands to the same shape, so this is the common case there, not an edge one.
{
  const posixCwd = "C:\\Users\\dev\\proj";
  const inside = await run(cmd("rm -rf /Users/dev/proj/dist"), { config: cfg({ mode: "medium" }), cwd: posixCwd });
  check("posix home path inside the project is not treated as a root", !inside.blocked && inside.completions === 0, JSON.stringify(inside.result)?.slice(0, 200));
  const home = await run(cmd("rm -rf /Users/dev"), { config: cfg({ mode: "simple" }) });
  check("a bare posix home stays protected", home.blocked, JSON.stringify(home.result)?.slice(0, 200));
  const windows = await run(cmd("rm -rf /Windows/System32"), { config: cfg({ mode: "simple" }) });
  check("posix-style /Windows path stays protected", windows.blocked, JSON.stringify(windows.result)?.slice(0, 200));
}

// ---------------------------------------------------------------- dynamic ---
{
  const medium = await run(cmd('rm -rf "$UNSET_VAR/data"'), { config: cfg({ mode: "medium" }) });
  check("medium: dynamic target escalates to the model", medium.completions === 1 && !medium.blocked, JSON.stringify(medium.result));
  const hard = await run(cmd('rm -rf "$UNSET_VAR/data"'), { config: cfg({ mode: "hard" }) });
  check("hard: dynamic target blocked", hard.blocked && hard.completions === 0, JSON.stringify(hard.result));
}
{
  // Wrappers nest: five levels of shell wrapping is past the scanner's depth
  // limit, and the cutoff must escalate, not wave the payload through.
  const nested = (levels) => {
    let inner = "rm -rf /etc";
    for (let i = 1; i < levels; i++) inner = `bash -c ${JSON.stringify(inner)}`;
    return inner;
  };
  const escaped = nested(2); // bash -c "bash -c \"rm -rf /etc\""
  const deep = nested(5);
  const shallow = await run(cmd(nested(1)), { config: cfg({ mode: "simple" }) });
  check("a single wrapper resolves its payload", shallow.blocked && /systemTarget/.test(shallow.result?.reason ?? ""), shallow.result?.reason);
  const two = await run(cmd(escaped), { config: cfg({ mode: "simple" }) });
  check("escaped quotes do not hide a nested payload", two.blocked && /systemTarget/.test(two.result?.reason ?? ""), `${JSON.stringify(two.result)?.slice(0, 160)} cmd=${escaped}`);
  const hard = await run(cmd(deep), { config: cfg({ mode: "hard" }) });
  check("hard: too-deep nesting is blocked, not ignored", hard.blocked && hard.completions === 0, `${JSON.stringify(hard.result)?.slice(0, 160)} cmd=${deep.slice(0, 90)}`);
  const medium = await run(cmd(deep), { config: cfg({ mode: "medium" }) });
  check("medium: too-deep nesting escalates to the model", medium.completions === 1, `completions=${medium.completions} blocked=${medium.blocked} cmd=${deep.slice(0, 90)}`);
}

// Each destructive git form must reach the gitDestructive rule; the preset action
// for that rule is pinned once per mode below.
for (const [command, label] of [
  ["git clean -fdx", "git clean"],
  ["git reset --hard HEAD~1", "git reset --hard"],
  ["git push --force origin main", "git push --force"],
  ["git branch -D feature", "git branch -D"],
  ["git stash drop", "git stash drop"],
]) {
  const p = await run(cmd(command), { config: cfg({ mode: "medium" }) });
  check(`destructive git reaches the checker in medium: ${label}`, p.completions === 1, `completions=${p.completions} blocked=${p.blocked}`);
}
for (const mode of ["simple", "medium", "hard"]) {
  const p = await run(cmd("git clean -fdx"), { config: cfg({ mode }) });
  const expected = mode === "hard" ? p.blocked && p.completions === 0 : mode === "medium" ? !p.blocked && p.completions === 1 : !p.blocked && p.completions === 0;
  check(`[${mode}] destructive git ${mode === "hard" ? "blocked" : mode === "medium" ? "escalated to the model" : "allowed without a model"}`, expected, JSON.stringify(p.result)?.slice(0, 160));
}

// Uncommitted work can be discarded without any flag at all: `restore` defaults
// to the worktree, `checkout <ref> -- <path>` restores from the index, and
// `switch -f`/`--discard-changes` throws the working tree away on the way out.
for (const command of [
  "git restore src/app.js",
  "git restore --source=HEAD~1 src/app.js",
  "git checkout -- src/app.js",
  "git checkout HEAD -- src/app.js",
  "git switch -f main",
  "git switch --discard-changes main",
  "git worktree remove --force ../wt",
  "git reflog expire --expire=now --all",
  "git gc --prune=now",
  "git filter-branch --force --all",
]) {
  const hard = await run(cmd(command), { config: cfg({ mode: "hard" }) });
  check(`[hard] uncommitted work destroyed: ${command}`, hard.blocked && hard.completions === 0, JSON.stringify(hard.result)?.slice(0, 160));
  const medium = await run(cmd(command), { config: cfg({ mode: "medium" }) });
  check(`[medium] escalated to the model: ${command}`, medium.completions === 1, `completions=${medium.completions} blocked=${medium.blocked}`);
  const simple = await run(cmd(command), { config: cfg({ mode: "simple" }) });
  check(`[simple] allowed without a model: ${command}`, !simple.blocked && simple.completions === 0, JSON.stringify(simple.result)?.slice(0, 160));
}

// …but these look similar and destroy nothing, so they must stay silent.
for (const command of [
  "git restore --staged src/app.js", // unstage: the working tree is kept
  "git checkout main", // git refuses when it would lose local changes
  "git switch main",
  "git switch -c feature/x",
  "git branch -d merged-feature", // refuses unmerged branches
  "git branch --delete merged-feature",
  "git gc", // plain gc only prunes unreachable objects git already dropped
  "git reflog",
  "git worktree remove ../wt", // without --force git refuses a dirty worktree
]) {
  const hard = await run(cmd(command), { config: cfg({ mode: "hard" }) });
  check(`[hard] not destructive, stays silent: ${command}`, !hard.blocked && hard.completions === 0, JSON.stringify(hard.result)?.slice(0, 160));
}
{
  const forced = await run(cmd("git branch --delete --force feature/x"), { config: cfg({ mode: "hard" }) });
  check("[hard] branch --delete --force is destructive", forced.blocked && forced.completions === 0, JSON.stringify(forced.result)?.slice(0, 160));
  const forcedShort = await run(cmd("git branch -D feature/x"), { config: cfg({ mode: "hard" }) });
  check("[hard] branch -D is destructive", forcedShort.blocked, JSON.stringify(forcedShort.result)?.slice(0, 160));
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
{
  // A file written through a language API is a write effect like any other: the
  // same classification, the same rules, and a computed target is unresolved
  // instead of a pass (`print(open('.env').read())` stays a read).
  const write = (code) => run(evalEvent(code), { config: cfg({ mode: "hard" }) });
  const env = await write("open('.env','w').write('A=1')");
  check("eval write: open('.env','w') is a protectSecrets block", env.blocked && /rule: protectSecrets/.test(String(env.result?.reason ?? "")) && env.completions === 0, JSON.stringify(env.result)?.slice(0, 200));
  const read = await write("print(open('.env').read())");
  check("eval write: open('.env') is a read and stays silent", !read.blocked && read.completions === 0, JSON.stringify(read.result)?.slice(0, 200));
  const outside = await write("shutil.copy('src/app.js','../outside/f')");
  check("eval write: a copy with an outside destination is an outsideWrite", outside.blocked && /rule: outsideWrite/.test(String(outside.result?.reason ?? "")) && outside.completions === 0, JSON.stringify(outside.result)?.slice(0, 200));
  const structured = await write("Path('.env').write_text('A=1')");
  check("eval write: Path(...).write_text names the file it rewrites", structured.blocked && /rule: protectSecrets/.test(String(structured.result?.reason ?? "")), JSON.stringify(structured.result)?.slice(0, 200));
  const computed = await write("open(target, 'w')");
  check("eval write: a computed write target is not a clean pass", computed.blocked && /rule: dynamicTargets/.test(String(computed.result?.reason ?? "")) && computed.completions === 0, JSON.stringify(computed.result)?.slice(0, 200));
  const method = await write("handle.write('x')");
  check("eval write: a method on an open handle is not a path this scan owns", !method.blocked && method.completions === 0, JSON.stringify(method.result)?.slice(0, 200));
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

  // A first-class tool writes where its path points, exactly like `echo x > …`:
  // a system file, a path outside the project, and a target the guard cannot
  // resolve are all judged, not just the credential stores.
  const hosts = await run({ toolName: "write", input: { path: "C:\\Windows\\System32\\drivers\\etc\\hosts", content: "127.0.0.1 x" } }, { config: cfg({ mode: "hard" }) });
  check("write: a system file is a systemTarget, not ordinary editing", hosts.blocked && /rule: systemTarget/.test(String(hosts.result?.reason ?? "")) && hosts.completions === 0, JSON.stringify(hosts.result)?.slice(0, 200));
  const outsidePatch = await run({ toolName: "apply_patch", input: { input: "*** Begin Patch\n*** Add File: C:\\other-project\\src\\evil.js\n+x\n*** End Patch" } }, { config: cfg({ mode: "hard" }) });
  check("apply_patch: an Add section outside the project is blocked", outsidePatch.blocked && /rule: outsideWrite/.test(String(outsidePatch.result?.reason ?? "")), JSON.stringify(outsidePatch.result)?.slice(0, 200));
  const unresolved = await run({ toolName: "write", input: { path: "%APPDATA%\\.env", content: "A=1" } }, { config: cfg({ mode: "hard" }) });
  check("write: a target the guard cannot resolve is a dynamicTargets violation", unresolved.blocked && /rule: dynamicTargets/.test(String(unresolved.result?.reason ?? "")) && unresolved.completions === 0, JSON.stringify(unresolved.result)?.slice(0, 200));
}

// --------------------------------------------------- secret paths (P0.1) ---
// A credential store is a static decision: no model call in any mode, and the
// block reason names the file rather than the pattern that matched it.
{
  const write = (target) => ({ toolName: "write", input: { path: target, content: "x", i: "update the config" } });
  for (const [target, expected, label] of [
    [`${CWD}\\.env`, true, ".env in the project"],
    [`${CWD}\\id_rsa`, true, "a private key"],
    [`${CWD}\\certs\\server.pem`, true, "a .pem"],
    [`${CWD}\\keystore.p12`, true, "a .p12"],
    [`${CWD}\\.npmrc`, true, ".npmrc"],
    [`${CWD}\\auth.json`, true, "auth.json"],
    [`${CWD}\\.git-credentials`, true, ".git-credentials"],
    [`~/.aws/credentials`, true, ".aws/credentials"],
    [`~/.ssh/id_rsa`, true, ".ssh/id_rsa"],
    [`~/.config/gh/hosts.yml`, true, "gh hosts.yml"],
    [`${CWD}\\notes.txt`, false, "an ordinary file"],
    [`${CWD}\\src\\app.ts`, false, "a source file"],
    [`${CWD}\\.env.example`, false, ".env.example is a template"],
    [`${CWD}\\.env.sample`, false, ".env.sample is a template"],
    [`${CWD}\\src\\.envrc`, false, ".envrc is not .env"],
  ]) {
    const p = await run(write(target), { config: cfg({ mode: "medium" }) });
    check(`secret write ${expected ? "blocked" : "allowed"}: ${label}`, p.blocked === expected && p.completions === 0, JSON.stringify(p.result)?.slice(0, 200));
  }
  const p = await run(write(`${CWD}\\.env`), { config: cfg({ mode: "medium" }) });
  const reason = String(p.result?.reason ?? "");
  check("secret write: the reason names the file, the rule and the mode", /^destructive-check: /.test(reason) && /rule: protectSecrets/.test(reason) && /\.env/.test(reason) && /mode: medium/.test(reason), reason);
  check("secret write: the reason keeps the retry sentence", /another tool/.test(reason), reason);
  check("secret write: no pattern is named instead of the file", !/\.env\.\*/.test(reason), reason);
}
{
  // The same rule through every other channel: a patch section, a structured
  // edit, a delete and a redirect.
  const patch = await run({ toolName: "apply_patch", input: { input: "*** Begin Patch\n*** Update File: .env\n@@\n-A=1\n+A=2\n*** End Patch", i: "bump env" } }, { config: cfg({ mode: "medium" }) });
  check("secret patch: an update section naming .env is blocked", patch.blocked && /protectSecrets/.test(String(patch.result?.reason ?? "")), JSON.stringify(patch.result)?.slice(0, 200));

  const structured = await run({ toolName: "edit", input: { path: `${CWD}\\.env`, edits: [{ op: "replace", find: "A=1", replace: "A=2" }], i: "bump env" } }, { config: cfg({ mode: "hard" }) });
  check("secret edit: the structured form's path is checked", structured.blocked && /protectSecrets/.test(String(structured.result?.reason ?? "")), JSON.stringify(structured.result)?.slice(0, 200));

  const removed = await run(cmd("rm -rf .env"), { config: cfg({ mode: "medium" }) });
  check("secret delete: rm of .env is blocked without a model call", removed.blocked && removed.completions === 0 && /protectSecrets/.test(String(removed.result?.reason ?? "")), JSON.stringify(removed.result)?.slice(0, 200));

  const redirect = await run(cmd("echo A=1 > .env"), { config: cfg({ mode: "medium" }) });
  check("secret redirect: `> .env` is blocked", redirect.blocked && /protectSecrets/.test(String(redirect.result?.reason ?? "")), JSON.stringify(redirect.result)?.slice(0, 200));
}
{
  // Mode mapping: simple asks (the user can still say yes), medium and hard block.
  const asked = await run(cmd("rm -rf .env"), { config: cfg({ mode: "simple" }), selects: ["Allow once"] });
  check("[simple] a secret delete asks the user and can be allowed once", !asked.blocked && asked.completions === 0, JSON.stringify(asked.result)?.slice(0, 200));
  const denied = await run(cmd("rm -rf .env"), { config: cfg({ mode: "simple" }), selects: ["Block"] });
  check("[simple] a secret delete blocks when the user declines", denied.blocked, JSON.stringify(denied.result)?.slice(0, 200));
  for (const mode of ["medium", "hard"]) {
    const p = await run(cmd("rm -rf .env"), { config: cfg({ mode }) });
    check(`[${mode}] a secret delete is blocked statically`, p.blocked && p.completions === 0, JSON.stringify(p.result)?.slice(0, 200));
  }
  const custom = await run(cmd("rm -rf .env"), { config: cfg({ mode: "custom", rules: { protectSecrets: "allow", insideDelete: "allow" } }) });
  check("custom: protectSecrets is a live rule that can be relaxed", !custom.blocked, JSON.stringify(custom.result)?.slice(0, 200));
}

// ------------------------------------------------------ allowDirs (P0.2) ---
// An extra scope directory that names a root, the home or a system tree does not
// widen the guard, it switches it off: those entries are refused and reported.
{
  const inside = (dirs, target) => run(cmd(`rm -rf ${target}`), { config: cfg({ mode: "simple", allowDirs: dirs }) });
  const baseline = await inside([], "C:\\shared\\libs\\generated");
  check("allowDirs: without an entry the delete is outside the project", baseline.blocked && baseline.completions === 0, JSON.stringify(baseline.result)?.slice(0, 200));
  const good = await inside(["C:\\shared\\libs"], "C:\\shared\\libs\\generated");
  check("allowDirs: a real directory widens the scope", !good.blocked && good.completions === 0, JSON.stringify(good.result)?.slice(0, 200));

  // Each row names a target *under* the entry, so the assertion fails when the
  // refusal is removed: an accepted entry would make the target inside the
  // project and `simple` would allow the delete. Where the classifier refuses the
  // target for an independent reason — a system segment is a system target
  // however wide the scope is — the /dc refusal report below carries the check.
  const rows = [
    ["C:\\", "a drive root", "C:\\shared\\libs\\generated", "filesystem root"],
    ["/", "the posix root", "C:\\shared\\libs\\generated", "filesystem root"],
    [HOME, "the user home", path.join(HOME, "notes", "draft.txt"), "user home"],
    [path.join(HOME, ".omp"), "the guard's own directory", path.join(HOME, ".omp", "logs", "old.jsonl"), "guard's own directory"],
    ["C:\\Windows", "the windows tree", "C:\\Windows\\System32\\config\\SAM", "system directories"],
    ["C:\\Program Files (x86)", "a program directory", "C:\\Program Files (x86)\\SomeApp\\data.bin", "system directories"],
    ["/etc", "a posix system directory", "/etc/nginx/nginx.conf", "system directories"],
    ["/usr/local/bin", "a posix system bin", "/usr/local/bin/old-tool", "system directories"],
    ["relative/path", "a relative path", "", "absolute path"],
    ["~", "a bare tilde", path.join(HOME, "notes", "draft.txt"), "user home"],
  ];
  for (const [entry, label, target] of rows) {
    if (!target) continue; // nothing exists under a relative entry to point at
    const p = await inside([entry], target);
    check(`allowDirs refuses ${label} (target ${target})`, p.blocked && p.completions === 0, `${entry} → ${JSON.stringify(p.result)?.slice(0, 160)}`);
  }
  // The refusal is not silent: /dc reports every entry it refused, with the
  // reason, instead of leaving the user with a setting that looks applied.
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "simple", allowDirs: [...rows.map((r) => r[0]), "C:\\shared\\libs"] }), registry: REG });
  const ctx = makeCtx({ cwd: CWD, hasUI: false, registry: REG });
  await ext.commands.get("dc").handler("", ctx);
  const report = ctx.notes.map((n) => n.message).join("\n");
  const rejectedLine = report.split("\n").find((line) => /rejected dirs/.test(line)) ?? "";
  for (const [entry, label, , reason] of rows) {
    check(`allowDirs reports refusing ${label}`, rejectedLine.includes(entry) && rejectedLine.includes(reason), rejectedLine.slice(0, 400));
  }
  check("allowDirs: /dc status reports the rejected entry and the reason", /rejected dirs/.test(report) && /C:\\ /.test(rejectedLine) && /filesystem root/.test(rejectedLine), report.slice(0, 300));
  check("allowDirs: the accepted entry is reported as scope", /shared\\libs/.test(report), report.slice(0, 300));
}

// ------------------------------------------- redirects and writes (P0.4) ---
// A redirect writes where it points; the verbs below each have their own
// argument positions, so `cp a ../out/` writes outside while `cp ../out/a .`
// only reads outside.
{
  for (const [command, expected, label] of [
    ["echo hi > ../outside.txt", true, "a redirect leaving the project"],
    ["echo hi >> ../outside.txt", true, "an append leaving the project"],
    ["echo hi > out.json", false, "a redirect inside the project"],
    ["echo hi > /tmp/dc-write.txt", false, "a redirect to the os temp dir"],
    ["echo hi > /dev/null", false, "a redirect to the null device"],
    ["echo hi > out.json 2>&1", false, "an fd duplication, not a file"],
    ["echo hi 2> err.log", false, "an stderr redirect inside the project"],
    ['echo "a > ../outside.txt"', false, "a redirect inside a quoted string"],
    ["cp src/app.js ../outside/", true, "cp writing outside"],
    ["cp ../outside/app.js src/", false, "cp reading from outside"],
    ["cp -r src ../outside/", true, "recursive cp writing outside"],
    ["mv src ../outside/", true, "mv writing outside"],
    ["truncate -s 0 ../outside/notes.txt", true, "truncate outside"],
    ["truncate -s 0 notes.txt", false, "truncate inside"],
    ["dd if=/dev/zero of=../outside/blob bs=1M count=1", true, "dd of= outside"],
    ["dd if=/dev/zero of=./zeros.bin bs=1M count=1", false, "dd of= inside"],
    ["rsync -a src/ ../outside/", true, "rsync writing outside"],
    ["rsync -a src/ dist/", false, "rsync inside the project"],
    ["rsync -a --delete ../outside/src/ dist/", true, "rsync --delete from an outside source"],
    ["chmod -R 755 ../outside/dir", true, "chmod -R outside"],
    ["chmod 755 src/app.js", false, "chmod inside"],
    ["ln -s ../outside/target link", true, "ln pointing outside"],
    ["ln -s src/app.js link", false, "ln inside the project"],
    ["npm test | tee ../outside/log.txt", true, "tee outside"],
    ["npm test | tee out.log", false, "tee inside"],
    ['sh -c "echo hi > ../outside.txt"', true, "a redirect inside a shell body"],
    ["echo hi >| ../outside.txt", true, "a noclobber redirect leaving the project"],
    ["echo hi >| out.json", false, "a noclobber redirect inside the project"],
    ["echo hi >& ../outside.txt", true, "both streams redirected to a file outside"],
    ["echo hi &> ../outside.txt", true, "&> to a file outside"],
    ["echo hi >&2", false, "stderr is a descriptor copy, not a file"],
    ["cp -t ../outside src/app.js", true, "cp -t writing outside"],
    ["cp -t src src/app.js", false, "cp -t writing inside"],
    ["cp src/app.js ../outside/ --backup=numbered", true, "a trailing option is not the destination"],
    ["cp -S .bak src/app.js ../outside/", true, "an option value is consumed, the destination is still read"],
    ["cp -S ../outside/suffix src/app.js src/app.js.copy", false, "an option value is not a write target"],
    ["install -m 644 src/app.js ../outside/", true, "install writing outside"],
    ["install -m 644 ../outside/app.js", false, "install with a single operand only reads"],
    ["curl -o ../outside/f https://example.com/x", true, "curl -o outside"],
    ["curl -O https://example.com/x", false, "curl -O writes the remote name into the cwd"],
    ["wget -O ../outside/f https://example.com/x", true, "wget -O outside"],
    ["wget -O out.bin https://example.com/x", false, "wget -O inside"],
    ["tar -xf a.tgz -C ../outside", true, "tar -C outside"],
    ["tar -xf a.tgz", false, "tar without -C extracts into the cwd"],
    ["unzip a.zip -d ../outside", true, "unzip -d outside"],
    ["sed -i s/a/b/ ../outside/f", true, "sed -i writes every operand"],
    ["sed s/a/b/ ../outside/f", false, "sed without -i only prints"],
    ["git clone https://example.com/r.git ../outside/repo", true, "git clone into an outside directory"],
    ["git clone https://example.com/r.git", false, "git clone without a destination"],
    ["cmd /c mklink /H innocent.js C:\\Users\\me\\.ssh\\id_rsa", true, "mklink /H naming a private key"],
    ["cmd /c mklink /J ../outside/link target", true, "mklink /J outside the project"],
    ["command cp src/app.js ../outside/", true, "a write behind `command`"],
    ["command tee ../outside/log", true, "a write behind `command` (tee)"],
    ["echo hi > {../outside,../tmp2}/x.txt", true, "a brace expansion is an unresolved target"],
    ["powershell -NoProfile -Command \"echo x > ../outside/f\"", true, "powershell flags before -Command"],
    ["bash -o pipefail -c 'echo x > ../outside/f'", true, "bash options before -c"],
    ["cmd /d /c \"echo x > ../outside/f\"", true, "cmd switches before /c"],
    ["wsl bash -c 'echo x > ../outside/f'", true, "wsl followed by another shell"],
    ["sudo cp src/app.js ../outside/", true, "a write behind a launcher"],
  ]) {
    const p = await run(cmd(command), { config: cfg({ mode: "hard" }) });
    check(`write ${expected ? "blocked" : "allowed"}: ${label}`, p.blocked === expected && p.completions === 0, `${command} → ${JSON.stringify(p.result)?.slice(0, 180)}`);
  }
  const p = await run(cmd("cp src/app.js ../outside/"), { config: cfg({ mode: "hard" }) });
  check("write: the reason keeps the structured shape", /^destructive-check: /.test(String(p.result?.reason ?? "")) && /rule: outsideWrite/.test(String(p.result?.reason ?? "")) && /mode: hard/.test(String(p.result?.reason ?? "")), p.result?.reason);
}

// --------------------------------------------- inline cd (the write scan) ---
// The delete/move scanner re-scopes per sub-command; the write scan has to resolve
// relative targets in the same directory, or `cd ..; echo pwn > target.js` looks
// like a write inside the project while the shell writes above it.
{
  const CD_PROJ = path.join(HOME, "cdproj");
  fs.rmSync(CD_PROJ, { recursive: true, force: true });
  fs.mkdirSync(path.join(CD_PROJ, ".git"), { recursive: true });
  const at = (command) => run(cmd(command), { config: cfg({ mode: "hard" }), cwd: CD_PROJ });
  const up = await at("echo warm; cd ..; echo pwn > target.js");
  check("the write scan follows an inline cd", up.blocked && /rule: outsideWrite/.test(String(up.result?.reason ?? "")) && up.completions === 0, JSON.stringify(up.result)?.slice(0, 200));
  const body = await at("bash -c 'cd .. && echo pwn > target.js'");
  check("the write scan follows a cd inside a shell body", body.blocked && /rule: outsideWrite/.test(String(body.result?.reason ?? "")) && body.completions === 0, JSON.stringify(body.result)?.slice(0, 200));
  const back = await at("echo warm; cd ..; echo pwn > cdproj/inside.js");
  check("a redirect that comes back into the project after a cd stays silent", !back.blocked && back.completions === 0, JSON.stringify(back.result)?.slice(0, 200));
}

// -------------------------------------------------------- here-documents ---
// A here-document is data for `cat` and code for a shell: `bash <<'EOF'` runs the
// body, so a `.env` rewrite inside it is a write and an `rm` inside it is a
// delete. Both scanners read one shared split, so they cannot disagree.
{
  const at = (command) => run(cmd(command), { config: cfg({ mode: "hard" }) });
  const env = await at("bash <<'EOF'\nprintf pwn > .env\nEOF");
  check("a shell-fed here-document body is scanned for writes", env.blocked && /rule: protectSecrets/.test(String(env.result?.reason ?? "")) && env.completions === 0, JSON.stringify(env.result)?.slice(0, 200));
  const del = await at("bash <<'EOF'\nrm -rf C:\\other\\project\nEOF");
  check("a shell-fed here-document body is scanned for deletes", del.blocked && /rule: outsideDelete/.test(String(del.result?.reason ?? "")) && del.completions === 0, JSON.stringify(del.result)?.slice(0, 200));
  const data = await at("cat <<'EOF'\nrm -rf ../outside\nEOF");
  check("a here-document fed to cat stays data for both scanners", !data.blocked && data.completions === 0, JSON.stringify(data.result)?.slice(0, 200));
  const unterminated = await at("cat <<'EOF' > out.json\nrm -rf ../outside\n");
  check("a misread `<<` cannot hide the lines after it", unterminated.blocked && /rule: outsideDelete/.test(String(unterminated.result?.reason ?? "")) && unterminated.completions === 0, JSON.stringify(unterminated.result)?.slice(0, 200));
}
{
  // Medium sends a write outside the project to the checker, simple asks; a
  // target the guard cannot resolve is a dynamicTargets violation, never a pass.
  const medium = await run(cmd("echo hi > ../outside.txt"), { config: cfg({ mode: "medium" }) });
  check("[medium] a write outside is escalated to the checker", medium.completions === 1 && !medium.blocked, JSON.stringify(medium.result)?.slice(0, 160));
  const simple = await run(cmd("echo hi > ../outside.txt"), { config: cfg({ mode: "simple" }), selects: ["Block"] });
  check("[simple] a write outside asks the user", simple.blocked && simple.completions === 0, JSON.stringify(simple.result)?.slice(0, 160));
  const remote = await run(cmd("rsync -a src/ user@host:/srv/app/"), { config: cfg({ mode: "hard" }) });
  check("hard: an unresolvable (remote) destination is blocked as dynamicTargets", remote.blocked && remote.completions === 0 && /rule: dynamicTargets/.test(String(remote.result?.reason ?? "")), JSON.stringify(remote.result)?.slice(0, 180));
  const remoteMedium = await run(cmd("rsync -a src/ user@host:/srv/app/"), { config: cfg({ mode: "medium" }) });
  check("medium: an unresolvable (remote) destination reaches the checker", remoteMedium.completions === 1 && !remoteMedium.blocked, JSON.stringify(remoteMedium.result)?.slice(0, 180));
  const heredoc = await run(cmd("cat <<'EOF' > out.json\ntee ../outside/x\nEOF"), { config: cfg({ mode: "hard" }) });
  check("a heredoc body is data, not a command line", !heredoc.blocked && heredoc.completions === 0, JSON.stringify(heredoc.result)?.slice(0, 180));
}


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

// --------------------------------------------------------- internal error ---
{
  // A malformed tool event must not brick the session, and must not disappear
  // silently either. Which way it fails depends on the mode: medium keeps the
  // call running and records the failure, while hard — the mode that promises
  // deterministic blocking — refuses to call an unanalyzable call safe.
  // A command value that explodes when the guard reads it: the analyzers call
  // String() on it long before any decision is made.
  const hostile = {
    toolName: "bash",
    input: {
      i: "run command",
      command: {
        toString() {
          throw new Error("malformed tool event");
        },
      },
    },
  };
  const medium = await run(hostile, { config: cfg({ mode: "medium" }) });
  check("internal error fails open outside hard mode (the command is not bricked)", !medium.blocked, JSON.stringify(medium.result));
  check(
    "internal error is reported to the UI",
    medium.ctx.notes.some((n) => /internal error/.test(n.message) && n.level === "warning"),
    JSON.stringify(medium.ctx.notes).slice(0, 200),
  );

  const hard = await run(hostile, { config: cfg({ mode: "hard" }) });
  check("internal error blocks in hard mode", hard.blocked && /analysis failed/.test(String(hard.result?.reason ?? "")), JSON.stringify(hard.result));

  let confirmText = "";
  const menuCtx = makeCtx({ cwd: CWD, registry: REG, selects: [pick("recent decisions"), pick("close")] });
  menuCtx.ui.confirm = async (_title, message) => ((confirmText = String(message)), true);
  await callTool({ toolCall: medium.ext.toolCall }, hostile, menuCtx);
  await medium.ext.commands.get("dc").handler("", menuCtx);
  check("internal error reaches the decision log", /internal/.test(confirmText), confirmText.slice(0, 200));
}


// ------------------------------------------------- the read-only class (S4) --
// A line every one of whose sub-commands cannot change anything passes without a
// model call; a spelling that *can* change something with the same verb does not.
{
  const cleanDry = await run(cmd("git clean -n"), { config: cfg({ mode: "medium" }) });
  check("read-only class: `git clean -n` only prints and passes without a model", !cleanDry.blocked && cleanDry.completions === 0, JSON.stringify(cleanDry.result)?.slice(0, 200));
  const cleanForced = await run(cmd("git clean -fdx"), { config: cfg({ mode: "hard" }) });
  check("read-only class: `git clean -fdx` is still a destructive git command", cleanForced.blocked && /rule: gitDestructive/.test(String(cleanForced.result?.reason ?? "")) && cleanForced.completions === 0, String(cleanForced.result?.reason ?? "").slice(0, 200));
  const status = await run(cmd("git status --short"), { config: cfg({ mode: "hard" }) });
  check("read-only class: `git status` is allowed in the strictest mode", !status.blocked && status.completions === 0, JSON.stringify(status.result)?.slice(0, 160));
  // The class is an allow, not a release: the same line with a real write verb in
  // it is judged by the ordinary scanners.
  const mixed = await run(cmd("git status && rm -rf ../outside"), { config: cfg({ mode: "medium" }) });
  check("read-only class: a destructive sub-command in the same line is not covered", mixed.blocked && mixed.completions === 0, String(mixed.result?.reason ?? "").slice(0, 200));
  const redirect = await run(cmd("echo hi > C:\\other\\note.txt"), { config: cfg({ mode: "hard" }) });
  check("read-only class: a redirect never enters the class", redirect.blocked && /rule: outsideWrite/.test(String(redirect.result?.reason ?? "")), String(redirect.result?.reason ?? "").slice(0, 200));
  for (const [command, label] of [["python -c \"import os\"", "python -c"], ["node -e \"1\"", "node -e"], ["bun run build", "bun run"], ["bash -c \"rm -rf /etc\"", "bash -c with a system delete"]]) {
    const p = await run(cmd(command), { config: cfg({ mode: "hard" }) });
    check(`read-only class: never an interpreter or runner (${label})`, command.startsWith("bash") ? p.blocked : !p.blocked, `${JSON.stringify(p.result)?.slice(0, 120)}`);
  }
}

// ---------------------------------------------------------- readonly mode ---
// Parking state: only a command the read-only class can vouch for runs, whatever
// the target. It only ever tightens, so the artifact and inside-project allows are
// closed too.
{
  const ro = (command) => run(cmd(command), { config: cfg({ mode: "readonly" }) });
  for (const [command, label] of [["ls -la", "a listing"], ["git status", "a git query"], ["grep -rn todo src", "a search"], ["cat package.json", "a read"]]) {
    const p = await ro(command);
    check(`readonly: ${label} passes without a model`, !p.blocked && p.completions === 0, JSON.stringify(p.result)?.slice(0, 160));
  }
  {
    const artifact = await ro("rm -rf node_modules");
    check("readonly: an artifact delete blocks without a model call", artifact.blocked && artifact.completions === 0, String(artifact.result?.reason ?? "").slice(0, 200));
  }
  for (const [command, label] of [
    ["mkdir newdir", "a directory create"],
    ["npm install left-pad", "a package install"],
    ["git commit -m x", "a commit"],
    ["echo hi > src/a.txt", "an inside-project write"],
    ["mv src/app.js src/old.js", "an inside-project move"],
  ]) {
    const p = await ro(command);
    check(`readonly: ${label} blocks without a model call`, p.blocked && p.completions === 0 && /rule: readonlyMutation/.test(String(p.result?.reason ?? "")), String(p.result?.reason ?? "").slice(0, 200));
  }
  const write = await run({ toolName: "write", input: { path: `${CWD}\\src\\new.ts`, content: "export {}" } }, { config: cfg({ mode: "readonly" }) });
  check("readonly: a first-class file write blocks", write.blocked && /rule: readonlyMutation/.test(String(write.result?.reason ?? "")), String(write.result?.reason ?? "").slice(0, 200));
  const evalRead = await run({ toolName: "eval", input: { language: "py", code: "print(1)" } }, { config: cfg({ mode: "readonly" }) });
  check("readonly: an eval body is a mutation whatever it contains", evalRead.blocked && /rule: readonlyMutation/.test(String(evalRead.result?.reason ?? "")), String(evalRead.result?.reason ?? "").slice(0, 200));
}

// ------------------------------------------------------------- guard self ---
// The guard's own controls: its config, its code, the approval list, the project
// policy file, and the host config when the edit touches the extension lists.
{
  const guardCfg = `${HOME}\\.omp\\destructive-check.json`;
  const onConfig = await run({ toolName: "write", input: { path: guardCfg, content: '{"mode":"simple"}' } }, { config: cfg({ mode: "medium" }) });
  check("guardSelf: writing the guard's config is blocked", onConfig.blocked && /rule: guardSelf/.test(String(onConfig.result?.reason ?? "")) && onConfig.completions === 0, String(onConfig.result?.reason ?? "").slice(0, 240));
  const redirect = await run(cmd(`echo {} > "${guardCfg}"`), { config: cfg({ mode: "medium" }) });
  check("guardSelf: a redirect into the guard's config is blocked", redirect.blocked && /rule: guardSelf/.test(String(redirect.result?.reason ?? "")), String(redirect.result?.reason ?? "").slice(0, 240));
  const holder = await run(cmd(`rm -rf "${HOME}\\.omp"`), { config: cfg({ mode: "medium" }) });
  check("guardSelf: deleting a directory that holds a control file is blocked", holder.blocked && /rule: guardSelf/.test(String(holder.result?.reason ?? "")), String(holder.result?.reason ?? "").slice(0, 240));
  const allowFile = await run({ toolName: "write", input: { path: `${HOME}\\.omp\\destructive-check-allow.json`, content: "[]" } }, { config: cfg({ mode: "medium" }) });
  check("guardSelf: the approval list is a control file too", allowFile.blocked && /rule: guardSelf/.test(String(allowFile.result?.reason ?? "")), String(allowFile.result?.reason ?? "").slice(0, 240));
  const hostConfig = `${HOME}\\.omp\\agent\\config.yml`;
  const extensions = await run({ toolName: "edit", input: { input: `[${hostConfig}#1A2B]\n+extensions: []` } }, { config: cfg({ mode: "medium" }) });
  check("guardSelf: the host config is a control file when the edit touches extensions", extensions.blocked && /rule: guardSelf/.test(String(extensions.result?.reason ?? "")), String(extensions.result?.reason ?? "").slice(0, 240));
  // The same file for an unrelated setting is not this rule's business: the
  // negative half is what keeps the rule from blocking ordinary configuration.
  const unrelated = await run({ toolName: "edit", input: { path: hostConfig, edits: [{ op: "replace", find: "theme: dark", replace: "theme: light" }] } }, { config: cfg({ mode: "medium" }) });
  check("guardSelf: an unrelated host-config edit is not the guard's business", !/rule: guardSelf/.test(String(unrelated.result?.reason ?? "")), String(unrelated.result?.reason ?? "").slice(0, 240));
  const floored = await run({ toolName: "write", input: { path: guardCfg, content: "{}" } }, { config: cfg({ mode: "custom", rules: { guardSelf: "allow", unreadTarget: "allow" } }) });
  check("guardSelf: `allow` in the file does not open the rule (RULE_FLOORS)", floored.blocked && /rule: guardSelf/.test(String(floored.result?.reason ?? "")), String(floored.result?.reason ?? "").slice(0, 240));
  const other = await run(cmd(`rm -rf "${HOME}\\.omp\\logs"`), { config: cfg({ mode: "medium" }) });
  check("guardSelf: the audit log directory is not claimed by the rule", !/rule: guardSelf/.test(String(other.result?.reason ?? "")), String(other.result?.reason ?? "").slice(0, 200));
}

const bad = report("policy modes");
process.exitCode = bad ? 1 : 0;
void results;
