// Policy layers: protection modes, rule actions, coverage, target classification.
// Every probe loads a fresh module instance (verdict caches are module-global).
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
  const inside = (dirs) => run(cmd("rm -rf C:\\shared\\libs\\generated"), { config: cfg({ mode: "simple", allowDirs: dirs }) });
  const baseline = await inside([]);
  check("allowDirs: without an entry the delete is outside the project", baseline.blocked && baseline.completions === 0, JSON.stringify(baseline.result)?.slice(0, 200));
  const good = await inside(["C:\\shared\\libs"]);
  check("allowDirs: a real directory widens the scope", !good.blocked && good.completions === 0, JSON.stringify(good.result)?.slice(0, 200));

  for (const [entry, label] of [
    ["C:\\", "a drive root"],
    ["/", "the posix root"],
    [HOME, "the user home"],
    [path.join(HOME, ".omp"), "the guard's own directory"],
    ["C:\\Windows", "the windows tree"],
    ["C:\\Program Files (x86)", "a program directory"],
    ["/etc", "a posix system directory"],
    ["/usr/local/bin", "a posix system bin"],
    ["relative/path", "a relative path"],
    ["~", "a bare tilde"],
  ]) {
    const p = await inside([entry]);
    check(`allowDirs refuses ${label}`, p.blocked && p.completions === 0, `${entry} → ${JSON.stringify(p.result)?.slice(0, 160)}`);
  }
  // The refusal is not silent: /dc reports it instead of leaving the user with a
  // setting that looks applied and is not.
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "simple", allowDirs: ["C:\\", "C:\\shared\\libs"] }), registry: REG });
  const ctx = makeCtx({ cwd: CWD, hasUI: false, registry: REG });
  await ext.commands.get("dc").handler("", ctx);
  const report = ctx.notes.map((n) => n.message).join("\n");
  check("allowDirs: /dc status reports the rejected entry and the reason", /rejected dirs/.test(report) && /C:\\ /.test(report) && /filesystem root/.test(report), report.slice(0, 300));
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
    ["sudo cp src/app.js ../outside/", true, "a write behind a launcher"],
  ]) {
    const p = await run(cmd(command), { config: cfg({ mode: "hard" }) });
    check(`write ${expected ? "blocked" : "allowed"}: ${label}`, p.blocked === expected && p.completions === 0, `${command} → ${JSON.stringify(p.result)?.slice(0, 180)}`);
  }
  const p = await run(cmd("cp src/app.js ../outside/"), { config: cfg({ mode: "hard" }) });
  check("write: the reason keeps the structured shape", /^destructive-check: /.test(String(p.result?.reason ?? "")) && /rule: outsideWrite/.test(String(p.result?.reason ?? "")) && /mode: hard/.test(String(p.result?.reason ?? "")), p.result?.reason);
}
{
  // Medium sends a write outside the project to the checker, simple asks; a
  // target the guard cannot resolve is a dynamicTargets violation, never a pass.
  const medium = await run(cmd("echo hi > ../outside.txt"), { config: cfg({ mode: "medium" }) });
  check("[medium] a write outside is escalated to the checker", medium.completions === 1 && !medium.blocked, JSON.stringify(medium.result)?.slice(0, 160));
  const simple = await run(cmd("echo hi > ../outside.txt"), { config: cfg({ mode: "simple" }), selects: ["Block"] });
  check("[simple] a write outside asks the user", simple.blocked && simple.completions === 0, JSON.stringify(simple.result)?.slice(0, 160));
  const remote = await run(cmd("rsync -a src/ user@host:/srv/app/"), { config: cfg({ mode: "medium" }) });
  check("an unresolvable (remote) destination is not a clean pass", remote.blocked || remote.completions > 0, JSON.stringify(remote.result)?.slice(0, 160));
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

const bad = report("policy modes");
process.exitCode = bad ? 1 : 0;
void results;
