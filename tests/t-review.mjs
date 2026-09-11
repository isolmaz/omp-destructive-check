// Regression cases from the external review (11 Sep 2026). Each block names the
// finding it pins: these are the spellings and schemas the previous revision
// classified as safe without ever reaching the checker.
import * as fs from "node:fs";
import * as path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { loadExt, makeCtx, callTool, bash, mkHome, fakeRegistry, installFetch, fetchResponse, checkerRequests, check, report, dialogDefects } from "./harness.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const AUDIT = path.join(HERE, "..", "tools", "dc-audit.mjs");
const HOME = mkHome("review");
const PROJ = path.join(HOME, "proj");
const OUTSIDE = path.join(HOME, "outside");
const LOG = path.join(HOME, ".omp", "logs", "destructive-check.jsonl");
const REG = fakeRegistry([["opencode-go", "deepseek-v4.1-flash"]]);

const cfg = (extra = {}) => ({
  enabled: true,
  mode: "hard",
  provider: "opencode-go",
  providers: { "opencode-go": { model: "deepseek-v4.1-flash" } },
  askOnDeny: false,
  ...extra,
});

const allowFetch = () => installFetch(() => fetchResponse(200, { choices: [{ message: { content: "ALLOW: stub" } }] }));

async function run(event, { config = cfg(), cwd = PROJ, selects = [], hasUI = true } = {}) {
  allowFetch();
  const ext = await loadExt({ home: HOME, config, registry: REG });
  const ctx = makeCtx({ cwd, hasUI, selects: [...selects], registry: REG });
  const result = await callTool(ext, event, ctx);
  return { ext, ctx, result, completions: checkerRequests().length, blocked: result?.block === true, reason: String(result?.reason ?? "") };
}

const cmd = (command) => bash(command, "cleanup");
const hub = (input) => ({ toolName: "hub", input });
const evalCall = (code) => ({ toolName: "eval", input: { language: "py", code } });
const pick = (prefix) => (options) => options.map((o) => (typeof o === "string" ? o : o.label)).find((l) => l.startsWith(prefix));

fs.rmSync(HOME, { recursive: true, force: true });
fs.mkdirSync(path.join(PROJ, ".git"), { recursive: true });
fs.mkdirSync(path.join(PROJ, "src"), { recursive: true });
fs.mkdirSync(path.join(PROJ, "dist"), { recursive: true });
fs.mkdirSync(path.join(OUTSIDE, "dist"), { recursive: true });
fs.mkdirSync(path.join(OUTSIDE, "data"), { recursive: true });
fs.writeFileSync(path.join(PROJ, "src", "app.js"), "// work\n");
fs.writeFileSync(path.join(PROJ, "cleanup"), "#!/usr/bin/env bash\nrm -rf src\n");
fs.writeFileSync(path.join(PROJ, "cleanup.sh"), "#!/usr/bin/env bash\nrm -rf src\n");

// ---------------------------------------------------------------- D01 paths ---
// `/tmp/../etc` normalizes to /etc: the temp shortcut must not run before `..`
// is resolved, and an artifact *prefix* must not make a variable suffix safe.
{
  const p = await run(cmd("rm -rf /tmp/../etc"));
  check("D01: /tmp/../etc is not an artifact path", p.blocked && p.completions === 0, p.reason);
}
{
  const p = await run(cmd('rm -rf dist/"$TARGET"'));
  check("D01: a variable under an artifact prefix stays dynamic", p.blocked || p.completions > 0, `blocked=${p.blocked} completions=${p.completions}`);
}
{
  const p = await run(cmd('mv src "$DEST"'), { config: cfg({ mode: "medium" }) });
  check("D01: an unresolved move destination is not waved through", p.blocked || p.completions > 0, `blocked=${p.blocked} completions=${p.completions}`);
}

// ------------------------------------------------------------------ D02 keys ---
// A stored session approval must never outrank a decision the current policy
// makes on its own, and two different eval bodies must not share one identity.
{
  const asks = ["Allow for this session", "close"];
  allowFetch();
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "custom", rules: { insideDelete: "ask" }, askOnDeny: true }), registry: REG });
  const ctx = makeCtx({ cwd: PROJ, selects: [...asks], registry: REG });
  const first = await callTool(ext, cmd("rm -rf src"), ctx);
  check("D02: the user can approve once for the session", first === undefined, JSON.stringify(first));
  // /dc → protection hard: the stored approval must not survive the policy change.
  const menuCtx = makeCtx({ cwd: PROJ, selects: [pick("protection:"), pick("hard"), pick("close")], registry: REG });
  await ext.commands.get("dc").handler("", menuCtx);
  const after = await callTool(ext, cmd("rm -rf src"), ctx);
  check("D02: a policy change invalidates the session approval", after?.block === true, JSON.stringify(after));
}
{
  allowFetch();
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "custom", rules: { codeDelete: "ask" } }), registry: REG });
  const ctx = makeCtx({ cwd: PROJ, selects: ["Allow for this session"], registry: REG });
  const first = await callTool(ext, evalCall('import shutil\nshutil.rmtree(target)'), ctx);
  check("D02: the eval approval is scoped to that body", first === undefined, JSON.stringify(first));
  const second = await callTool(ext, evalCall('import shutil\nshutil.rmtree("/etc")'), ctx);
  check("D02: a different eval body is not covered by the earlier approval", second?.block === true, JSON.stringify(second));
}
{
  // The verdict cache must not outlive a policy change either.
  allowFetch();
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "custom", rules: { outsideDelete: "model" } }), registry: REG });
  const ctx = makeCtx({ cwd: PROJ, registry: REG });
  await callTool(ext, cmd("rm -rf " + path.join(OUTSIDE, "data")), ctx);
  const menuCtx = makeCtx({ cwd: PROJ, selects: [pick("coverage:"), pick("processes:"), pick("close")], registry: REG });
  await ext.commands.get("dc").handler("", menuCtx);
  await callTool(ext, cmd("rm -rf " + path.join(OUTSIDE, "data")), ctx);
  check("D12: a policy change drops cached verdicts", checkerRequests().length === 2, `requests=${checkerRequests().length}`);
}

// ------------------------------------------------------------- D03 cwd/scope ---
// The host moves a leading `cd X && …` into the tool's `cwd` field; resolving
// targets against the session cwd judges a different directory than the one the
// command runs in.
{
  const p = await run({ toolName: "bash", input: { command: "rm -rf data", cwd: OUTSIDE } }, { config: cfg({ mode: "simple" }) });
  check("D03: the tool call's own cwd is used for target resolution", p.blocked, `blocked=${p.blocked} reason=${p.reason}`);
}
{
  const p = await run(hub({ op: "start", application: "sh", args: ["-c", "rm -rf data"], cwd: OUTSIDE }), { config: cfg({ mode: "simple" }) });
  check("D03: hub launches resolve against the tool call's cwd", p.blocked, `blocked=${p.blocked} reason=${p.reason}`);
}
{
  // Changing directory must change where targets resolve, never which roots are
  // authorized: `<outside>/dist` is not "an artifact of the project".
  const p = await run(cmd(`cd "${OUTSIDE}" && rm -rf dist`), { config: cfg({ mode: "simple" }) });
  check("D03: cd does not authorize a new project scope", p.blocked, `blocked=${p.blocked} reason=${p.reason}`);
}

// --------------------------------------------------------- D04 edit adapters ---
{
  // Two sections, the destructive move in the second one.
  const patch = [
    "[src/app.js#1A2B]",
    "+console.log(1)",
    "",
    `[src/keep.js#3C4D]`,
    "MV ../outside/leak.js",
  ].join("\n");
  const p = await run({ toolName: "edit", input: { input: patch } });
  check("D04: every hashline section is inspected, not just the first", p.blocked, `blocked=${p.blocked} reason=${p.reason}`);
}
{
  const p = await run({ toolName: "edit", input: { path: "src/app.js", edits: [{ op: "delete" }] } });
  check("D04: a structured edit op is inspected", p.blocked, `blocked=${p.blocked} reason=${p.reason}`);
}

// ------------------------------------------------------- D05 command words ---
{
  // `bash` here is a target, not the command being run.
  const p = await run(cmd("rm -rf dist bash"));
  check("D05: a target named like a command word is not dropped", p.blocked, `blocked=${p.blocked} reason=${p.reason}`);
}
{
  const p = await run(cmd("source ./cleanup.sh"));
  check("D05: `source ./x.sh` is analysed through the file", p.blocked, `blocked=${p.blocked} reason=${p.reason}`);
}
{
  const p = await run(cmd(". ./cleanup.sh"));
  check("D05: `. ./x.sh` is analysed through the file", p.blocked, `blocked=${p.blocked} reason=${p.reason}`);
}
{
  const p = await run(cmd("sh cleanup"));
  check("D05: a script without an extension is still read", p.blocked, `blocked=${p.blocked} reason=${p.reason}`);
}
{
  const p = await run(cmd(String.raw`r\m -rf src`));
  check("D05: a backslash-escaped command word is normalized", p.blocked, `blocked=${p.blocked} reason=${p.reason}`);
}
{
  const p = await run(cmd('r"m" -rf src'));
  check("D05: a quote-split command word is normalized", p.blocked, `blocked=${p.blocked} reason=${p.reason}`);
}
{
  const p = await run(cmd('echo "$(rm -rf src)"'));
  check("D05: command substitution inside quotes is scanned", p.blocked, `blocked=${p.blocked} reason=${p.reason}`);
}

// -------------------------------------------------------- D06 git spellings ---
for (const [command, label] of [
  ["git --git-dir=.git reset --hard", "global option before the subcommand"],
  ['git "reset" --hard', "quoted subcommand"],
  ["git push origin +HEAD:main", "forced refspec"],
  ["git restore --staged -W src/app.js", "staged plus worktree"],
  ["git branch -Df topic", "combined short flags"],
]) {
  const p = await run(cmd(command));
  check(`D06: ${label} is classified as destructive`, p.blocked, `blocked=${p.blocked} reason=${p.reason}`);
}
{
  // --force-with-lease is deliberately allowed: it refuses to touch a ref that
  // moved since the last fetch, so it cannot silently destroy unseen work.
  const p = await run(cmd("git push --force-with-lease origin main"));
  check("D06: force-with-lease stays allowed", !p.blocked && p.completions === 0, p.reason);
}

// ------------------------------------------------------------ D07 eval args ---
{
  const p = await run(evalCall('import shutil\nnote = "dist"\nshutil.rmtree(target)'), { config: cfg({ mode: "medium" }) });
  check("D07: an unrelated literal does not answer for the delete target", p.blocked || p.completions > 0, `blocked=${p.blocked} completions=${p.completions}`);
}
{
  const p = await run(evalCall('import shutil\nprint("finished")\nshutil.rmtree("' + path.join(PROJ, "dist") + '")'), { config: cfg({ mode: "medium" }) });
  check("D07: an artifact-only delete is not blocked because of an unrelated literal", !p.blocked && p.completions === 0, `blocked=${p.blocked} reason=${p.reason}`);
}

// -------------------------------------------------------------- D08 merging ---
{
  const p = await run(cmd(`rm -rf src ${path.join(OUTSIDE, "data")}`), { config: cfg({ mode: "custom", rules: { outsideDelete: "allow", insideDelete: "block" } }) });
  check("D08: an allowed target does not release a blocked one", p.blocked, `blocked=${p.blocked} reason=${p.reason}`);
}
{
  const p = await run(cmd("rm -rf dist"), { config: cfg({ mode: "custom", rules: { artifactDelete: "block" } }) });
  check("D08: artifactDelete is a live rule", p.blocked, `blocked=${p.blocked} reason=${p.reason}`);
}
{
  const p = await run(cmd("reboot"), { config: cfg({ mode: "hard", rules: { catastrophic: "allow" } }) });
  check("D08: a preset is not silently overridden by stored rules", p.blocked, `blocked=${p.blocked} reason=${p.reason}`);
}

// ------------------------------------------------------- D09 config limits ---
{
  const probe = path.join(HOME, "logsize-probe.mjs");
  fs.writeFileSync(
    probe,
    [
      `import { loadExt, makeCtx, callTool, bash, mkHome, fakeRegistry, installFetch, fetchResponse } from ${JSON.stringify(new URL("./harness.mjs", import.meta.url).href)};`,
      `const HOME = mkHome("review");`,
      `installFetch(() => fetchResponse(200, { choices: [{ message: { content: "ALLOW: stub" } }] }));`,
      `const ext = await loadExt({ home: HOME, config: { enabled: true, mode: "hard", logSize: -1 }, registry: fakeRegistry([["opencode-go", "m"]]) });`,
      `const ctx = makeCtx({ cwd: "C:/scratch/proj" });`,
      `await callTool(ext, bash("rm -rf /etc", "cleanup"), ctx);`,
      `console.log("completed");`,
    ].join("\n"),
  );
  let out = "";
  let timedOut = false;
  try {
    out = execFileSync(process.execPath, [probe], { encoding: "utf8", timeout: 20_000, stdio: ["ignore", "pipe", "pipe"] });
  } catch (err) {
    timedOut = err.killed === true || err.signal === "SIGTERM" || /ETIMEDOUT/.test(String(err.code));
    out = `${err.stdout ?? ""}${err.stderr ?? ""}`;
  }
  check("D09: a negative logSize cannot hang the decision path", !timedOut && /completed/.test(out), out.slice(0, 200));
}

// ------------------------------------------------------- D10 internal error ---
{
  const hostile = { toolName: "bash", input: { command: { toString() { throw new Error("malformed tool event"); } } } };
  const p = await run(hostile);
  check("D10: hard mode blocks when the analysis itself fails", p.blocked, JSON.stringify(p.result));
}

// ------------------------------------------------------------- D11 hub ops ---
{
  const p = await run(hub({ op: "send", name: "dev-server", text: "rm -rf src" }));
  check("D11: writing into a running process is not silently safe", p.blocked || p.completions > 0, `blocked=${p.blocked} completions=${p.completions}`);
}
{
  const p = await run(hub({ op: "restart", name: "dev-server" }));
  check("D11: restarting an unknown process spec is not silently safe", p.blocked || p.completions > 0, `blocked=${p.blocked} completions=${p.completions}`);
}

// --------------------------------------------------------- D13 audit trail ---
{
  fs.rmSync(LOG, { force: true });
  allowFetch();
  const a = await loadExt({ home: HOME, config: cfg(), registry: REG });
  const b = await loadExt({ home: HOME, config: cfg(), registry: REG });
  const ctxA = makeCtx({ cwd: PROJ, registry: REG, sessionId: "session-a" });
  const ctxB = makeCtx({ cwd: PROJ, registry: REG, sessionId: "session-b" });
  await callTool(a, cmd("rm -rf /etc"), ctxA);
  await callTool(b, cmd("rm -rf /etc"), ctxB);
  await callTool(a, cmd("rm -rf /etc"), ctxA);
  const lines = fs.existsSync(LOG) ? fs.readFileSync(LOG, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
  check("D13: two sessions keep the chain intact", lines.length === 3, `${lines.length} lines`);
  let audit = "";
  try {
    audit = execFileSync(process.execPath, [AUDIT, "--file", LOG], { encoding: "utf8" });
  } catch (err) {
    audit = `${err.stdout ?? ""}${err.stderr ?? ""}`;
  }
  check("D13: the verifier reads a multi-session log as intact", /chain {3}: intact/.test(audit), audit);
  check("D13: the session id is recorded", lines.every((l) => l.session === "session-a" || l.session === "session-b"), JSON.stringify(lines.map((l) => l.session)));
}
{
  // Model deny + "allow once" is the human's final decision: the log has to say so.
  fs.rmSync(LOG, { force: true });
  installFetch(() => fetchResponse(200, { choices: [{ message: { content: "DENY: unlocks the user's data" } }] }));
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "custom", rules: { outsideDelete: "model" }, askOnDeny: true }), registry: REG });
  const ctx = makeCtx({ cwd: PROJ, selects: ["Allow once"], registry: REG, sessionId: "session-c" });
  const p = await callTool(ext, cmd("rm -rf " + path.join(OUTSIDE, "data")), ctx);
  const lines = fs.existsSync(LOG) ? fs.readFileSync(LOG, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
  check("D13: the human's override is recorded, not just the model verdict", p === undefined && lines.some((l) => l.action === "model:deny") && lines.some((l) => /allow/i.test(l.action) && l.rule === "outsideDelete"), JSON.stringify(lines));
}

// ----------------------------------------------------- D14 test gate honesty ---
{
  const old = path.join(HOME, "old-extension.ts");
  const repo = path.join(HERE, "..");
  fs.writeFileSync(old, execFileSync("git", ["show", "HEAD~3:destructive-check.ts"], { cwd: repo, encoding: "utf8", maxBuffer: 32 * 1024 * 1024 }));
  let code = 0;
  try {
    execFileSync(process.execPath, [path.join(HERE, "t-coverage.mjs")], { encoding: "utf8", env: { ...process.env, DC_EXT: old }, stdio: ["ignore", "pipe", "pipe"] });
  } catch (err) {
    code = err.status ?? 1;
  }
  check("D14: the coverage suite fails the process when checks fail", code === 1, `exit=${code}`);
}

// -------------------------------------------------------- D16 reasoning field ---
{
  const posts = installFetch(() => fetchResponse(200, { choices: [{ message: { content: "ALLOW: stub" } }] }));
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "custom", rules: { outsideDelete: "model" }, providers: { "opencode-go": { model: "deepseek-v4.1-flash", reasoning: "high" } } }), registry: REG });
  const ctx = makeCtx({ cwd: PROJ, registry: REG });
  await callTool(ext, cmd("rm -rf " + path.join(OUTSIDE, "data")), ctx);
  const body = JSON.parse(posts.at(-1)?.init?.body ?? "{}");
  check("D16: the configured reasoning effort reaches the request", body.reasoning_effort === "high", JSON.stringify(body).slice(0, 200));
}

// ------------------------------------------------------------ D18 verdict ---
{
  // A verdict in the reasoning trace is not the answer; the model's content is.
  // askOnError is off so the assertion pins the decision path itself: text that
  // is not a verdict must fail closed, not become an ALLOW.
  installFetch(() => fetchResponse(200, { choices: [{ message: { content: "no verdict here", reasoning_content: "ALLOW: looks fine to me" }, finish_reason: "stop" }] }));
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "custom", rules: { outsideDelete: "model" }, askOnDeny: false, askOnError: false, engine: "in-process" }), registry: REG });
  const ctx = makeCtx({ cwd: PROJ, registry: REG });
  const p = await callTool(ext, cmd("rm -rf " + path.join(OUTSIDE, "data")), ctx);
  check("D18: reasoning text does not decide the verdict", p?.block === true && /could not produce a verdict/.test(String(p?.reason ?? "")), JSON.stringify(p));
}
{
  // The same rule for a truncated reply: an empty message is an error, not a
  // silent default, and the reason names the finish_reason.
  installFetch(() => fetchResponse(200, { choices: [{ message: { content: "" }, finish_reason: "length" }] }));
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "custom", rules: { outsideDelete: "model" }, askOnDeny: false, askOnError: false }), registry: REG });
  const ctx = makeCtx({ cwd: PROJ, registry: REG });
  const p = await callTool(ext, cmd("rm -rf " + path.join(OUTSIDE, "data")), ctx);
  check("D18: a truncated reply is an error", p?.block === true && /finish_reason: length/.test(String(p?.reason ?? "")), JSON.stringify(p));
}

// ---------------------------------------------------------- D17 CLI binary ---
{
  // The CLI checker must run the omp binary, not whatever runtime the host
  // happens to be: the nested run needs omp's own provider plumbing, and its
  // flags must disable tools and extensions (a nested guard would re-check the
  // checker's own prompt).
  const calls = [];
  const exec = async (cmd, args, opts) => {
    calls.push({ cmd, args, opts });
    return { stdout: "DENY: stub\n", stderr: "", code: 0, killed: false };
  };
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "custom", rules: { outsideDelete: "model" }, engine: "cli" }), registry: REG, exec });
  const ctx = makeCtx({ cwd: PROJ, registry: REG });
  process.env.OMP_DC_BIN = process.execPath;
  try {
    const p = await callTool(ext, cmd("rm -rf " + path.join(OUTSIDE, "data")), ctx);
    check("D17: OMP_DC_BIN is the binary that runs", calls[0]?.cmd === process.execPath, JSON.stringify(calls[0]?.cmd));
    check("D17: the nested run disables tools and extensions", calls[0]?.args?.includes("--no-tools") && calls[0]?.args?.includes("--no-extensions"), JSON.stringify(calls[0]?.args));
    check("D17: the nested run names the checker model", calls[0]?.args?.includes("opencode-go/deepseek-v4.1-flash"), JSON.stringify(calls[0]?.args));
    check("D17: a denied CLI verdict blocks", p?.block === true, JSON.stringify(p));
  } finally {
    delete process.env.OMP_DC_BIN;
  }
}
{
  // Without an override, a host that is not omp falls back to the CLI on PATH;
  // spawning the host's own runtime would run something that is not omp at all.
  const calls = [];
  const exec = async (cmd) => {
    calls.push(cmd);
    return { stdout: "ALLOW: stub\n", stderr: "", code: 0, killed: false };
  };
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "custom", rules: { outsideDelete: "model" }, engine: "cli" }), registry: REG, exec });
  const ctx = makeCtx({ cwd: PROJ, registry: REG });
  await callTool(ext, cmd("rm -rf " + path.join(OUTSIDE, "data")), ctx);
  const isOmp = /^omp(\.exe|-[\w.]+)?$/i.test(path.basename(process.execPath));
  check("D17: a non-omp host uses the omp CLI from PATH", isOmp || calls[0] === "omp", `execPath=${process.execPath} cmd=${calls[0]}`);
}

// --------------------------------------------------- D20 installer vs lock ---
{
  // A guard locked from /dc is read-only on purpose: the installer must not
  // unlock it silently, and when it does replace it (--unlock) the mode comes
  // back, so the lock is not a one-shot obstacle.
  const install = (argv) => {
    try {
      const stdout = execFileSync(process.execPath, [path.join(HERE, "..", "install.mjs"), ...argv], {
        encoding: "utf8",
        env: { ...process.env, USERPROFILE: HOME, HOME },
        stdio: ["ignore", "pipe", "pipe"],
      });
      return { code: 0, out: stdout };
    } catch (err) {
      return { code: err.status ?? 1, out: `${err.stdout ?? ""}${err.stderr ?? ""}` };
    }
  };
  const DEST = path.join(HOME, ".omp", "shared", "destructive-check.ts");
  const SRC = path.join(HERE, "..", "destructive-check.ts");
  const readOnly = (file) => (fs.statSync(file).mode & 0o200) === 0;

  const first = install([]);
  check("D20: a fresh install writes the guard", first.code === 0 && fs.existsSync(DEST), first.out);
  fs.appendFileSync(DEST, "\n// a local edit the installer does not know about\n");
  fs.chmodSync(DEST, 0o444);
  const blocked = install(["--force"]);
  check("D20: a locked guard is not replaced without --unlock", blocked.code !== 0 && /read-only \(locked/.test(blocked.out) && readOnly(DEST), `code=${blocked.code} out=${blocked.out}`);
  const forced = install(["--force", "--unlock"]);
  check("D20: --unlock replaces the locked copy", forced.code === 0 && fs.readFileSync(DEST, "utf8") === fs.readFileSync(SRC, "utf8"), `code=${forced.code} out=${forced.out}`);
  check("D20: the lock is back after the install", readOnly(DEST), `mode ${fs.statSync(DEST).mode.toString(8)}`);
  fs.chmodSync(DEST, 0o644);
}

// ------------------------------------------------- D23 secrets in the log ---
{
  // Command text lands in the audit log: credentials on the command line must
  // not, or the file that proves what happened becomes a secret store.
  const p = await run(cmd(`rm -rf ${path.join(OUTSIDE, "data")} --token=SUPERSECRETVALUE123`));
  const raw = fs.readFileSync(LOG, "utf8");
  const last = raw.trim().split("\n").at(-1) ?? "";
  check("D23: a secret on the command line is masked in the log", !raw.includes("SUPERSECRETVALUE123") && /token=\*\*\*/.test(last), last.slice(0, 200));
  check("D23: the decision is still recorded", p.blocked, p.reason);
  if (process.platform !== "win32") {
    check("D23: the audit log is not group/world readable", (fs.statSync(LOG).mode & 0o077) === 0, `mode ${fs.statSync(LOG).mode.toString(8)}`);
  }
}

// -------------------------------------------------------- D19 error-path allow ---
{
  installFetch(() => fetchResponse(500, "boom"));
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "custom", rules: { outsideDelete: "model" }, askOnError: true }), registry: REG });
  const ctx = makeCtx({ cwd: PROJ, selects: ["Allow for this session"], registry: REG });
  const first = await callTool(ext, cmd("rm -rf " + path.join(OUTSIDE, "data")), ctx);
  installFetch(() => fetchResponse(200, { choices: [{ message: { content: "ALLOW: stub" } }] }));
  const second = await callTool(ext, cmd("rm -rf " + path.join(OUTSIDE, "data")), ctx);
  check("D19: the checker-error approval is remembered for the session", first === undefined && second === undefined && checkerRequests().length === 0, `first=${first === undefined} second=${second === undefined} requests=${checkerRequests().length}`);
}

report("review");
