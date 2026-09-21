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
import { loadExt, makeCtx, callTool, bash, mkHome, fakeRegistry, installFetch, fetchResponse, checkerRequests, check, report, dialogDefects, confirmLog, EXT_PATH } from "./harness.mjs";

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
  const p = await run(cmd("rm -rf C:\\other\\project\\data"));
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
  const { panels, defects } = await dc({ selects: ["audit log", "verify the audit chain", "close"] });
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
    const { panels } = await dc({ selects: ["guard: ok", "integrity: ok", "close"], extPath: INSTALLED });
    const panel = panels.at(-1) ?? "";
    check("guard integrity: a matching install reports ok", /state\s*: ok/.test(panel), panel);
    check("guard integrity: the panel names the loaded file", panel.includes(INSTALLED), panel);
  }
  {
    // Appended, not replaced: the panel has to run against a file the host can
    // still load, and an extra comment is a real edit with a new hash.
    fs.appendFileSync(INSTALLED, "\n// edited after the install, off the books\n");
    const { panels } = await dc({ selects: ["guard: changed", "integrity: changed", "close"], extPath: INSTALLED });
    const panel = panels.at(-1) ?? "";
    check("guard integrity: an edit after the install reports changed", /state\s*: changed/.test(panel) && /install\.mjs --force/.test(panel), panel);
  }
  {
    // A copy with no manifest next to it is "unmanaged" — never a passing hash
    // taken from a manifest that describes some other file.
    fs.rmSync(MANIFEST, { force: true });
    const { panels } = await dc({ selects: ["guard: unmanaged", "integrity: unmanaged", "close"], extPath: INSTALLED });
    const panel = panels.at(-1) ?? "";
    check("guard integrity: a copy with no manifest is unmanaged, not ok", /state\s*: unmanaged/.test(panel), panel);
  }
  {
    fs.copyFileSync(EXT_PATH, INSTALLED);
    fs.writeFileSync(MANIFEST, JSON.stringify({ sha256: manifestOf(INSTALLED), installedAt: "2026-09-11T00:00:00.000Z", version: "2.4" }));
    await dc({ selects: ["guard: ok", "lock: destructive-check.ts: writable · destructive-check.json: writable", "lock the guard only", "close"], extPath: INSTALLED });
    check("guard lock: locking leaves the installed file read-only", (fs.statSync(INSTALLED).mode & 0o200) === 0, `mode ${fs.statSync(INSTALLED).mode.toString(8)}`);
    check("guard lock: the config stays writable when only the guard is locked", (fs.statSync(path.join(HOME, ".omp", "destructive-check.json")).mode & 0o200) !== 0, "");
    await dc({ selects: ["guard: ok", "lock: destructive-check.ts: read-only · destructive-check.json: writable", "unlock both files", "close"], extPath: INSTALLED });
    check("guard lock: unlocking restores a writable file", (fs.statSync(INSTALLED).mode & 0o200) !== 0, `mode ${fs.statSync(INSTALLED).mode.toString(8)}`);
  }
  {
    fs.writeFileSync(`${INSTALLED}.bak`, "// the previous guard\n");
    const { panels } = await dc({ selects: ["guard: ok", "restore the previous guard (.bak)", "close"], extPath: INSTALLED });
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
}
{
  const before = confirmLog.length;
  const { defects } = await dc({ selects: [(options) => options.map((o) => o.label).find((l) => l.startsWith("watch"))], config: cfg({ mode: "hard" }) });
  const written = JSON.parse(fs.readFileSync(path.join(HOME, ".omp", "destructive-check.json"), "utf8"));
  check("/dc: watch mode toggles and persists", written.dryRun === true, JSON.stringify(written));
  check("/dc: the watch entry explains itself", defects.length === 0 && confirmLog.length >= before, defects.join("; "));
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

const bad = report("coverage");
process.exitCode = bad ? 1 : 0;
