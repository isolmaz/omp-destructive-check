#!/usr/bin/env node
/**
 * dc-audit.mjs — independent verifier for the destructive-check audit log.
 *
 *   node tools/dc-audit.mjs                    # ~/.omp/logs/destructive-check.jsonl
 *   node tools/dc-audit.mjs --file <path>      # a specific file, e.g. the rotated .1
 *   node tools/dc-audit.mjs --home <dir>       # resolve the default under another home
 *   node tools/dc-audit.mjs --json             # machine-readable summary
 *   node tools/dc-audit.mjs doctor [--home <dir>] [--json]
 *                                              # one report: the log's hash chain, the
 *                                              # installed guard against its install
 *                                              # manifest, the config file, and the
 *                                              # decisions in the last 200 entries
 *
 * Exit code: 0 = chain intact, 1 = broken chain or unreadable log, 2 = usage.
 * `doctor` exits 0 when the chain is intact, the installed guard hashes to the
 * manifest's sha256 and the config parses; 1 when any of those is false. It reads
 * the files and writes nothing, and it never imports the extension: a guard that
 * misreports its own state cannot change what the doctor says. Its guard line
 * carries the path, then present|missing for the file, then the verdict on its
 * sha256: match or changed against the manifest, unmanaged without one,
 * unreadable when the file cannot be hashed, absent when it is not there.
 *
 * The guard writes one JSON line per decision, each carrying `prev` (the
 * previous line's `chain`) and `chain` = SHA-256 of the line without `chain`.
 * This tool recomputes that with node:crypto, deliberately not with the
 * extension's own code: an independent implementation is what makes the check
 * worth running. Editing, reordering or deleting a line in the middle breaks the
 * chain; trimming the tail does not, and a writer with access to the file can
 * re-chain it — the log is a record, not a vault.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";

const USAGE = "usage: node tools/dc-audit.mjs [doctor] [--file <path>] [--home <dir>] [--json]";
const args = process.argv.slice(2);
const value = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
if (args.includes("--help") || args.includes("-h")) {
  console.log(fs.readFileSync(new URL(import.meta.url), "utf8").split("*/")[0].replace(/^\/\*\*?/, "").trim());
  process.exit(0);
}

// `doctor` is a mode, not a flag scattered through the argument list: the other
// flags keep the meaning they have always had for a plain chain walk.
const doctor = args[0] === "doctor";
if (doctor) {
  const rest = args.slice(1);
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === "--json") continue;
    if (rest[i] === "--home" && rest[i + 1] && !rest[i + 1].startsWith("-")) {
      i++;
      continue;
    }
    console.error(`${USAGE}\ndoctor: unknown or incomplete argument ${JSON.stringify(rest[i] ?? "--home needs a directory")}`);
    process.exit(2);
  }
}

const home = value("--home") ?? os.homedir();
const file = value("--file") ?? path.join(home, ".omp", "logs", "destructive-check.jsonl");
const asJson = args.includes("--json");

// Strings hash as utf8, and a Buffer hashes as the bytes on disk: the installed
// guard is compared with what install.mjs hashed, which is the file's bytes.
const sha256 = (input) => createHash("sha256").update(input).digest("hex");

// Verification walks the file once: every line must hash to its own `chain` and
// point at the previous line's `chain`. Truncated tails are fine; edits are not.
function walkChain(text) {
  const lines = text.split("\n").filter((l) => l.trim().length > 0);
  const problems = [];
  let prev = "";
  lines.forEach((line, i) => {
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      problems.push({ line: i + 1, reason: "not valid JSON" });
      return;
    }
    const { chain, ...core } = entry;
    if (core.prev !== prev) problems.push({ line: i + 1, reason: `prev is ${JSON.stringify(core.prev ?? null)}, expected ${JSON.stringify(prev)}` });
    else if (sha256(JSON.stringify({ ...core, prev: core.prev })) !== chain) problems.push({ line: i + 1, reason: "content does not hash to its own chain value" });
    prev = String(chain ?? "");
  });
  return { lines, problems };
}

const readText = (target) => {
  try {
    return { text: fs.readFileSync(target, "utf8") };
  } catch (err) {
    return { error: `cannot read ${target}: ${err.code ?? err.message}`, code: err.code };
  }
};

const readBytes = (target) => {
  try {
    return { bytes: fs.readFileSync(target) };
  } catch {
    return {};
  }
};

const exists = (target) => {
  try {
    return fs.existsSync(target);
  } catch {
    return false;
  }
};

// ------------------------------------------------------------------ doctor --
// One report over four sections. Nothing below writes: the log, the installed
// guard, the install manifest and the config are read, hashed and reported.
const entriesLine = (d) => `${d.entries} ${d.entries === 1 ? "entry" : "entries"}${d.entries > d.window ? ` (last ${d.window} counted)` : ""}`;

if (doctor) {
  const LABEL = 10;
  const say = (label, text) => console.log(`${label.padEnd(LABEL)}: ${text}`);

  // --- file ---------------------------------------------------------------
  const logPresent = exists(file);
  const logRead = readText(file);
  const walked = logRead.error ? { lines: [], problems: [] } : walkChain(logRead.text);
  // A missing log is an empty record, not tampering; anything else that stops the
  // walk is reported and makes the report unhealthy.
  const logIssues = logRead.error && logRead.code !== "ENOENT" ? [{ line: 0, reason: logRead.error }] : walked.problems;
  const fileSection = {
    path: file,
    present: logPresent,
    entries: walked.lines.length,
    chain: logRead.error ? (logPresent ? "BROKEN" : "intact") : walked.problems.length ? "BROKEN" : "intact",
    ok: logIssues.length === 0,
    problems: logIssues,
  };

  // --- guard --------------------------------------------------------------
  const guardFile = path.join(home, ".omp", "shared", "destructive-check.ts");
  const manifestFile = path.join(path.dirname(guardFile), "destructive-check.manifest.json");
  const backupFile = `${guardFile}.bak`;
  const guardPresent = exists(guardFile);
  const guardBytes = readBytes(guardFile);
  const actual = guardBytes.bytes ? sha256(guardBytes.bytes) : "";
  let manifest = null;
  const manifestBytes = readBytes(manifestFile);
  if (manifestBytes.bytes) {
    try {
      const parsed = JSON.parse(manifestBytes.bytes.toString("utf8"));
      if (parsed?.sha256) manifest = String(parsed.sha256);
    } catch {
      /* a manifest that is not JSON is no manifest */
    }
  }
  const integrity = actual ? (manifest ? (actual === manifest ? "match" : "changed") : "unmanaged") : guardPresent ? "unreadable" : "absent";
  const lock = (() => {
    try {
      return (fs.statSync(guardFile).mode & 0o200) !== 0 ? "writable" : "read-only";
    } catch {
      return "absent";
    }
  })();
  const backup = exists(backupFile) ? "present" : "absent";
  const guardSection = { path: guardFile, present: guardPresent, sha256: actual, manifestFile, manifest, integrity, lock, backup, ok: integrity === "match" };

  // --- config -------------------------------------------------------------
  const configFile = path.join(home, ".omp", "destructive-check.json");
  const configPresent = exists(configFile);
  const configRead = readText(configFile);
  let configKeys = [];
  let configError = null;
  if (!configRead.error) {
    try {
      const parsed = JSON.parse(configRead.text);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) configKeys = Object.keys(parsed).sort();
      else configError = `not a JSON object (${Array.isArray(parsed) ? "array" : typeof parsed})`;
    } catch (err) {
      configError = `invalid JSON: ${err.message}`;
    }
  } else if (configRead.code !== "ENOENT") {
    configError = configRead.error;
  }
  const configSection = { path: configFile, present: configPresent, keys: configKeys, ok: configError === null, error: configError };

  // --- decisions ----------------------------------------------------------
  const WINDOW = 200;
  const window = walked.lines.slice(-WINDOW);
  const parsedWindow = window.map((line) => {
    try {
      return JSON.parse(line);
    } catch {
      return null; // already reported as a chain problem
    }
  }).filter((entry) => entry !== null);
  const tally = (values) => {
    const counts = {};
    for (const v of values) counts[v] = (counts[v] ?? 0) + 1;
    return Object.fromEntries(Object.entries(counts).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)));
  };
  const actions = tally(parsedWindow.map((entry) => String(entry.action ?? "?")));
  const rules = tally(parsedWindow.map((entry) => String(entry.rule ?? "?")));
  const newest = (() => {
    for (let i = walked.lines.length - 1; i >= 0; i--) {
      try {
        const entry = JSON.parse(walked.lines[i]);
        if (entry?.ts) return String(entry.ts);
      } catch {
        /* keep looking: only the newest parsable entry has a timestamp */
      }
    }
    return "";
  })();
  const decisions = { window: WINDOW, counted: parsedWindow.length, entries: walked.lines.length, action: actions, rule: rules, newest };
  const listed = (counts) => (Object.keys(counts).length ? Object.entries(counts).map(([k, n]) => `${k} ${n}`).join(", ") : "(none)");

  const ok = fileSection.ok && guardSection.ok && configSection.ok;

  if (asJson) {
    console.log(JSON.stringify({ file: fileSection, guard: guardSection, config: configSection, decisions, ok }, null, 2));
  } else {
    say("file", `${file} ${logPresent ? "present" : "missing"}`);
    say("entries", String(fileSection.entries));
    say("chain", fileSection.chain);
    for (const problem of fileSection.problems.slice(0, 20)) console.log(problem.line ? `  line ${problem.line}: ${problem.reason}` : `  ${problem.reason}`);
    if (fileSection.problems.length > 20) console.log(`  … ${fileSection.problems.length - 20} more`);
    console.log("");
    say("guard", `${guardFile} ${guardPresent ? "present" : "missing"} ${integrity}`);
    say("sha256", actual || "(unreadable)");
    say("manifest", manifest ?? "(none)");
    say("lock", lock);
    say("backup", backup);
    console.log("");
    say("config", `${configFile} ${configPresent ? "present" : "missing"}`);
    say("keys", configKeys.length ? configKeys.join(", ") : "(none)");
    if (configError) say("error", configError);
    console.log("");
    say("decisions", entriesLine(decisions));
    say("action", listed(actions));
    say("rule", listed(rules));
    say("newest", newest || "(none)");
  }
  process.exit(ok ? 0 : 1);
}

// ------------------------------------------------------------- chain walk --
const read = readText(file);
if (read.error) {
  if (asJson) console.log(JSON.stringify({ file, entries: 0, ok: false, problems: [read.error] }));
  else console.error(read.error);
  process.exit(1);
}

const { lines, problems } = walkChain(read.text);

const tail = lines.slice(-5).map((line) => {
  try {
    const e = JSON.parse(line);
    return { ts: e.ts, tool: e.tool, rule: e.rule, action: e.action, command: String(e.command ?? "").slice(0, 60) };
  } catch {
    return { ts: "", tool: "", rule: "?", action: "unparsable", command: "" };
  }
});

if (asJson) {
  console.log(JSON.stringify({ file, entries: lines.length, ok: problems.length === 0, problems, tail }, null, 2));
} else {
  console.log(`file    : ${file}`);
  console.log(`entries : ${lines.length}`);
  console.log(`chain   : ${problems.length ? "BROKEN" : "intact"}`);
  for (const p of problems.slice(0, 20)) console.log(`  line ${p.line}: ${p.reason}`);
  if (problems.length > 20) console.log(`  … ${problems.length - 20} more`);
  console.log("");
  console.log("last entries:");
  for (const e of tail) console.log(`  ${String(e.ts).slice(11, 19)} ${e.action} · ${e.rule} · ${e.command}`);
}
process.exit(problems.length ? 1 : 0);
