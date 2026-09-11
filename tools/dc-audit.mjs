#!/usr/bin/env node
/**
 * dc-audit.mjs — independent verifier for the destructive-check audit log.
 *
 *   node tools/dc-audit.mjs                  # ~/.omp/logs/destructive-check.jsonl
 *   node tools/dc-audit.mjs --file <path>    # a specific file, e.g. the rotated .1
 *   node tools/dc-audit.mjs --home <dir>     # resolve the default under another home
 *   node tools/dc-audit.mjs --json           # machine-readable summary
 *
 * Exit code: 0 = chain intact, 1 = broken chain or unreadable log, 2 = usage.
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

const args = process.argv.slice(2);
const value = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
if (args.includes("--help") || args.includes("-h")) {
  console.log(fs.readFileSync(new URL(import.meta.url), "utf8").split("*/")[0].replace(/^\/\*\*?/, "").trim());
  process.exit(0);
}

const home = value("--home") ?? os.homedir();
const file = value("--file") ?? path.join(home, ".omp", "logs", "destructive-check.jsonl");
const asJson = args.includes("--json");

const sha256 = (text) => createHash("sha256").update(text, "utf8").digest("hex");

let raw;
try {
  raw = fs.readFileSync(file, "utf8");
} catch (err) {
  const why = `cannot read ${file}: ${err.code ?? err.message}`;
  if (asJson) console.log(JSON.stringify({ file, entries: 0, ok: false, problems: [why] }));
  else console.error(why);
  process.exit(1);
}

const lines = raw.split("\n").filter((l) => l.trim().length > 0);
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
