// The installer's pre-install test gate.
//
// destructive-check.ts is copied into ~/.omp/shared/, the directory every omp
// profile loads, so a build that fails its own suites must never get there.
// install.mjs runs the five offline stub suites first and refuses to copy when
// one of them fails; --skip-tests is the deliberate bypass.
//
// This suite is NOT part of the gate's own suite list (install.mjs SUITES):
// running it from inside the gate would nest installer invocations for no gain.
// Run it directly:  node tests/t-install.mjs
import * as fs from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { mkHome, check, report } from "./harness.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, "..");
const ROOT = mkHome("install");
const SRC_DIR = path.join(ROOT, "repo");
const HOME = path.join(ROOT, "home");
const DEST = path.join(HOME, ".omp", "shared", "destructive-check.ts");
const MANIFEST = path.join(HOME, ".omp", "shared", "destructive-check.manifest.json");

fs.rmSync(ROOT, { recursive: true, force: true });
fs.mkdirSync(HOME, { recursive: true });
// A faithful snapshot, `.git` included: the review suite reads older revisions
// (`git show HEAD~3:destructive-check.ts`) to prove a regression stays closed.
fs.cpSync(REPO, SRC_DIR, {
  recursive: true,
  filter: (src) => !src.includes(`${path.sep}.omp-destructive-check-tests`) && !src.endsWith(`${path.sep}node_modules`),
});

const COPY_SRC = path.join(SRC_DIR, "destructive-check.ts");
const PRISTINE = fs.readFileSync(path.join(REPO, "destructive-check.ts"));

const install = (argv) => {
  try {
    const stdout = execFileSync(process.execPath, [path.join(SRC_DIR, "install.mjs"), ...argv], {
      encoding: "utf8",
      cwd: SRC_DIR,
      env: { ...process.env, USERPROFILE: HOME, HOME, DC_TEST_ROOT: path.join(HOME, ".scratch") },
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { code: 0, out: stdout };
  } catch (err) {
    return { code: err.status ?? 1, out: `${err.stdout ?? ""}${err.stderr ?? ""}` };
  }
};

// 1. A guard that cannot load fails its own suites — and never reaches the
//    directory every profile loads.
fs.appendFileSync(COPY_SRC, "\nthis is not valid typescript(((\n");
const refused = install(["--force"]);
check("install: a broken guard is refused", refused.code !== 0, `code=${refused.code}`);
check("install: the refusal names the failing suite and says nothing was installed", /t-static\.mjs failed/.test(refused.out) && /nothing was installed/.test(refused.out), refused.out.slice(0, 300));
check("install: nothing was written when the gate refuses", !fs.existsSync(DEST), DEST);

// 2. --skip-tests is the explicit bypass, and it still installs the file it was
//    given (the gate is a safety net, not a second implementation of the copy).
const bypassed = install(["--force", "--skip-tests"]);
check("install: --skip-tests bypasses the gate", bypassed.code === 0 && fs.existsSync(DEST), `code=${bypassed.code} ${bypassed.out.slice(0, 200)}`);

// 3. With a healthy guard the gate runs the suites and the copy goes through,
//    byte for byte, with a manifest written next to it.
fs.writeFileSync(COPY_SRC, PRISTINE);
const healthy = install(["--force"]);
check("install: a healthy guard installs", healthy.code === 0, `code=${healthy.code} ${healthy.out.slice(-300)}`);
check("install: the gate reports the suites it ran", /tests\s+: t-static\.mjs \d+\/\d+ passed/.test(healthy.out), healthy.out.slice(0, 300));
check("install: the installed copy matches the source", fs.existsSync(DEST) && fs.readFileSync(DEST).equals(PRISTINE), "copy differs from source");
check("install: the manifest is written", fs.existsSync(MANIFEST), MANIFEST);

// 4. `dc-audit doctor` is the file-based report over the installed guard, the
//    audit chain and the config. It has to be right about a state it can only see
//    on disk, so the rows below hand it a known state and then break it: the log
//    the suite chains itself (the installer never runs the extension, and an audit
//    file written by the code under test would prove nothing) and the installed
//    copy, which the last row edits behind the manifest's back.
const AUDIT_DIR = path.join(HOME, ".omp", "logs");
const AUDIT = path.join(AUDIT_DIR, "destructive-check.jsonl");
const CONFIG = path.join(HOME, ".omp", "destructive-check.json");
const DOCTOR = path.join(SRC_DIR, "tools", "dc-audit.mjs");

const doctor = (argv) => {
  try {
    const stdout = execFileSync(process.execPath, [DOCTOR, ...argv], {
      encoding: "utf8",
      cwd: SRC_DIR,
      env: { ...process.env, USERPROFILE: HOME, HOME, DC_TEST_ROOT: path.join(HOME, ".scratch") },
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { code: 0, out: stdout };
  } catch (err) {
    return { code: err.status ?? 1, out: `${err.stdout ?? ""}${err.stderr ?? ""}` };
  }
};

// The guard's own line format: one entry plus the hash of the entry before it, in
// the key order the extension writes. Any other order would not hash to `chain`.
const chained = (entries) => {
  let prev = "";
  return entries.map((entry) => {
    const core = { ...entry, prev };
    prev = createHash("sha256").update(JSON.stringify(core)).digest("hex");
    return JSON.stringify({ ...core, chain: prev });
  });
};
const logEntry = (n, rule, action) => ({
  ts: `2026-01-01T00:00:0${n}.000Z`, session: "install-suite", tool: "bash", rule, action, detail: `${rule} was requested`, command: `cmd ${n}`, cwd: SRC_DIR, mode: "enforce", ms: n,
});
const LOG = chained([
  logEntry(1, "rm-rf", "block"),
  logEntry(2, "git-reset", "ask"),
  logEntry(3, "curl-pipe", "model"),
  logEntry(4, "npm-install", "allow"),
  logEntry(5, "rm-rf", "allow"),
]);
fs.mkdirSync(AUDIT_DIR, { recursive: true });
fs.writeFileSync(AUDIT, `${LOG.join("\n")}\n`);
fs.writeFileSync(CONFIG, `${JSON.stringify({ mode: "ask" }, null, 2)}\n`);

// No --home: the doctor resolves the scratch home from the environment the same
// way the installer does.
const healthyDoctor = doctor(["doctor"]);
const healthyRow = (label) => healthyDoctor.out.split("\n").find((line) => line.startsWith(label)) ?? "";
check("doctor: a healthy install reports exit 0", healthyDoctor.code === 0, `code=${healthyDoctor.code} ${healthyDoctor.out.slice(0, 300)}`);
check("doctor: the guard row matches its manifest", /^guard\s*:.*\bmatch\b/m.test(healthyDoctor.out), healthyRow("guard"));
check("doctor: the guard lock is reported as writable", /^lock\s*:\s*writable$/m.test(healthyDoctor.out), healthyRow("lock"));
check("doctor: the log chain is reported intact", /^chain\s*:\s*intact$/m.test(healthyDoctor.out), healthyRow("chain"));
check("doctor: the decisions section counts the last entries", /^decisions\s*:\s*5 entries$/m.test(healthyDoctor.out) && /^action\s*:\s*allow 2, ask 1, block 1, model 1$/m.test(healthyDoctor.out) && /^newest\s*:\s*2026-01-01T00:00:05\.000Z$/m.test(healthyDoctor.out), healthyDoctor.out.split("\n").filter((line) => /^(decisions|action|rule|newest)/.test(line)).join(" | "));
check("doctor: the config section lists the keys it found", /^config\s*:.*\bpresent$/m.test(healthyDoctor.out) && /^keys\s*:\s*mode$/m.test(healthyDoctor.out), healthyRow("config"));
check("doctor: the report is read-only", fs.readFileSync(AUDIT, "utf8") === `${LOG.join("\n")}\n`, `${AUDIT} changed while the doctor ran`);

const asObject = (run) => {
  try {
    return JSON.parse(run.out);
  } catch {
    return null;
  }
};
const jsonDoctor = asObject(doctor(["doctor", "--home", HOME, "--json"]));
check("doctor: --json returns the same report as one object", jsonDoctor?.ok === true && jsonDoctor?.guard?.integrity === "match" && jsonDoctor?.file?.chain === "intact" && jsonDoctor?.config?.keys?.join() === "mode" && jsonDoctor?.decisions?.action?.block === 1 && jsonDoctor?.decisions?.newest === "2026-01-01T00:00:05.000Z", JSON.stringify(jsonDoctor)?.slice(0, 300) ?? "not JSON");

// One edited line in the middle: the entry no longer hashes to its own chain, and
// the report has to name it. The tail below it still passes (its `prev` points at
// the chain value the edited line kept), so the number is the whole assertion.
const editedLog = LOG.slice();
editedLog[2] = editedLog[2].replace("cmd 3", "cmd 3 --force");
fs.writeFileSync(AUDIT, `${editedLog.join("\n")}\n`);
const brokenDoctor = doctor(["doctor", "--home", HOME]);
check("doctor: an edited line is reported by its number", brokenDoctor.code === 1 && /^chain\s*:\s*BROKEN$/m.test(brokenDoctor.out) && /\bline 3\b/.test(brokenDoctor.out), `code=${brokenDoctor.code} ${brokenDoctor.out.split("\n").slice(0, 6).join(" | ")}`);
fs.writeFileSync(AUDIT, `${LOG.join("\n")}\n`);

// A guard that no longer matches the manifest is what an in-place edit looks
// like: exit 1 and `changed`, with the log left intact so the guard is the only
// thing that can make it unhealthy.
fs.appendFileSync(DEST, "\n// edited outside the installer\n");
const changedDoctor = doctor(["doctor", "--home", HOME]);
check("doctor: an edited guard reads as changed", changedDoctor.code === 1 && /^guard\s*:.*\bchanged\b/m.test(changedDoctor.out), `code=${changedDoctor.code} ${changedDoctor.out.split("\n").find((line) => line.startsWith("guard")) ?? ""}`);

const misuse = doctor(["doctor", "--file", AUDIT]);
check("doctor: a flag it does not take is a usage error", misuse.code === 2, `code=${misuse.code} ${misuse.out.slice(0, 200)}`);

try {
  fs.rmSync(ROOT, { recursive: true, force: true });
} catch {
  console.error(`install: scratch cleanup left ${ROOT} behind`);
}

const bad = report("install");
process.exitCode = bad ? 1 : 0;
