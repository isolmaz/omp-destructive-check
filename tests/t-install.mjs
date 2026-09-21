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

try {
  fs.rmSync(ROOT, { recursive: true, force: true });
} catch {
  console.error(`install: scratch cleanup left ${ROOT} behind`);
}

const bad = report("install");
process.exitCode = bad ? 1 : 0;
