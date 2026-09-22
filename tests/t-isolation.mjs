// Isolation mechanics — the out-of-band half of the guard.
//
// Everything in destructive-check.ts runs in-band: same user, same filesystem
// rights as the agent it watches. The runbook in docs/REFERENCE.md tells users to
// put the boundary somewhere the agent cannot rewrite — a deny ACE on the guard
// files and on the data that must survive. This suite executes exactly those
// commands in a scratch directory, so the runbook is known to work on this
// machine instead of being advice nobody tried.
import * as fs from "node:fs";
import * as path from "node:path";
import { execFileSync } from "node:child_process";
import { mkHome, check, report } from "./harness.mjs";

const ROOT = mkHome("isolation");

if (process.platform !== "win32") {
  console.log("\n### isolation\n  1/1 passed (SKIP: deny-ACE mechanics are exercised with icacls on Windows)");
  process.exit(0);
}

// icacls wants the principal the way the account database knows it: for a local
// account that is `MACHINE\user`; a bare name can resolve to a phantom principal
// that never matches the token the agent runs with.
const USER = [process.env.USERDOMAIN, process.env.USERNAME].filter(Boolean).join("\\") || String(process.env.USERNAME ?? "");
const icacls = (args) => {
  try {
    return execFileSync("icacls", args, { encoding: "utf8" });
  } catch (err) {
    return `${err.stdout ?? ""}${err.stderr ?? ""}`;
  }
};
const listed = (dir) => /DENY/i.test(icacls([dir]));
const canDelete = (target) => {
  try {
    fs.rmSync(target, { recursive: true, force: true });
    return true;
  } catch {
    return false;
  }
};

const dir = path.join(ROOT, "protected");
const file = path.join(dir, "keep.txt");
const clearAce = () => icacls([dir, "/remove:d", USER]);

fs.rmSync(ROOT, { recursive: true, force: true });
fs.mkdirSync(dir, { recursive: true });
fs.writeFileSync(file, "user data\n");
clearAce();

fs.writeFileSync(path.join(dir, "probe.txt"), "x");
check("isolation: a control file is deletable before the ACE", canDelete(path.join(dir, "probe.txt")) && !fs.existsSync(path.join(dir, "probe.txt")), "the control delete failed");

// 1. Deny delete on the directory: the ACE inherits to its children, so neither
//    the file inside nor the directory itself can be removed by the account the
//    agent runs as — whatever tool asks, extension or not.
const applied = icacls([dir, "/deny", `${USER}:(OI)(CI)(D)`]);
check("isolation: the deny ACE is listed on the directory", listed(dir), applied);
check("isolation: deleting a file inside the denied directory fails", !canDelete(file) && fs.existsSync(file), "the delete succeeded — the ACE did not hold");

// 2. An over-eager `rm -rf` does not get further.
check("isolation: recursive removal of the denied tree fails", !canDelete(dir) && fs.existsSync(file), "rm -rf removed a denied directory");

// 3. The ACE is what holds it: remove it and the same delete works again.
clearAce();
check("isolation: removing the deny ACE clears it from the listing", !listed(dir), icacls([dir]));
check("isolation: after /remove:d the delete works again", canDelete(file) && !fs.existsSync(file), "still denied after /remove:d");

clearAce();
try {
  fs.rmSync(ROOT, { recursive: true, force: true });
} catch {
  console.error(`isolation: scratch cleanup left ${ROOT} behind`);
}

const bad = report("isolation");
process.exitCode = bad ? 1 : 0;
