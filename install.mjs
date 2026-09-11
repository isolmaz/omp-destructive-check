#!/usr/bin/env node
/**
 * install.mjs — copy destructive-check.ts into ~/.omp/shared/ and print the
 * config.yml block that loads it.
 *
 *   node install.mjs            # copy; asks before overwriting a different file
 *   node install.mjs --force    # overwrite without asking (a .bak copy is kept)
 *
 * The copy is shared by every omp profile. Fail-closed: an existing file is
 * never replaced without either --force or a "y" answer on stdin.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.join(HERE, "destructive-check.ts");

const HOME_DIR = path.resolve(os.homedir());
const OMP = path.join(HOME_DIR, ".omp");
const DEST = path.join(OMP, "shared", "destructive-check.ts");
const CONFIG_YML = path.join(OMP, "agent", "config.yml");
const AUTO_DISCOVERED = path.join(OMP, "agent", "extensions", "destructive-check.ts");

const args = process.argv.slice(2);
const force = args.includes("--force");

// Display paths relative to the home directory; separators normalized for
// output. path.relative handles separator and (on Windows) case differences.
const short = (p) => {
  const abs = path.resolve(p);
  const rel = path.relative(HOME_DIR, abs);
  const shown = rel && !rel.startsWith("..") && !path.isAbsolute(rel) ? path.join("~", rel) : abs;
  return shown.split(path.sep).join("/");
};

function snippet() {
  return [
    "Add this to " + short(CONFIG_YML) + ":",
    "",
    "extensions:",
    `  - ${short(DEST)}`,
    "",
    "Per-profile opt-out:",
    "",
    "disabledExtensions:",
    "  - extension-module:destructive-check",
  ].join("\n");
}

async function confirm(question) {
  if (!process.stdin.isTTY && !process.stdout.isTTY) return false;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await rl.question(question);
    return /^y(es)?$/i.test(answer.trim());
  } finally {
    rl.close();
  }
}

async function main() {
  if (args.includes("--help") || args.includes("-h")) {
    console.log("usage: node install.mjs [--force]");
    return 0;
  }

  if (!fs.existsSync(SRC)) {
    console.error(`install: ${short(SRC)} not found — run this script from the repository copy.`);
    return 1;
  }

  const source = fs.readFileSync(SRC);

  if (fs.existsSync(AUTO_DISCOVERED)) {
    console.log(`note: ${short(AUTO_DISCOVERED)} exists — auto-discovery already loads the extension.`);
  }

  fs.mkdirSync(path.dirname(DEST), { recursive: true });

  if (fs.existsSync(DEST)) {
    const current = fs.readFileSync(DEST);
    if (current.equals(source)) {
      console.log(`unchanged: ${short(DEST)}`);
    } else if (force || (await confirm(`overwrite ${short(DEST)}? [y/N] `))) {
      const backup = `${DEST}.bak`;
      fs.copyFileSync(DEST, backup);
      fs.copyFileSync(SRC, DEST);
      console.log(`installed: ${short(DEST)} (previous copy in ${short(backup)})`);
    } else {
      console.error(`install: kept the existing ${short(DEST)} — re-run with --force to overwrite.`);
      return 1;
    }
  } else {
    fs.copyFileSync(SRC, DEST);
    console.log(`installed: ${short(DEST)}`);
  }

  console.log("");
  console.log(snippet());

  if (fs.existsSync(CONFIG_YML)) {
    const config = fs.readFileSync(CONFIG_YML, "utf8");
    if (!config.includes("destructive-check")) {
      console.log("");
      console.log(`note: ${short(CONFIG_YML)} does not reference the extension yet.`);
    }
  }

  return 0;
}

process.exitCode = await main();
