// Test-quality gate: run the suites against deliberately broken copies of the
// extension and require each break to be caught. A mutation that survives means
// the check it targets asserts nothing. The patterns below are anchored to real
// lines, and a pattern that no longer matches is reported as a failure rather
// than skipped.
//
// The pristine source is never touched: every run loads a copy through DC_EXT,
// and the gate refuses to report anything before the unmutated copy passes the
// suites it is about to break (a check that was already red proves nothing).
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const EXT = "destructive-check.ts";
const original = fs.readFileSync(EXT, "utf8");
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), "dc-mutation-"));
const COPY = path.join(WORK, "destructive-check.ts");

// Each gate run gets its own scratch root: two suites (or two gates) running at
// the same time must not share ~/.omp-destructive-check-tests/<suite> state, or a
// concurrent run's leftovers turn into phantom failures. It stays outside the OS
// temp directory on purpose — the guard treats temp paths as disposable
// artifacts, so a scratch HOME under %TEMP% would change what the policy cases
// actually test.
const ROOT = path.join(os.homedir(), ".omp-destructive-check-tests", `mutation-${process.pid}`);

function runSuite(suite, extPath, label = "baseline") {
  // One scratch root per run, not per gate: a suite that leaves state behind
  // (an audit log, a trash directory, a config) must not be able to turn the next
  // mutation's run into a phantom crash or a phantom pass.
  const root = path.join(ROOT, String(label).replace(/[^a-z0-9]+/gi, "-").slice(0, 60) || "run");
  try {
    const out = execFileSync(process.execPath, [suite], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, DC_EXT: extPath, DC_TEST_ROOT: root } });
    return { code: 0, out };
  } catch (err) {
    return { code: err.status ?? 1, out: `${err.stdout ?? ""}${err.stderr ?? ""}` };
  }
}

const mutations = [
  {
    name: "internal error path blocks instead of failing open",
    suite: "tests/t-static.mjs",
    expect: "internal error fails open",
    from: "      const detail = String(err?.message ?? err).slice(0, 200);",
    to: "      return { block: true, reason: \"internal error\" };\n      void err;",
  },
  {
    name: "internal error is no longer logged",
    suite: "tests/t-static.mjs",
    expect: "internal error reaches the decision log",
    from: "      logDecision({ tool: String(event?.toolName ?? \"?\"), rule: \"internal\", action: \"error\", detail, command: typeof raw === \"string\" ? raw.slice(0, 240) : \"\", cwd: ctx?.cwd });",
    to: "",
  },
  {
    name: "verdict parser trusts the first verdict line again",
    suite: "tests/t-llm.mjs",
    expect: "names both verdicts fails closed",
    from: "  return deny ?? allow;\n}",
    to: "  return allow ?? deny;\n}",
  },
  {
    name: "request no longer carries an abort signal",
    suite: "tests/t-llm.mjs",
    expect: "aborts at the configured timeout",
    from: "  const signal = AbortSignal.timeout(Math.max(200, (deadline || Date.now() + CFG.timeoutMs) - Date.now()));",
    to: "  const signal = undefined;",
  },
  {
    name: "opencode providers lose the routing session header",
    suite: "tests/t-llm.mjs",
    expect: "opencode providers get a routing session id",
    from: "let sessionId = wantsSessionHeader(model) ? checkerSessionId(ctx) : \"\";",
    to: "let sessionId = \"\";",
  },
  {
    name: "an output cap is applied even when the config says 0",
    suite: "tests/t-llm.mjs",
    expect: "no output cap by default",
    from: "  const cap = Number(CFG.maxOutputTokens) > 0 ? Number(CFG.maxOutputTokens) : 0;",
    to: "  const cap = Number(CFG.maxOutputTokens) > 0 ? Number(CFG.maxOutputTokens) : 96;",
  },
  {
    name: "verdict cache ignores the workspace",
    suite: "tests/t-llm.mjs",
    expect: "cache is workspace-scoped",
    from: "  return `${policyRevision()}|${sha256Hex(`${plan.kind}\\u0000${plan.scope.cwdAbs}\\u0000${identity}`)}`;",
    to: "  return `${sha256Hex(identity)}`;",
  },
  {
    name: "the menu crashes when a select returns nothing",
    suite: "tests/t-menu.mjs",
    expect: "survives closing the menu",
    from: 'if (choice === undefined || choice.toLowerCase().startsWith("close")) open = false;',
    to: 'if (choice.toLowerCase().startsWith("close")) open = false;',
  },
  {
    name: "an unanswered user prompt opens the gate",
    suite: "tests/t-llm.mjs",
    expect: "DENY without a UI fails closed",
    from: '  if (!ctx?.hasUI || !ctx?.ui?.select) return "block";',
    to: '  if (!ctx?.hasUI || !ctx?.ui?.select) return "allow-once";',
  },
  {
    name: "bare git restore is no longer destructive",
    suite: "tests/t-static.mjs",
    expect: "uncommitted work destroyed: git restore src/app.js",
    from: "    const stagedOnly = has(/(^|\\s)--staged(\\s|$)/) && !has(/(^|\\s)(--worktree|-W|--source|-s)(\\s|=|$)/) && !hasShort(\"W\") && !hasShort(\"s\");",
    to: "    const stagedOnly = true;",
  },
  {
    name: "git switch -f loses its force detection",
    suite: "tests/t-static.mjs",
    expect: "uncommitted work destroyed: git switch -f main",
    from: "  if (sub === \"switch\" && (has(/(^|\\s)(-f|--force|--discard-changes)(\\s|$)/) || hasShort(\"f\"))) return true;",
    to: "  if (sub === \"switch\" && false) return true;",
  },
  {
    name: "git checkout -- pathspec restore is missed again",
    suite: "tests/t-static.mjs",
    expect: "uncommitted work destroyed: git checkout -- src/app.js",
    from: "    if (has(/(^|\\s)--(\\s|$)/)) return true;",
    to: "    if (false) return true;",
  },
  {
    name: "nested shell bodies are not unwrapped",
    suite: "tests/t-static.mjs",
    expect: "escaped quotes do not hide a nested payload",
    from: "    if (!t.quoted && SHELL_EXEC_FLAG_RE.test(t.text)) return unwrapShellBody(sub.slice(t.index + t.raw.length));",
    to: "    if (!t.quoted && SHELL_EXEC_FLAG_RE.test(t.text)) return sub.slice(t.index + t.raw.length);",
  },
  {
    name: "depth cutoff goes back to waving payloads through",
    suite: "tests/t-static.mjs",
    expect: "too-deep nesting is blocked",
    from: '  if (depth > MAX_SCAN_DEPTH) {\n    if (!found.some((f) => f.verb === "depth")) found.push({ verb: "depth", sub: command, scope });\n    return found;\n  }',
    to: '  if (depth > MAX_SCAN_DEPTH) return found;',
  },
  {
    name: "posix home paths are roots again",
    suite: "tests/t-static.mjs",
    expect: "posix home path inside the project is not treated as a root",
    from: "const ROOT_RE = /^(?:[a-zA-Z]:)?[\\\\/]?$|^\\/$/;",
    to: "const ROOT_RE = /^(?:[a-zA-Z]:)?[\\\\/]?$|^\\/(Users|Windows)(?:[\\\\/].*)?$/i;",
  },
  {
    name: "medium lets destructive git through again",
    suite: "tests/t-static.mjs",
    expect: "destructive git reaches the checker in medium",
    from: '    gitDestructive: "model",\n    scriptExec: "model",\n    codeDelete: "block",',
    to: '    gitDestructive: "allow",\n    scriptExec: "model",\n    codeDelete: "block",',
  },
  {
    name: "an approval option loses its explanation",
    suite: "tests/t-llm.mjs",
    expect: "carries an explanation",
    from: '    { label: "Block", description: "refuse the command; nothing is executed" },',
    to: '    { label: "Block" },',
  },
  {
    name: "script bodies are opened again by nobody",
    suite: "tests/t-coverage.mjs",
    expect: "script body: `sh ./loop.sh` is judged by what it runs",
    from: "  scanScoped(body.text, scope, depth + 1, found);",
    to: "  void body.text;",
  },
  {
    name: "an unreadable script is waved through",
    suite: "tests/t-coverage.mjs",
    expect: "script body: an unreadable script is scriptExec, not a pass",
    from: '    record({ verb: "script", reason: `could not read ${abs || rawPath}` });\n    return;',
    to: "    return;",
  },
  {
    name: "the script chain depth limit disappears",
    suite: "tests/t-coverage.mjs",
    expect: "script body: a chain past the analysis limit fails closed",
    from: "  if (state.depth + 1 > MAX_SCRIPT_DEPTH) {",
    to: "  if (false) {",
  },
  {
    name: "the probe whitelist is dropped",
    suite: "tests/t-coverage.mjs",
    expect: "probe: `command -v rm` runs nothing and is not blocked",
    from: "    if (PROBE_RE.test(cmd) && isProbe(toks.slice(i + 1))) return found;",
    to: "    if (false) return found;",
  },
  {
    name: "hub launches are not analysed",
    suite: "tests/t-coverage.mjs",
    expect: "hub: a launch is scanned like a command",
    from: '  if (name === "hub" && CFG.coverage.processes) {',
    to: "  if (false) {",
  },
  {
    name: "the catastrophic class is never consulted",
    suite: "tests/t-coverage.mjs",
    expect: "catastrophic [hard]: fork bomb",
    from: "  const out = catastrophicViolations(command);",
    to: "  const out = [];",
  },
  {
    name: "a catastrophic command inside a script body is dropped",
    suite: "tests/t-coverage.mjs",
    expect: "script body: a catastrophic command inside a script is caught",
    from: '    found.push({ verb: "catastrophic", detail: hit.detail, sub: rawPath, scope, script: state.script });',
    to: "    void hit;",
  },
  {
    name: "decisions stop being appended to the audit log",
    suite: "tests/t-coverage.mjs",
    expect: "audit: a blocked decision is appended to the log file",
    from: '    nodeFs.appendFileSync(LOG_FILE, auditLine(core) + "\\n", { mode: 0o600 });',
    to: "",
  },
  {
    name: "a .env file is no longer a credential path",
    suite: "tests/t-static.mjs",
    expect: "secret write blocked: .env in the project",
    from: '  if (base === ".env" || base.startsWith(".env.")) return true;',
    to: "  if (false) return true;",
  },
  {
    name: "the file tools skip the secret-path check",
    suite: "tests/t-static.mjs",
    expect: "secret write blocked: .env in the project",
    from: '    for (const target of fileToolTargets(input, text)) violations.push(...writeTargetViolations(target, scope, ""));',
    to: "",
  },
  {
    name: "redirect destinations are not classified again",
    suite: "tests/t-static.mjs",
    expect: "write blocked: a redirect leaving the project",
    from: '    for (const dest of redirectTargets(part)) out.push(...writeTargetViolations(dest, current, ">"));',
    to: '    for (const dest of []) out.push(...writeTargetViolations(dest, current, ">"));',
  },
  {
    name: "allowDirs entries are trusted as written again",
    suite: "tests/t-static.mjs",
    expect: "allowDirs: /dc status reports the rejected entry and the reason",
    from: "    const reason = allowDirReject(entry);",
    to: '    const reason = "";',
  },
  {
    name: "watch mode enforces its decisions again",
    suite: "tests/t-coverage.mjs",
    expect: "watch: an inside delete is not enforced",
    from: '  if (CFG.dryRun) {\n    if (action === "model") return checkThenDecide(ctx, key, violation, plan, event);',
    to: '  if (false) {\n    if (action === "model") return checkThenDecide(ctx, key, violation, plan, event);',
  },
  {
    name: "canonicalization stops resolving links",
    suite: "tests/t-coverage.mjs",
    expect: "realpath: a link inside the project that points outside is outside",
    from: "function resolveReal(abs, now) {",
    to: "function resolveReal(abs, now) {\n  return { path: nodePath.resolve(abs), cache: false };",
  },
  {
    name: "a shell-fed here-document body is dropped from the write scan again",
    suite: "tests/t-static.mjs",
    expect: "a shell-fed here-document body is scanned for writes",
    from: "  for (const body of bodies) if (body.code) out.push(...writeViolations(body.text, scope, depth + 1));",
    to: "  for (const body of bodies) if (false) out.push(...writeViolations(body.text, scope, depth + 1));",
  },
  {
    name: "the delete scanner ignores a shell-fed here-document body again",
    suite: "tests/t-static.mjs",
    expect: "a shell-fed here-document body is scanned for deletes",
    from: "  for (const body of bodies) if (body.code) scanScoped(body.text, current, depth + 1, found);",
    to: "  for (const body of bodies) if (false) scanScoped(body.text, current, depth + 1, found);",
  },
  {
    name: "the write scan trusts a probe word again",
    suite: "tests/t-static.mjs",
    expect: "a write behind `command`",
    from: "    if (PROBE_RE.test(cmd) && isProbe(toks.slice(i + 1))) return [];",
    to: "    if (PROBE_RE.test(cmd)) return [];",
  },
  {
    name: "the write scan ignores an inline cd again",
    suite: "tests/t-static.mjs",
    expect: "the write scan follows an inline cd",
    from: "      const moved = scopeAfterCd(current, cd[1]);",
    to: "      const moved = undefined;",
  },
  {
    name: ">| destinations are not read again",
    suite: "tests/t-static.mjs",
    expect: "a noclobber redirect leaving the project",
    from: '    } else if (sub[k] === "|") {\n      k++;\n    }',
    to: "    }",
  },
  {
    name: ">& with a file operand is skipped as a descriptor copy again",
    suite: "tests/t-static.mjs",
    expect: "both streams redirected to a file outside",
    from: '      if (/^\\s*(?:-|\\d+)(?![\\w.-])/.test(sub.slice(k + 1))) {\n        i = k;\n        continue;\n      }\n      k++;',
    to: "      i = k;\n      continue;",
  },
  {
    name: "a single operand is counted as a destination again",
    suite: "tests/t-static.mjs",
    expect: "install with a single operand only reads",
    from: '  if (c === "cp" || c === "mv" || c === "install") return lastOperand; // only the destination is written',
    to: '  if (c === "cp" || c === "mv" || c === "install") return operands.slice(-1);',
  },
  {
    name: "a destination flag is no longer the destination",
    suite: "tests/t-static.mjs",
    expect: "cp -t writing outside",
    from: "  if (flagged.some(Boolean)) return flagged.filter(Boolean);",
    to: "  if (false) return flagged.filter(Boolean);",
  },
  {
    name: "recovery rewrites a delete even when the mode is off",
    suite: "tests/t-llm.mjs",
    expect: "recovery: mode=off leaves the approved command alone",
    from: "  if (plan.kind !== \"bash\" || !recoveryApplies(rule)) return null;",
    to: "  if (plan.kind !== \"bash\") return null;",
  },
  {
    name: "the policy block is dropped from the checker prompt",
    suite: "tests/t-llm.mjs",
    expect: "the policy block leads the prompt and survives the budget",
    from: "  return fitPrompt(policyBlock(Math.floor(CFG.maxPromptChars * 0.6)), lines.join(\"\\n\"));",
    to: "  return fitPrompt(\"\", lines.join(\"\\n\"));",
  },
  {
    name: "authority=off still invites a justified repeat",
    suite: "tests/t-llm.mjs",
    expect: "retry: authority=off offers no invitation",
    from: "  if (retryAuthority() === \"off\") return \"the retry authority is off\";",
    to: "  if (false) return \"\";",
  },
  {
    name: "the session retry budget is ignored",
    suite: "tests/t-llm.mjs",
    expect: "retry: the session budget is spent after one retry",
    from: "  if (retriesSpent >= CFG.retry.sessionBudget) return \"the session's retry budget is used up\";",
    to: "  if (false) return \"\";",
  },
  {
    name: "the exempt floor can be emptied by the config",
    suite: "tests/t-llm.mjs",
    expect: "retry: an exempt rule gets no invitation",
    from: "  const out = new Set(RETRY_EXEMPT_RULES);",
    to: "  const out = new Set();",
  },
  {
    name: "an unjustified repeat reaches the retry checker",
    suite: "tests/t-llm.mjs",
    expect: "retry: a repeat with nothing new to say is a hard block",
    from: "  if (!justification.text) {",
    to: "  if (false) {",
  },
  {
    name: "a claim is believed without being verified",
    suite: "tests/t-llm.mjs",
    expect: "retry: a false committed claim blocks",
    from: "  if (CFG.verify.level !== \"off\" && !ok) {",
    to: "  if (false) {",
  },
  {
    name: "the retry verdict enum is not checked",
    suite: "tests/t-llm.mjs",
    expect: "retry: an unknown decision value is not a verdict",
    from: "  if (decision !== \"allow\" && decision !== \"block\") return null;",
    to: "  if (false) return null;",
  },
];

const rows = [];
try {
  fs.writeFileSync(COPY, original);
  const baseline = [];
  for (const suite of [...new Set(mutations.map((m) => m.suite))]) {
    const run = runSuite(suite, COPY);
    const green = run.code === 0 && /\d+\/\d+ passed/.test(run.out) && !/FAIL /.test(run.out);
    baseline.push({ suite, ...run, green });
  }
  const red = baseline.filter((b) => !b.green);
  for (const b of red) console.log(`BAD  baseline not green: ${b.suite} (exit ${b.code})`);
  if (red.length) {
    console.log("\nBASELINE IS NOT GREEN — a mutation could only be 'caught' by a check that already fails. Fix the suites first.");
    process.exitCode = 1;
  } else {
    for (const m of mutations) {
      const mutated = original.includes(m.from) ? original.replace(m.from, m.to) : null;
      if (mutated === null) {
        rows.push({ mutation: m.name, result: "PATTERN NOT FOUND (stale mutation)" });
        continue;
      }
      fs.writeFileSync(COPY, mutated);
      const { out: output } = runSuite(m.suite, COPY, m.name);
      // A suite that dies before printing its report proves nothing: without the
      // report there are no FAIL lines, and "no FAIL lines" is exactly what a
      // surviving mutation looks like. Count it as a crash, never as a catch.
      if (!/\d+\/\d+ passed/.test(output)) {
        rows.push({ mutation: m.name, result: "CRASHED (no report printed — not evidence)" });
        continue;
      }
      const failed = new RegExp(`FAIL `).test(output) && new RegExp(m.expect.slice(0, 30).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).test(output.split("FAIL").slice(1).join("FAIL"));
      rows.push({ mutation: m.name, result: failed ? "caught (suite failed as expected)" : "NOT CAUGHT — the check is vacuous" });
    }

    for (const r of rows) console.log(`${r.result === "caught (suite failed as expected)" ? "OK  " : "BAD "} ${r.mutation} — ${r.result}`);
    const allCaught = rows.length > 0 && rows.every((r) => r.result.startsWith("caught"));
    console.log(allCaught ? "\nall mutations caught" : "\nSOME MUTATIONS SURVIVED — the suite must be fixed or the mutation pattern updated");
    process.exitCode = allCaught ? 0 : 1;
  }
} finally {
  fs.rmSync(WORK, { recursive: true, force: true });
  fs.rmSync(ROOT, { recursive: true, force: true });
}
