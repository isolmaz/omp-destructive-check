// Test-quality gate: run the suites against deliberately broken copies of the
// extension and require each break to be caught. A mutation that survives means
// the check it targets asserts nothing. Run it after changing policy or checker
// code; the patterns below are anchored to real lines, and a pattern that no
// longer matches is reported as a failure rather than skipped.
// Restores the extension afterwards (a crash mid-run leaves it mutated).
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";

const EXT = "destructive-check.ts";
const original = fs.readFileSync(EXT, "utf8");

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
    from: "      logDecision({ tool: String(event?.toolName ?? \"?\"), rule: \"internal\", action: \"error\", detail });",
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
    from: "  const signal = AbortSignal.timeout(CFG.timeoutMs);",
    to: "  const signal = undefined;",
  },
  {
    name: "opencode providers lose the routing session header",
    suite: "tests/t-llm.mjs",
    expect: "opencode providers get a routing session id",
    from: "let sessionId = wantsSessionHeader(model) ? checkerSessionId(ctx) : \"\";",
    to: "const sessionId = \"\";",
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
    from: "  return `${scope.cwdAbs}|${action}`;",
    to: "  return `${action}`;",
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
    from: "    const stagedOnly = has(/(^|\\s)--staged(\\s|$)/) && !has(/(^|\\s)(--worktree|--source|-s)(\\s|=|$)/);",
    to: "    const stagedOnly = true;",
  },
  {
    name: "git switch -f loses its force detection",
    suite: "tests/t-static.mjs",
    expect: "uncommitted work destroyed: git switch -f main",
    from: "  if (sub === \"switch\" && has(/(^|\\s)(-f|--force|--discard-changes)(\\s|$)/)) return true;",
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
    from: '        scanScoped(unwrapShellBody(sub.slice(flag.index + flag.raw.length)), scope, depth + 1, found);',
    to: '        scanScoped(sub.slice(flag.index + flag.raw.length), scope, depth + 1, found);',
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
    from: '    gitDestructive: "model",\n    scriptExec: "allow",\n    codeDelete: "block",',
    to: '    gitDestructive: "allow",\n    scriptExec: "allow",\n    codeDelete: "block",',
  },
];

const rows = [];
for (const m of mutations) {
  const mutated = original.includes(m.from) ? original.replace(m.from, m.to) : null;
  if (mutated === null) {
    rows.push({ mutation: m.name, result: "PATTERN NOT FOUND (stale mutation)" });
    continue;
  }
  fs.writeFileSync(EXT, mutated);
  let output = "";
  try {
    output = execFileSync(process.execPath, [m.suite], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (err) {
    output = `${err.stdout ?? ""}${err.stderr ?? ""}`;
  }
  const failed = new RegExp(`FAIL `).test(output) && new RegExp(m.expect.slice(0, 30).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).test(output.split("FAIL").slice(1).join("FAIL"));
  rows.push({ mutation: m.name, result: failed ? "caught (suite failed as expected)" : "NOT CAUGHT — the check is vacuous" });
}
fs.writeFileSync(EXT, original);

for (const r of rows) console.log(`${r.result === "caught (suite failed as expected)" ? "OK  " : "BAD "} ${r.mutation} — ${r.result}`);
const allCaught = rows.every((r) => r.result.startsWith("caught"));
console.log(allCaught ? "\nall mutations caught" : "\nSOME MUTATIONS SURVIVED — the suite must be fixed or the mutation pattern updated");
process.exitCode = allCaught ? 0 : 1;
