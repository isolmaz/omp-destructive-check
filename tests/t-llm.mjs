// Checker layer: HTTP in-process verdicts, CLI fallback, failure policy, cache,
// prompt budget and intent injection.
import {
  fetchResponse,
  loadExt,
  makeCtx,
  callTool,
  bash,
  mkHome,
  fakeRegistry,
  installFetch,
  checkerRequests,
  checkerHeaders,
  lastCheckerRequest,
  checkerPrompt,
  dialogDefects,
  checkerUserPrompt,
  selectLog,
  check,
  report,
} from "./harness.mjs";

const HOME = mkHome("llm");
const CWD = "C:\\scratch\\proj";
const REG = fakeRegistry([
  ["opencode-go", "deepseek-v4.1-flash", { compat: { maxTokensField: "max_completion_tokens" } }],
  ["bai", "glm-5.3-flash"],
  ["google", "gemini-3.5-flash", { api: "google-generative-ai" }],
]);

const cfg = (extra = {}) => ({
  enabled: true,
  mode: "custom",
  rules: { insideDelete: "model" },
  provider: "opencode-go",
  providers: { "opencode-go": { model: "deepseek-v4.1-flash" }, bai: { model: "glm-5.3-flash" } },
  ...extra,
});

const ok = (content) => fetchResponse(200, { choices: [{ message: { content } }] });
const deny = (reason) => ok(`DENY: ${reason}`);
const err = (status, text = "") => fetchResponse(status, text);

async function run({ config = cfg(), handler, exec, selects = [], hasUI = true, command = "rm -rf src", event, branch } = {}) {
  installFetch(handler ?? (() => ok("ALLOW: regenerated output")));
  const ext = await loadExt({ home: HOME, config, registry: REG, exec });
  const ctx = makeCtx({ cwd: CWD, hasUI, selects: [...selects], registry: REG, branch });
  const result = await callTool(ext, event ?? bash(command, "cleanup source directory"), ctx);
  return { ext, ctx, result, execCalls: ext.execCalls.length, blocked: result?.block === true };
}

// ------------------------------------------------------------ verdict path --
{
  const p = await run({ handler: () => ok("ALLOW: regenerated build output") });
  check("ALLOW verdict passes the command", !p.blocked, JSON.stringify(p.result));
  check("checker request goes to /chat/completions", lastCheckerRequest().url.endsWith("/chat/completions"), lastCheckerRequest().url);
  check("checker body uses the model id", lastCheckerRequest().body.model === "deepseek-v4.1-flash");
  check("no output cap by default", !("max_completion_tokens" in lastCheckerRequest().body) && !("max_tokens" in lastCheckerRequest().body), JSON.stringify(lastCheckerRequest().body).slice(0, 200));
  check("checker identifies itself with a user agent", String(checkerHeaders()["user-agent"]).startsWith("omp-destructive-check/"), JSON.stringify(checkerHeaders()));
  check("opencode providers get a routing session id", String(checkerHeaders()["x-opencode-session"] ?? "").length > 8, JSON.stringify(checkerHeaders()));
  check("checker runs deterministically (temperature 0)", lastCheckerRequest().body.temperature === 0);
  check("checker request is not streamed", lastCheckerRequest().body.stream === false);
}
{
  const p = await run({ handler: () => ok("DENY: untracked user work would be lost"), selects: ["Block"] });
  check("DENY verdict blocks after the user confirms", p.blocked);
  check("DENY reason reaches the tool result", /untracked user work/.test(p.result?.reason ?? ""), p.result?.reason);
  check("block reason names the rule", /rule: insideDelete/.test(p.result?.reason ?? ""), p.result?.reason);
  check("block reason warns against tool-hopping", /another tool/.test(p.result?.reason ?? ""), p.result?.reason);
}
{
  const p = await run({ handler: () => ok("DENY: risky"), selects: ["Allow once"] });
  check("DENY + 'allow once' lets the command through", !p.blocked, JSON.stringify(p.result));
}
{
  // Reasoning traces are not verdicts: a model that "thinks" an ALLOW and then
  // returns no message has produced no decision, and that fails closed.
  const p = await run({
    handler: () => fetchResponse(200, { choices: [{ message: { content: "", reasoning_content: "checking …\nALLOW: only generated files" } }] }),
    hasUI: false,
    exec: async () => ({ stdout: "", stderr: "cli down", code: 1, killed: false }),
  });
  check("a verdict in reasoning_content is not a verdict", p.blocked, JSON.stringify(p.result));
}
{
  const p = await run({ handler: () => ok("DENY: risky"), selects: ["Allow for this session"] });
  const again = await callTool({ toolCall: p.ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, registry: REG }));
  check("session approval is remembered", again === undefined && checkerRequests().length === 1, `requests=${checkerRequests().length}`);
}
{
  const p = await run({ handler: () => ok("DENY: risky"), hasUI: false });
  check("DENY without a UI fails closed", p.blocked, JSON.stringify(p.result));
}
{
  const p = await run({ config: cfg({ askOnDeny: false }), handler: () => ok("DENY: risky"), selects: ["Allow once"] });
  check("askOnDeny=off blocks without prompting", p.blocked);
}

{
  // The previous parser trusted the first verdict line, so a model that named the
  // verdict it rejected ("an ALLOW would be wrong here … DENY:") could open the gate.
  const p = await run({ config: cfg({ askOnDeny: false }), handler: () => ok("ALLOW: looks like a generated dir\nwait — DENY: untracked work inside") });
  check("a reply that names both verdicts fails closed", p.blocked, JSON.stringify(p.result));
}
{
  // A stuck provider must not hold the command hostage: the request carries an
  // abort signal that fires at the configured timeout.
  let signal;
  await run({ config: cfg({ timeoutMs: 150 }), handler: (_url, init) => { signal = init?.signal; return ok("ALLOW: fine"); } });
  const outcome = await new Promise((resolve) => {
    if (!signal) return resolve("no signal on the request");
    if (signal.aborted) return resolve("aborted");
    const timer = setTimeout(() => resolve("never aborted"), 1500);
    signal.addEventListener("abort", () => { clearTimeout(timer); resolve("aborted"); }, { once: true });
  });
  check("the request aborts at the configured timeout", outcome === "aborted", outcome);
}

// --------------------------------------------------------- failure policy ---
{
  const p = await run({ handler: () => err(401, "unauthorized: invalid api key"), hasUI: false, exec: async () => ({ stdout: "", stderr: "cli down", code: 1, killed: false }) });
  check("HTTP failure blocks", p.blocked);
  check("HTTP failure reports status and body", /401/.test(p.result?.reason ?? "") && /invalid api key/.test(p.result?.reason ?? ""), p.result?.reason);
  check("HTTP failure is not reported as a model denial", !/model denied/.test(p.result?.reason ?? ""), p.result?.reason);
}
{
  const boom = async () => {
    throw new Error("connect ECONNREFUSED 127.0.0.1:443");
  };
  const asked = await run({ handler: boom, selects: ["Allow once"] });
  check("network failure asks the user (allow once)", !asked.blocked, JSON.stringify(asked.result));
  const blocked = await run({ handler: boom, hasUI: false, exec: async () => ({ stdout: "", stderr: "cli down", code: 1, killed: false }) });
  check("network failure without a UI blocks with the real cause", blocked.blocked && /ECONNREFUSED/.test(blocked.result?.reason ?? ""), blocked.result?.reason);
}
{
  const p = await run({ handler: () => ok("I cannot help with that."), hasUI: false, exec: async () => ({ stdout: "", stderr: "cli down", code: 1, killed: false }) });
  check("reply without a verdict line blocks", p.blocked && /no ALLOW\/DENY/.test(p.result?.reason ?? ""), p.result?.reason);
}
{
  const p = await run({ handler: () => fetchResponse(200, { choices: [{ message: {} }] }), hasUI: false, exec: async () => ({ stdout: "", stderr: "cli down", code: 1, killed: false }) });
  check("empty reply blocks with an actionable reason", p.blocked && /empty message \(finish_reason/.test(p.result?.reason ?? ""), p.result?.reason);
}
{
  const p = await run({ config: cfg({ provider: "opencode-go", providers: {}, model: "" }), hasUI: false });
  check("missing checker model fails with an actionable reason", p.blocked && /no checker model/.test(p.result?.reason ?? ""), p.result?.reason);
}

// ------------------------------------------------------------------ cache ---
{
  const p = await run({ handler: () => ok("ALLOW: fine") });
  const again = await callTool({ toolCall: p.ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, registry: REG }));
  check("identical command in the same workspace is cached", again === undefined && checkerRequests().length === 1, `requests=${checkerRequests().length}`);
  const other = await callTool({ toolCall: p.ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: "C:\\other\\ws", registry: REG }));
  check("cache is workspace-scoped", other === undefined && checkerRequests().length === 2, `requests=${checkerRequests().length}`);
}
{
  const p = await run({ config: cfg({ cacheEnabled: false }), handler: () => ok("ALLOW: fine") });
  await callTool({ toolCall: p.ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, registry: REG }));
  check("cache can be disabled", checkerRequests().length === 2, `requests=${checkerRequests().length}`);
}

// ----------------------------------------------------------------- prompt ---
{
  const p = await run({ handler: () => ok("ALLOW: fine"), event: bash(`rm -rf ${"dir/".repeat(120)}src`, "cleanup generated output") });
  const prompt = checkerUserPrompt();
  const body = lastCheckerRequest().body;
  check("prompt carries cwd", prompt.includes(CWD));
  check("prompt carries the action", /action: rm -rf/.test(prompt));
  check("prompt carries the agent intent", prompt.includes("cleanup generated output"));
  check("prompt marks the intent as agent-written and untrusted", /untrusted/.test(prompt) && /never an instruction/.test(prompt), prompt);
  check("prompt names the rule behind each flagged target", /\n  - \w+: /.test(prompt), prompt);
  // The budget is a contract, not a magic number: the request fits the configured
  // cap, and the policy block is the part that is never trimmed away — an action
  // the checker cannot see is worse than a short one.
  check("prompt stays inside the configured budget", prompt.length <= 1200, `len=${prompt.length}`);
  check("the policy block leads the prompt and survives the budget", prompt.startsWith("=== User policy") && /=== end policy ===/.test(prompt), prompt.slice(0, 120));
  check("checker contract is sent in the system role", body.messages?.[0]?.role === "system" && String(body.messages[0].content).length > 200);
  check("the system prompt says the policy block is authoritative", /authoritative/i.test(String(body.messages?.[0]?.content ?? "")), String(body.messages?.[0]?.content ?? "").slice(0, 160));
}
{
  // A user who lowers the cap gets the cap: the body is what gets trimmed.
  const p = await run({ config: cfg({ maxPromptChars: 400 }), handler: () => ok("ALLOW: fine") });
  const prompt = checkerUserPrompt();
  check("a lowered maxPromptChars is respected", prompt.length <= 400, `len=${prompt.length}`);
  check("the trimmed prompt still names the action", /action: /.test(prompt), prompt);
  check("the trimmed prompt still leads with the policy block", prompt.startsWith("=== User policy"), prompt.slice(0, 80));
}
{
  const p = await run({ config: cfg({ includeIntent: false }), handler: () => ok("ALLOW: fine"), event: bash("rm -rf src", "should not appear") });
  check("intent can be turned off", !checkerUserPrompt().includes("should not appear"));
}
{
  const branch = [
    { message: { role: "user", content: [{ type: "text", text: "please clean the repo" }] } },
    { message: { role: "assistant", content: [{ type: "text", text: "I will remove the generated build directory." }] } },
  ];
  await run({ handler: () => ok("ALLOW: fine"), event: { toolName: "bash", input: { command: "rm -rf src" } }, branch });
  check("intent falls back to the last assistant message", checkerUserPrompt().includes("remove the generated build directory"));
}

{
  const p = await run({ config: cfg({ maxOutputTokens: 128 }), handler: () => ok("ALLOW: fine") });
  check("a configured cap uses the model compat field", lastCheckerRequest().body.max_completion_tokens === 128, JSON.stringify(lastCheckerRequest().body).slice(0, 160));
}
{
  // Gateways that route per conversation answer 400 MissingSessionID first.
  let calls = 0;
  const prompts = () => checkerRequests();
  const p = await run({ config: cfg({ provider: "bai", providers: { bai: { model: "glm-5.3-flash" } } }), handler: (_url, init) => {
    calls += 1;
    const retried = Boolean(init?.headers?.["x-opencode-session"]);
    return retried ? ok("ALLOW: retried with session") : { ok: false, status: 400, text: async () => JSON.stringify({ error: { type: "MissingSessionID" } }), json: async () => ({}) };
  } });
  check("MissingSessionID triggers exactly one retry with a session id", calls === 2 && !p.blocked, `calls=${calls} requests=${prompts().length}`);
}
{
  const p = await run({ config: cfg({ provider: "bai", providers: { bai: { model: "glm-5.3-flash" } } }), hasUI: false, exec: async () => ({ stdout: "", stderr: "cli down", code: 1, killed: false }), handler: () => ({ ok: false, status: 400, text: async () => JSON.stringify({ error: { type: "MissingSessionID" } }), json: async () => ({}) }) });
  check("a persistent MissingSessionID fails with the provider body", p.blocked && /MissingSessionID/.test(p.result?.reason ?? ""), p.result?.reason);
}

// ------------------------------------------------------------ other APIs ----
{
  const p = await run({ config: cfg({ maxOutputTokens: 96, provider: "bai", providers: { bai: { model: "glm-5.3-flash" } } }), handler: () => ok("ALLOW: fine") });
  check("max_tokens is used when a cap is set", lastCheckerRequest().body.max_tokens === 96, JSON.stringify(lastCheckerRequest().body).slice(0, 160));
  check("providers that do not route by session get no session header", checkerHeaders()["x-opencode-session"] === undefined, JSON.stringify(checkerHeaders()));
  check("bai provider is used", lastCheckerRequest().url.includes("bai.example"), lastCheckerRequest().url);
}
{
  const registry = fakeRegistry([["anthropic", "claude-haiku-4-5", { api: "anthropic-messages", baseUrl: "https://api.anthropic.com" }]]);
  installFetch(() => fetchResponse(200, { content: [{ type: "text", text: "ALLOW: fine" }] }));
  const ext = await loadExt({ home: HOME, config: cfg({ provider: "anthropic", providers: { anthropic: { model: "claude-haiku-4-5" } } }), registry });
  const result = await callTool(ext, bash("rm -rf src"), makeCtx({ cwd: CWD, registry }));
  check("anthropic always sends max_tokens", lastCheckerRequest().body.max_tokens === 8192, JSON.stringify(lastCheckerRequest().body).slice(0, 160));
  check("anthropic API uses the messages endpoint", lastCheckerRequest().url === "https://api.anthropic.com/v1/messages", lastCheckerRequest().url);
  check("anthropic request keeps the system prompt", /safety reviewer/.test(String(lastCheckerRequest().body.system ?? "")));
  check("anthropic ALLOW passes", result === undefined);
}

// -------------------------------------------------------------- CLI engine --
{
  const p = await run({ config: cfg({ engine: "cli" }), exec: async () => ({ stdout: "ALLOW: cli engine ok", stderr: "", code: 0, killed: false }) });
  check("cli engine uses one nested invocation", p.execCalls === 1, `exec=${p.execCalls}`);
  check("cli engine passes the model spec", p.ext.execCalls[0].args.includes("opencode-go/deepseek-v4.1-flash"), p.ext.execCalls[0].args.join(" "));
  check("cli engine ALLOW passes", !p.blocked);
  const deny = await run({ config: cfg({ engine: "cli", askOnDeny: false }), exec: async () => ({ stdout: "DENY: risky", stderr: "", code: 0, killed: false }) });
  check("cli engine DENY blocks", deny.blocked && /risky/.test(deny.result?.reason ?? ""), deny.result?.reason);
  const killed = await run({ config: cfg({ engine: "cli" }), exec: async () => ({ stdout: "", stderr: "", code: 0, killed: true }), hasUI: false });
  check("killed checker process is a failure, not a denial", killed.blocked && /killed/.test(killed.result?.reason ?? ""), killed.result?.reason);
}
{
  // auto: unsupported API goes straight to the CLI
  const p = await run({ config: cfg({ provider: "google", providers: { google: { model: "gemini-3.5-flash" } } }), exec: async () => ({ stdout: "ALLOW: cli", stderr: "", code: 0, killed: false }) });
  check("auto: unsupported api uses the CLI", p.execCalls === 1 && checkerRequests().length === 0, `exec=${p.execCalls} http=${checkerRequests().length}`);
}
{
  // auto: in-process failure falls back to the CLI
  const p = await run({ handler: () => err(502, "bad gateway"), exec: async () => ({ stdout: "ALLOW: cli fallback", stderr: "", code: 0, killed: false }) });
  check("auto: in-process failure falls back to the CLI", p.execCalls === 1 && !p.blocked, `exec=${p.execCalls} blocked=${p.blocked}`);
  const both = await run({ handler: () => err(502, "bad gateway"), exec: async () => ({ stdout: "", stderr: "boom", code: 1, killed: false }), hasUI: false });
  check("auto: both engines failing reports both causes", both.blocked && /502/.test(both.result?.reason ?? "") && /boom/.test(both.result?.reason ?? ""), both.result?.reason);
}

// ------------------------------------------------------ second chance ------
// A blocked operation may be repeated once with a justification. Every row here
// names a plausible way that loop could be wrong: an invitation it should not
// give, a repeat it should not accept, a claim it must not believe.
const retryCfg = (extra = {}) =>
  cfg({
    rules: { insideDelete: "model" },
    askOnDeny: false,
    ...extra,
  });

// The first request is the normal verdict; the retry request is the one that
// carries the SECOND CHANCE marker.
const twoStage = (verdict, first = "DENY: untracked work would be lost") => (_url, init) => (String(init.body).includes("SECOND CHANCE") ? verdict : ok(first));
const jsonVerdict = (obj) => ok(JSON.stringify(obj));
const gitStub = ({ dirty = false, checkIgnore = 1, repo = true } = {}) => async (cmd, args) => {
  if (cmd !== "git") return { stdout: "", stderr: "not git", code: 1, killed: false };
  if (args[0] === "status") return { stdout: dirty ? " M src/keep.txt\n" : "", stderr: "", code: 0, killed: false };
  if (args[0] === "log") return { stdout: repo ? `${"a".repeat(40)}\n` : "", stderr: "", code: 0, killed: false };
  if (args[0] === "check-ignore") return { stdout: "", stderr: "", code: checkIgnore, killed: false };
  return { stdout: "", stderr: "unknown git probe", code: 1, killed: false };
};
const said = (text) => [{ message: { role: "assistant", content: [{ type: "text", text }] } }];
const retry = (pattern, base = retryCfg()) => ({ retry: { ...base.retry, ...pattern } });

{
  // The invitation is a promise: it appears on a first block, never on the block
  // that ends the loop, and the hard sentence replaces it exactly there. The
  // verdict here is a *verified* allow, so a build that let the unjustified repeat
  // through would open the gate — the row fails on the outcome, not on a wording.
  const allowWithClaim = jsonVerdict({ decision: "allow", confidence: "high", reason: "looks fine to me", claims: [{ type: "resolved_targets", value: "src" }] });
  const first = await run({ config: retryCfg(), handler: twoStage(allowWithClaim), branch: said("cleaning src") });
  check("retry: a first block invites the justified repeat", /repeat the same call/.test(first.result?.reason ?? ""), first.result?.reason);
  check("retry: a first block keeps the no-tool-hopping clause", /another tool/.test(first.result?.reason ?? ""), first.result?.reason);

  const again = await callTool({ toolCall: first.ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("cleaning src") }));
  check("retry: a repeat with nothing new to say is a hard block", again?.block === true && /No further attempts/.test(again?.reason ?? ""), again?.reason);
  check("retry: the hard block names the missing justification", /no new justification/.test(again?.reason ?? ""), again?.reason);
  check("retry: the hard block does not invite another repeat", !/repeat the same call/.test(again?.reason ?? ""), again?.reason);
  check("retry: the unjustified repeat costs no checker call", checkerRequests().length === 1, `requests=${checkerRequests().length}`);
}
{
  // Exempt rules never enter the loop, however the config reads: the floor is not
  // something a setting can lower.
  const p = await run({
    config: cfg({ rules: { protectSecrets: "block" }, retry: { authority: "model", exempt: [] } }),
    event: { toolName: "write", input: { path: `${CWD}\\.env`, input: "A=1\n" } },
    branch: said("writing the env file"),
  });
  check("retry: an exempt rule gets no invitation", p.blocked && !/repeat the same call/.test(p.result?.reason ?? ""), p.result?.reason);
  const again = await callTool({ toolCall: p.ext.toolCall }, { toolName: "write", input: { path: `${CWD}\\.env`, input: "A=1\n" } }, makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("the user asked me to write it") }));
  check("retry: an exempt rule never reaches the retry checker", again?.block === true && checkerRequests().length === 0, `requests=${checkerRequests().length}`);
}
{
  // authority=off and a spent budget are the same answer: no loop at all. A model
  // rule is still put to the checker — it is only the retry that is gone.
  const refused = () => deny("risky");
  const off = await run({ config: retryCfg({ retry: { authority: "off" } }), handler: refused, branch: said("cleaning src") });
  check("retry: authority=off offers no invitation", off.blocked && !/repeat the same call/.test(off.result?.reason ?? ""), off.result?.reason);
  const zero = await run({ config: retryCfg({ retry: { sessionBudget: 0 } }), handler: refused, branch: said("cleaning src") });
  check("retry: a zero session budget offers no invitation", zero.blocked && !/repeat the same call/.test(zero.result?.reason ?? ""), zero.result?.reason);
  const none = await run({ config: retryCfg({ retry: { maxAttempts: 0 } }), handler: refused, branch: said("cleaning src") });
  check("retry: a zero per-action budget offers no invitation", none.blocked && !/repeat the same call/.test(none.result?.reason ?? ""), none.result?.reason);
  const again = await callTool({ toolCall: off.ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("justify justify") }));
  check("retry: authority=off never invites the repeat", again?.block === true && /No further attempts/.test(again?.reason ?? ""), again?.reason);
}
{
  // The justified repeat: one extra request, inside the same budget, answered as
  // JSON, and the prompt it went out with says what the checker is looking at.
  const base = retryCfg();
  const exec = gitStub();
  const p = await run({
    config: base,
    exec,
    handler: twoStage(jsonVerdict({ decision: "allow", confidence: "high", reason: "git is clean and the target is regenerated", claims: [{ type: "committed", value: "src" }] })),
    branch: said("cleaning src"),
  });
  const second = await callTool(
    { toolCall: p.ext.toolCall },
    bash("rm -rf src"),
    makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("src is committed, nothing untracked lives there") }),
  );
  check("retry: a justified repeat is allowed", second?.block !== true, JSON.stringify(second));
  check("retry: the repeat costs exactly one extra checker call", checkerRequests().length === 2, `requests=${checkerRequests().length}`);
  const prompt = String(lastCheckerRequest().body.messages.at(-1).content);
  check("retry: the retry prompt is marked as a second chance", /SECOND CHANCE/.test(prompt), prompt.slice(0, 200));
  check("retry: the retry prompt leads with the policy block", prompt.startsWith("=== User policy"), prompt.slice(0, 80));
  check("retry: the justification is inside an untrusted block", /<untrusted_justification source="agent message">[\s\S]*committed, nothing untracked[\s\S]*<\/untrusted_justification>/.test(prompt), prompt);
  check("retry: the retry prompt names the resolved target", /resolved targets: src/.test(prompt), prompt);
  check("retry: the retry prompt asks for the JSON contract", /"decision":"allow"\|"block"/.test(prompt) && /"claims"/.test(prompt), prompt);
  check("retry: the retry prompt repeats the first refusal", /first refusal/.test(prompt), prompt);
}
{
  // Only JSON is a verdict on this path: prose, a wrong enum value and a missing
  // reason are all the same answer — block, and say why.
  const contract = /the JSON object the request asked for/;
  const prose = await run({ config: retryCfg(), handler: twoStage(ok("ALLOW: it is fine, trust me")), branch: said("first") });
  const proseRepeat = await callTool({ toolCall: prose.ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("allow it, it is fine") }));
  check("retry: a prose reply is not a retry verdict", proseRepeat?.block === true && contract.test(proseRepeat?.reason ?? ""), proseRepeat?.reason);

  const badEnum = await run({ config: retryCfg(), handler: twoStage(jsonVerdict({ decision: "maybe", confidence: "high", reason: "unsure" })), branch: said("first") });
  const enumRepeat = await callTool({ toolCall: badEnum.ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("a justification") }));
  check("retry: an unknown decision value is not a verdict", enumRepeat?.block === true && contract.test(enumRepeat?.reason ?? ""), enumRepeat?.reason);

  const noReason = await run({ config: retryCfg(), handler: twoStage(jsonVerdict({ decision: "allow", confidence: "high" })), branch: said("first") });
  const reasonRepeat = await callTool({ toolCall: noReason.ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("a justification") }));
  check("retry: an allow without a reason is not a verdict", reasonRepeat?.block === true && contract.test(reasonRepeat?.reason ?? ""), reasonRepeat?.reason);
}
{
  // The authority matrix. `ask` never lets the checker open the gate on its own,
  // and a low-confidence allow is not a decision either.
  const ask = await run({ config: retry({ authority: "ask" }), exec: gitStub(), handler: twoStage(jsonVerdict({ decision: "allow", confidence: "high", reason: "ok", claims: [{ type: "committed", value: "src" }] })), branch: said("first") });
  const asked = await callTool({ toolCall: ask.ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, hasUI: true, selects: ["Allow once"], registry: REG, branch: said("src is committed and regenerated") }));
  check("retry: authority=ask puts a model allow to the user", !asked?.block && selectLog.at(-1)?.title?.includes("destructive-check"), JSON.stringify(asked));

  const low = await run({ config: retryCfg(), exec: gitStub(), handler: twoStage(jsonVerdict({ decision: "allow", confidence: "low", reason: "probably ok", claims: [{ type: "committed", value: "src" }] })), branch: said("first") });
  const askedLow = await callTool({ toolCall: low.ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, hasUI: true, selects: ["Block"], registry: REG, branch: said("src is committed and regenerated") }));
  check("retry: a low-confidence allow becomes a question, not a decision", askedLow?.block === true && /the user refused/.test(askedLow?.reason ?? ""), askedLow?.reason);
}
{
  // Session budget: the second justified repeat in a session is not on offer, even
  // though this operation has never asked for one.
  const p = await run({
    config: retryCfg({ retry: { sessionBudget: 1 } }),
    exec: gitStub(),
    handler: twoStage(jsonVerdict({ decision: "allow", confidence: "high", reason: "ok", claims: [{ type: "committed", value: "src" }] })),
    branch: said("first"),
  });
  const allowed = await callTool({ toolCall: p.ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("src is committed") }));
  check("retry: the first justified repeat is allowed", allowed?.block !== true, JSON.stringify(allowed));
  const other = await callTool({ toolCall: p.ext.toolCall }, bash("rm -rf lib"), makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("first") }));
  check("retry: the session budget is spent after one retry", other?.block === true && !/repeat the same call/.test(other?.reason ?? ""), other?.reason);
}
{
  // A claim the guard cannot check is not evidence: this is what keeps a
  // confident-sounding justification from opening the gate by itself.
  const unverified = await run({
    config: retryCfg(),
    exec: gitStub({ dirty: true }),
    handler: twoStage(jsonVerdict({ decision: "allow", confidence: "high", reason: "the path is committed", claims: [{ type: "committed", value: "src" }] })),
    branch: said("first"),
  });
  const blocked = await callTool({ toolCall: unverified.ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("src is committed, honest") }));
  check("retry: a false committed claim blocks", blocked?.block === true && /could be verified/.test(blocked?.reason ?? ""), blocked?.reason);

  const noClaim = await run({ config: retryCfg(), handler: twoStage(jsonVerdict({ decision: "allow", confidence: "high", reason: "looks fine" })), branch: said("first") });
  const empty = await callTool({ toolCall: noClaim.ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("it looks fine to me") }));
  check("retry: an allow with no checkable claim blocks", empty?.block === true && /no claim/.test(empty?.reason ?? ""), empty?.reason);

  const mismatch = await run({
    config: retryCfg(),
    exec: gitStub({ checkIgnore: 1 }),
    handler: twoStage(jsonVerdict({ decision: "allow", confidence: "high", reason: "ignored", claims: [{ type: "resolved_targets", value: "lib" }] })),
    branch: said("first"),
  });
  const wrong = await callTool({ toolCall: mismatch.ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("the target list is just lib") }));
  check("retry: a claim that names the wrong target blocks", wrong?.block === true && /could be verified/.test(wrong?.reason ?? ""), wrong?.reason);

  const ignored = await run({
    config: retryCfg(),
    exec: gitStub({ checkIgnore: 0 }),
    handler: twoStage(jsonVerdict({ decision: "allow", confidence: "high", reason: "ignored", claims: [{ type: "ignored", value: "src" }] })),
    branch: said("first"),
  });
  const okIgnored = await callTool({ toolCall: ignored.ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("git ignores src") }));
  check("retry: a verified ignored claim allows", okIgnored?.block !== true, JSON.stringify(okIgnored));
}
{
  // user_authorized is checked against the user's own messages, which only the
  // `context` event carries.
  // Two retries are allowed here: the first is spent on the claim that cannot be
  // verified, the second on the one the user's own message backs.
  const ext = await loadExt({ home: HOME, config: retryCfg({ retry: { maxAttempts: 2 } }), registry: REG, exec: gitStub() });
  installFetch(twoStage(jsonVerdict({ decision: "allow", confidence: "high", reason: "the user asked for it", claims: [{ type: "user_authorized", value: "src" }] })));
  const onContext = ext.handlers.get("context")?.[0];
  check("retry: the context event is subscribed for user messages", typeof onContext === "function");
  await callTool(ext, bash("rm -rf src"), makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("first") }));
  const withoutUser = await callTool(ext, bash("rm -rf src"), makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("the user authorized this") }));
  check("retry: user_authorized with no user message blocks", withoutUser?.block === true, withoutUser?.reason);
  onContext({ messages: [{ role: "user", content: [{ type: "text", text: "please delete src, I re-created it" }] }] });
  const withUser = await callTool(ext, bash("rm -rf src"), makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("the user authorized this, see their message") }));
  check("retry: user_authorized against the user's own message allows", withUser?.block !== true, JSON.stringify(withUser));
}
{
  // dc_justify is the explicit half: it records, and only a matching target makes
  // the record count.
  const ext = await loadExt({ home: HOME, config: retryCfg(), registry: REG, exec: gitStub() });
  installFetch(twoStage(jsonVerdict({ decision: "allow", confidence: "high", reason: "ok", claims: [{ type: "committed", value: "src" }] })));
  const tool = ext.tools.get("dc_justify");
  check("retry: dc_justify is registered and visible", Boolean(tool) && tool.hidden === false && tool.approval === "read", JSON.stringify(tool && Object.keys(tool)));
  check("retry: dc_justify describes itself", /justif/i.test(String(tool?.description ?? "")), String(tool?.description ?? ""));
  const recorded = await tool.execute("call-1", { target: "src", intent: "src is regenerated output, the file is committed", evidence: "git status is clean" });
  check("retry: dc_justify records and says so", /recorded/.test(String(recorded?.content?.[0]?.text ?? "")), JSON.stringify(recorded));
  const refused = await tool.execute("call-2", { target: "", intent: "" });
  check("retry: dc_justify refuses an empty record", /nothing was recorded/.test(String(refused?.content?.[0]?.text ?? "")), JSON.stringify(refused));
  // The hint tells the agent the tool exists; it is a custom message, not policy.
  const hint = ext.handlers.get("before_agent_start")?.[0]?.({}, makeCtx({ cwd: CWD, registry: REG }));
  check("retry: the agent is told the justification tool exists", /dc_justify/.test(String(hint?.message?.content ?? "")), JSON.stringify(hint));
  await callTool(ext, bash("rm -rf src"), makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("first") }));
  // No new assistant text at all this time: only the dc_justify record justifies it.
  const viaTool = await callTool(ext, bash("rm -rf src"), makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("first") }));
  check("retry: a recorded justification counts without new agent text", viaTool?.block !== true, JSON.stringify(viaTool));
  const prompt = String(lastCheckerRequest().body.messages.at(-1).content);
  check("retry: the recorded justification travels in its own untrusted block", /<untrusted_justification source="dc_justify tool">[\s\S]*regenerated output/.test(prompt), prompt);
}
{
  // Recovery is what makes an approved delete reversible: the rewritten command is
  // what runs, and the modes decide whether it is written at all.
  const base = retryCfg();
  const runCase = async (config) => {
    const p = await run({
      config,
      exec: gitStub(),
      handler: twoStage(jsonVerdict({ decision: "allow", confidence: "high", reason: "ok", claims: [{ type: "committed", value: "src" }] })),
      branch: said("first"),
    });
    // The first call was refused; this is the justified repeat.
    return callTool({ toolCall: p.ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, hasUI: false, registry: REG, branch: said("src is committed and regenerated") }));
  };
  const rewritten = await runCase(base);
  check("recovery: the delete is rewritten into a move", /^mkdir -p .*\.omp\/dc-trash\/session\/\d{8}-\d{6}/.test(String(rewritten?.input?.command ?? "")), JSON.stringify(rewritten));
  check("recovery: the move is reported truthfully to the agent", /echo "destructive-check: moved src to /.test(String(rewritten?.input?.command ?? "")), String(rewritten?.input?.command ?? ""));
  check("recovery: the rewrite keeps the original command out of it", !/rm -rf/.test(String(rewritten?.input?.command ?? "")), String(rewritten?.input?.command ?? ""));
  const off = await runCase({ ...base, recovery: { mode: "off" } });
  check("recovery: mode=off leaves the approved command alone", off?.input === undefined && !off?.block, JSON.stringify(off));
  const high = await runCase({ ...base, recovery: { mode: "high" } });
  check("recovery: mode=high skips a rule that is not high severity", high?.input === undefined && !high?.block, JSON.stringify(high));
}
{
  const defects = dialogDefects();
  check("every approval option carries an explanation", defects.length === 0, defects.join(" | "));
}

// ------------------------------------------------------------ two stages ---
// The one-digit pre-filter: `0` answers without the detailed request, `1` pays for
// it, and anything that is not a digit is a checker failure — never an allow.
{
  const staged = async (fast) => {
    installFetch((_url, init) => (String(init.body).includes("FAST STAGE") ? ok(fast) : ok("ALLOW: the detailed answer")));
    const ext = await loadExt({ home: HOME, config: cfg({ checker: { twoStage: true } }), registry: REG });
    const ctx = makeCtx({ cwd: CWD, registry: REG, selects: ["Block"] });
    const result = await callTool(ext, bash("rm -rf src", "cleanup"), ctx);
    const bodies = checkerRequests().map((call) => JSON.parse(call.init.body));
    return { result, bodies, fast: bodies.filter((body) => String(body.messages?.at(-1)?.content ?? "").includes("FAST STAGE")) };
  };
  const zero = await staged("0");
  check("two-stage: a 0 answers without the detailed request", !zero.result?.block && zero.bodies.length === 1 && zero.fast.length === 1, JSON.stringify({ calls: zero.bodies.length, result: zero.result }));
  check("two-stage: the fast request carries its own small cap", zero.fast[0]?.max_completion_tokens === 512, JSON.stringify(zero.fast[0]?.max_completion_tokens));
  check("two-stage: the fast request still carries the user policy block", /User policy/.test(String(zero.fast[0]?.messages?.at(-1)?.content ?? "")), String(zero.fast[0]?.messages?.at(-1)?.content ?? "").slice(0, 120));
  const one = await staged("1");
  check("two-stage: a 1 buys the detailed request", !one.result?.block && one.bodies.length === 2 && one.fast.length === 1, JSON.stringify({ calls: one.bodies.length, result: one.result }));
  check("two-stage: the detailed request has no fast-stage instruction", !/FAST STAGE/.test(String(one.bodies.at(-1)?.messages?.at(-1)?.content ?? "")), String(one.bodies.at(-1)?.messages?.at(-1)?.content ?? "").slice(0, 120));
  const junk = await staged("2");
  check("two-stage: an answer that is not 0 or 1 is a checker failure, not an allow", junk.result?.block === true && /neither 0 nor 1/.test(String(junk.result?.reason ?? "")), String(junk.result?.reason ?? "").slice(0, 240));
  const prose = await staged("I would need more context to decide.");
  check("two-stage: a prose answer fails closed with its own text", prose.result?.block === true && /neither 0 nor 1/.test(String(prose.result?.reason ?? "")), String(prose.result?.reason ?? "").slice(0, 240));
}

const bad = report("checker layer");
process.exitCode = bad ? 1 : 0;
