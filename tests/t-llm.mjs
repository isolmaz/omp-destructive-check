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
  const p = await run({
    handler: () => fetchResponse(200, { choices: [{ message: { content: "", reasoning_content: "checking …\nALLOW: only generated files" } }] }),
  });
  check("verdict is read from reasoning_content too", !p.blocked, JSON.stringify(p.result));
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
  check("empty reply blocks with an actionable reason", p.blocked && /empty reply/.test(p.result?.reason ?? ""), p.result?.reason);
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
  check("prompt stays inside the token budget", prompt.length <= 900, `len=${prompt.length}`);
  check("checker contract is sent in the system role", body.messages?.[0]?.role === "system" && String(body.messages[0].content).length > 200);
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

// The approval prompt is the one dialogue this suite opens.
{
  const defects = dialogDefects();
  check("every approval option carries an explanation", defects.length === 0, defects.join(" | "));
}

const bad = report("checker layer");
process.exitCode = bad ? 1 : 0;
