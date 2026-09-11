// /dc command: protection modes, per-rule editing, toggles and persistence.
import { loadExt, makeCtx, callTool, bash, mkHome, fakeRegistry, installFetch, fetchResponse, checkerRequests, selectLog, dialogDefects, check, report } from "./harness.mjs";

const HOME = mkHome("menu");
const CWD = "C:\\scratch\\proj";
const REG = fakeRegistry([
  ["opencode-go", "deepseek-v4.1-flash"],
  ["bai", "glm-5.3-flash"],
]);

const cfg = (extra = {}) => ({
  enabled: true,
  mode: "medium",
  provider: "opencode-go",
  providers: { "opencode-go": { model: "deepseek-v4.1-flash" }, bai: { model: "glm-5.3-flash" } },
  ...extra,
});

const pick = (prefix) => (options) => options.map((o) => (typeof o === "string" ? o : o.label)).find((l) => l.startsWith(prefix));
const exact = (label) => (options) => options.map((o) => (typeof o === "string" ? o : o.label)).find((l) => l === label);

async function menu({ config = cfg(), selections = [], inputs = [], hasUI = true, fetchHandler, exec } = {}) {
  installFetch(fetchHandler ?? (() => fetchResponse(200, { choices: [{ message: { content: "ALLOW: self-test" } }] })));
  const ext = await loadExt({ home: HOME, config, registry: REG, exec });
  const ctx = makeCtx({ cwd: CWD, hasUI, registry: REG, selects: selections, inputs });
  const confirms = [];
  ctx.ui.confirm = async (title, message) => {
    confirms.push(`${title}\n${message}`);
    return true;
  };
  await ext.commands.get("dc").handler("", ctx);
  return { ext, ctx, confirms, config: ext.readConfig() };
}

// ----------------------------------------------------------------- status ---
{
  const { confirms, ctx } = await menu({ selections: [pick("status"), pick("close")] });
  const text = confirms.join("\n");
  for (const needle of ["protection", "checker", "timeout", "ask on deny", "coverage", "rules"]) {
    check(`/dc status shows ${needle}`, text.includes(needle), text.slice(0, 200));
  }
  check("/dc sets a status line", ctx.statuses.some((s) => String(s.text).includes("dc:")), JSON.stringify(ctx.statuses));
}
{
  const { ctx } = await menu({ hasUI: false });
  check("/dc headless prints the status", ctx.notes.some((n) => /protection/.test(n.message)), JSON.stringify(ctx.notes).slice(0, 160));
}
{
  const { confirms } = await menu({ selections: [pick("recent decisions"), pick("close")] });
  check("/dc lists recent decisions", confirms.some((c) => /no decisions yet/.test(c)), JSON.stringify(confirms).slice(0, 120));
}

{
  const { confirms } = await menu({ selections: [pick("test checker"), pick("close")], fetchHandler: () => fetchResponse(200, { choices: [{ message: { content: "DENY: sample looks risky" } }] }) });
  const text = confirms.join("\n");
  check("/dc self-test reports the engine that will be used", /auto → in-process/.test(text), text.slice(0, 200));
  check("/dc self-test reports the verdict", /DENY — sample looks risky/.test(text), text.slice(0, 300));
  check("/dc self-test reports the latency", /request : \d+ ms/.test(text), text.slice(0, 300));
  check("/dc self-test reaches the provider once", checkerRequests().length === 1, `requests=${checkerRequests().length}`);
  check("/dc self-test never runs the sample command", /nothing is executed/.test(text), text.slice(0, 300));
}
{
  const { confirms, ctx } = await menu({ selections: [pick("test checker"), pick("close")], fetchHandler: () => fetchResponse(403, "forbidden: bad key"), exec: async () => ({ stdout: "", stderr: "cli down", code: 1, killed: false }) });
  const text = confirms.join("\n");
  check("/dc self-test surfaces the real failure", /FAILED after \d+ ms/.test(text) && /403/.test(text), text.slice(0, 300));
  check("/dc self-test failure pops an error notice", ctx.notes.some((n) => n.level === "error"), JSON.stringify(ctx.notes).slice(0, 200));
}
{
  const registry = fakeRegistry([["google", "gemini-3.5-flash", { api: "google-generative-ai" }]]);
  installFetch(() => fetchResponse(200, { choices: [{ message: { content: "ALLOW: x" } }] }));
  const ext = await loadExt({ home: HOME, config: cfg({ provider: "google", providers: { google: { model: "gemini-3.5-flash" } } }), registry, exec: async () => ({ stdout: "ALLOW: cli", stderr: "", code: 0, killed: false }) });
  const ctx = makeCtx({ cwd: CWD, registry, selects: [pick("status"), pick("close")] });
  const confirms = [];
  ctx.ui.confirm = async (title, message) => (confirms.push(message), true);
  await ext.commands.get("dc").handler("", ctx);
  check("/dc status shows the effective CLI engine for unsupported APIs", /auto → cli \(google-generative-ai\)/.test(confirms.join("\n")), confirms.join("\n").slice(0, 300));
}

// ------------------------------------------------------------- protection ---
{
  const { config } = await menu({ selections: [pick("protection"), pick("hard"), pick("close")] });
  check("/dc switches the protection mode", config.mode === "hard", JSON.stringify(config));
  check("/dc clears stored custom rules when a preset is chosen", !config.rules || Object.keys(config.rules).length === 0, JSON.stringify(config.rules));
}
{
  const { config } = await menu({ selections: [pick("protection"), pick("simple"), pick("close")] });
  check("/dc can select simple mode", config.mode === "simple", JSON.stringify(config));
}

// -------------------------------------------------------------- rule edits --
{
  const { config } = await menu({ selections: [pick("rules"), pick("insideDelete"), pick("allow"), pick("close"), pick("close")] });
  check("/dc rule edit switches to custom mode", config.mode === "custom", JSON.stringify(config));
  check("/dc rule edit persists the action", config.rules?.insideDelete === "allow", JSON.stringify(config.rules));
}
{
  const { config } = await menu({ selections: [pick("rules"), pick("systemTarget"), pick("model"), pick("close"), pick("close")] });
  check("/dc can set a rule to model escalation", config.rules?.systemTarget === "model", JSON.stringify(config.rules));
}

// ----------------------------------------------------------------- toggles --
{
  const { config } = await menu({ selections: [pick("ask on deny"), pick("close")] });
  check("/dc toggles ask-on-deny", config.askOnDeny === false, JSON.stringify(config));
}
{
  const { config } = await menu({ selections: [pick("ask on error"), pick("close")] });
  check("/dc toggles ask-on-error", config.askOnError === false, JSON.stringify(config));
}
{
  const { config } = await menu({ selections: [pick("intent"), pick("close")] });
  check("/dc toggles intent injection", config.includeIntent === false, JSON.stringify(config));
}
{
  const { config } = await menu({ selections: [pick("coverage"), pick("eval:"), pick("close")] });
  check("/dc toggles tool coverage", config.coverage?.eval === false, JSON.stringify(config.coverage));
}
{
  const { config } = await menu({ selections: [pick("cache"), pick("toggle"), pick("close")] });
  check("/dc toggles the verdict cache", config.cacheEnabled === false, JSON.stringify(config));
}

// ------------------------------------------------------------ allowed dirs --
{
  const { config } = await menu({ selections: [pick("allowed dirs"), exact("add a directory"), pick("close")], inputs: ["C:\\shared\\libs"] });
  check("/dc stores an extra project directory", config.allowDirs?.[0] === "C:\\shared\\libs", JSON.stringify(config.allowDirs));
  const guard = await loadExt({ home: HOME, config, registry: REG });
  const inside = await callTool(guard, bash("rm -rf C:\\shared\\libs\\generated"), makeCtx({ cwd: CWD, registry: REG }));
  check("extra project directory changes classification (simple mode)", config.mode === "medium" ? inside?.block === true : inside === undefined, JSON.stringify(inside)?.slice(0, 140));
}
{
  const withDirs = cfg({ allowDirs: ["C:\\shared\\libs", "D:\\scratch"] });
  const { config } = await menu({ config: withDirs, selections: [pick("allowed dirs"), pick("clear the list"), pick("close")] });
  check("/dc clears the extra project directories", (config.allowDirs ?? []).length === 0, JSON.stringify(config.allowDirs));
}

// ---------------------------------------------------------------- checker ---
{
  const { config } = await menu({ selections: [pick("checker"), pick("model:"), pick("bai"), pick("glm-5.3-flash"), pick("back"), pick("close")] });
  check("/dc switches the checker provider", config.provider === "bai", JSON.stringify(config));
  check("/dc stores the per-provider model", config.providers?.bai?.model === "glm-5.3-flash", JSON.stringify(config.providers));
  check("/dc keeps the other provider entry", config.providers?.["opencode-go"]?.model === "deepseek-v4.1-flash", JSON.stringify(config.providers));
}

{
  const { config } = await menu({ selections: [pick("checker"), pick("engine:"), "cli", pick("back"), pick("close")] });
  check("/dc persists the checker engine", config.engine === "cli", JSON.stringify(config.engine));
}
{
  const { config } = await menu({ selections: [pick("checker"), pick("token cap"), "512", pick("back"), pick("close")], inputs: ["512"] });
  check("/dc persists the output token cap", config.maxOutputTokens === 512, JSON.stringify(config.maxOutputTokens));
}
{
  const { config } = await menu({ selections: [pick("checker"), pick("reasoning:"), "low", pick("back"), pick("close")] });
  check("/dc persists the reasoning effort", config.reasoning === "low", JSON.stringify(config.reasoning));
}
{
  const { config } = await menu({ selections: [pick("checker"), pick("timeout:"), pick("back"), pick("close")], inputs: ["2500"] });
  check("/dc persists the checker timeout", config.timeoutMs === 2500, JSON.stringify(config.timeoutMs));
}
{
  const { config } = await menu({ selections: [pick("checker"), pick("timeout:"), pick("back"), pick("close")], inputs: ["not a number"] });
  check("/dc ignores a nonsense timeout", config.timeoutMs === undefined, JSON.stringify(config.timeoutMs));
}

// ------------------------------------------------------- escapes and safety --
{
  let threw = null;
  let result = null;
  try {
    result = await menu({ selections: [undefined, undefined], inputs: [undefined] });
  } catch (err) {
    threw = err;
  }
  check("/dc survives closing the menu without choosing anything", !threw, String(threw));
  check("/dc with no selections leaves the config untouched", result && JSON.stringify(result.config) === JSON.stringify(cfg()), JSON.stringify(result?.config));
}

// ------------------------------------------------------------- explanations --
{
  // Dialogue coverage is asserted by every suite that opens one; this one walks
  // the menus, t-llm covers the approval prompt.
  const defects = dialogDefects();
  check("every /dc option carries an explanation", defects.length === 0, defects.slice(0, 8).join(" | "));
  check("the menu surface was actually exercised", selectLog.length > 10, `dialogs=${selectLog.length}`);
}

const bad = report("/dc command");
process.exitCode = bad ? 1 : 0;
