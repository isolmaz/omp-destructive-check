// /dc command: protection modes, per-rule editing, toggles and persistence.
import { loadExt, makeCtx, callTool, bash, mkHome, fakeRegistry, installFetch, fetchResponse, checkerRequests, selectLog, overlayLog, dialogDefects, check, report } from "./harness.mjs";

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

async function menu({ config = cfg(), selections = [], inputs = [], hasUI = true, fetchHandler, exec, overlay = false, overlays = [] } = {}) {
  installFetch(fetchHandler ?? (() => fetchResponse(200, { choices: [{ message: { content: "ALLOW: self-test" } }] })));
  const ext = await loadExt({ home: HOME, config, registry: REG, exec });
  const ctx = makeCtx({ cwd: CWD, hasUI, registry: REG, selects: selections, inputs, overlay, overlays });
  const confirms = [];
  ctx.ui.confirm = async (title, message) => {
    confirms.push(`${title}\n${message}`);
    return true;
  };
  // The handler must never take the process down with it: a suite that dies
  // before it prints its report proves nothing (the mutation gate counts a crash
  // as a survivor), so the throw is captured here and asserted per case.
  let error = null;
  try {
    await ext.commands.get("dc").handler("", ctx);
  } catch (err) {
    error = err;
  }
  return { ext, ctx, confirms, error, config: ext.readConfig() };
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
  // The config has `enabled`, the status line reports it, and the menu is the only
  // surface users touch — so the switch has to live there, not in a hand-edited file.
  const off = await menu({ config: cfg({ enabled: false }), selections: [pick("enabled:"), pick("status"), pick("close")] });
  check("/dc turns the guard on and persists it", off.config.enabled === true, JSON.stringify(off.config));
  const on = await menu({ selections: [pick("enabled:"), pick("close")] });
  check("/dc turns the guard off and persists it", on.config.enabled === false, JSON.stringify(on.config));
  check("/dc reports the off state on the status line", on.ctx.statuses.some((s) => String(s.text) === "dc: off"), JSON.stringify(on.ctx.statuses));
}
{
  // The in-memory ring dies with the module instance; the log file does not, and
  // reading it back is the point of writing it.
  installFetch(() => fetchResponse(200, { choices: [{ message: { content: "ALLOW: stub" } }] }));
  const ext = await loadExt({ home: HOME, config: cfg(), registry: REG });
  const ctx = makeCtx({ cwd: CWD, registry: REG });
  await callTool(ext, bash("rm -rf /etc", "cleanup"), ctx);
  const { confirms } = await menu({ selections: [pick("recent decisions"), pick("close")] });
  check("/dc lists decisions from the log file", confirms.some((c) => /block · systemTarget/.test(c)), JSON.stringify(confirms).slice(0, 200));
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
  // `menu()` swallows the throw so the suite can still print its report, so the
  // check has to look at both: an unanswered select must leave the menu, not
  // walk into `choice.toLowerCase()`.
  check("/dc survives closing the menu without choosing anything", !threw && !result?.error, String(threw ?? result?.error));
  check("/dc with no selections leaves the config untouched", result && JSON.stringify(result.config) === JSON.stringify(cfg()), JSON.stringify(result?.config));
}

// --------------------------------------------------- new settings (S2) -----
{
  // Every new setting is a menu entry + a DEFAULTS key + a persistence check.
  const { config } = await menu({ selections: [pick("friction preset"), "quiet", pick("close")] });
  check("/dc stores the friction preset", config.preset === "quiet", JSON.stringify(config.preset));
  check("/dc writes the settings the preset stands for", config.askOnDeny === false && config.retry?.authority === "off" && config.verify?.level === "off", JSON.stringify({ askOnDeny: config.askOnDeny, retry: config.retry, verify: config.verify }));
}
{
  const { config } = await menu({ selections: [pick("friction preset"), "strict", pick("close")] });
  check("/dc can select the strict preset", config.preset === "strict" && config.verify?.level === "claims+adversarial", JSON.stringify({ preset: config.preset, verify: config.verify }));
}
{
  const { config } = await menu({ selections: [pick("policy note"), pick("close")], inputs: ["never touch the archive folder"] });
  check("/dc stores the policy note", config.policyNote === "never touch the archive folder", JSON.stringify(config.policyNote));
}
{
  const { config } = await menu({ selections: [pick("ui:"), pick("pop-up mode"), pick("close"), pick("close")] });
  check("/dc cycles the pop-up mode", config.ui?.overlay === "always", JSON.stringify(config.ui));
}
{
  const { config, error } = await menu({ selections: [pick("ui:"), pick("status line"), pick("status line location"), undefined, pick("close"), pick("close")] });
  check("/dc moves the status line without leaving the menu", config.ui?.statusLine?.location === "belowEditor", JSON.stringify(config.ui?.statusLine));
  check("/dc survives an unanswered status-line select", !error, String(error));
}
{
  const { config } = await menu({ selections: [pick("ui:"), pick("status line"), pick("status line detail"), pick("close"), pick("close")] });
  check("/dc cycles the status line detail", ["minimal", "counters"].includes(config.ui?.statusLine?.detail), JSON.stringify(config.ui?.statusLine));
}
{
  const { config } = await menu({ selections: [pick("ui:"), pick("status line"), pick("bar side"), pick("close"), pick("close")] });
  check("/dc moves the guard's segment to the other side", config.ui?.statusLine?.barSide === "left", JSON.stringify(config.ui?.statusLine));
}
{
  const { config } = await menu({ selections: [pick("ui:"), pick("pop-up buttons"), pick("close"), pick("close")] });
  check("/dc trims the pop-up buttons but keeps deny", (config.ui?.popupButtons ?? []).includes("deny") && config.ui.popupButtons.length < 3, JSON.stringify(config.ui?.popupButtons));
}
{
  const { config } = await menu({ selections: [pick("ui:"), pick("session summary"), pick("close"), pick("close")] });
  check("/dc toggles the session summary", config.ui?.sessionSummary === false, JSON.stringify(config.ui));
}
{
  const { config } = await menu({ selections: [pick("retry:"), pick("retry authority"), pick("close"), pick("close")] });
  check("/dc cycles the retry authority", config.retry?.authority === "ask", JSON.stringify(config.retry));
}
{
  const { config } = await menu({ selections: [pick("retry:"), pick("attempts per action"), pick("close"), pick("close")] });
  check("/dc cycles the per-action attempt budget", config.retry?.maxAttempts === 2, JSON.stringify(config.retry));
}
{
  const { config } = await menu({ selections: [pick("retry:"), pick("attempts per session"), pick("close"), pick("close")] });
  check("/dc cycles the per-session attempt budget", config.retry?.sessionBudget === 5, JSON.stringify(config.retry));
}
{
  const { config } = await menu({ selections: [pick("retry:"), pick("remember approvals"), pick("close"), pick("close")] });
  check("/dc cycles how approvals are remembered", config.retry?.rememberApproved === "once", JSON.stringify(config.retry));
}
{
  const { config } = await menu({ selections: [pick("retry:"), pick("justify tool"), pick("close"), pick("close")] });
  check("/dc toggles the justify tool", config.justifyTool?.enabled === false, JSON.stringify(config.justifyTool));
}
{
  const { config } = await menu({ selections: [pick("retry:"), pick("verification"), pick("close"), pick("close")] });
  check("/dc cycles the verification level", config.verify?.level === "claims+adversarial", JSON.stringify(config.verify));
}
{
  const { config } = await menu({ selections: [pick("retry:"), pick("recovery:"), pick("close"), pick("close")] });
  check("/dc cycles the recovery mode", config.recovery?.mode === "high", JSON.stringify(config.recovery));
}
{
  const { config } = await menu({ selections: [pick("retry:"), pick("trash retention"), pick("close"), pick("close")] });
  check("/dc cycles the trash retention", config.recovery?.ttlHours === 168, JSON.stringify(config.recovery));
}
{
  const { config } = await menu({ selections: [pick("retry:"), pick("trust erosion"), pick("close"), pick("close")] });
  check("/dc cycles the trust erosion mode", config.erosion?.mode === "log", JSON.stringify(config.erosion));
}
{
  // The exemption list is stored policy: the row adds one rule to it, and the
  // three fixed rules are a floor, not a setting — they never reach the file.
  const added = await menu({ selections: [pick("retry:"), pick("exempt from the loop: insideDelete"), pick("close"), pick("close")] });
  check("/dc stores an extra exemption from the loop", (added.config.retry?.exempt ?? []).includes("insideDelete"), JSON.stringify(added.config.retry));
  check("/dc never writes the fixed exemptions to the file", !(added.config.retry?.exempt ?? []).includes("catastrophic"), JSON.stringify(added.config.retry));
  const removed = await menu({
    config: cfg({ retry: { exempt: ["insideDelete"] } }),
    selections: [pick("retry:"), pick("exempt from the loop: insideDelete"), pick("close"), pick("close")],
  });
  check("/dc takes a rule back out of the exemption list", !(removed.config.retry?.exempt ?? []).includes("insideDelete"), JSON.stringify(removed.config.retry));
  const cleared = await menu({
    config: cfg({ retry: { exempt: ["insideDelete", "scriptExec"] } }),
    selections: [pick("retry:"), pick("always exempt"), pick("close"), pick("close")],
  });
  check("/dc clears the extra exemptions from the fixed row", (cleared.config.retry?.exempt ?? []).length === 0, JSON.stringify(cleared.config.retry));
}
{
  // The trash directory is where a justified delete is moved instead of removed:
  // a text row, so the value has to survive the round trip through the file.
  const { config } = await menu({ selections: [pick("retry:"), pick("trash directory"), pick("close"), pick("close")], inputs: ["D:\\dc-trash"] });
  check("/dc stores the trash directory", config.recovery?.dir === "D:\\dc-trash", JSON.stringify(config.recovery));
  const blank = await menu({ selections: [pick("retry:"), pick("trash directory"), pick("close"), pick("close")], inputs: ["   "] });
  check("/dc ignores an empty trash directory", blank.config.recovery?.dir === undefined, JSON.stringify(blank.config.recovery));
}
{
  // The pick-up panel is the other setting surface: it writes the same keys.
  const before = overlayLog.length;
  const { config } = await menu({ overlay: true, overlays: [["\r", "\u001b"]] });
  check("/dc opens the setting panel when the host draws overlays", overlayLog.length === before + 1, `overlays=${overlayLog.length - before}`);
  check("the panel row cycles and persists the friction preset", config.preset === "strict", JSON.stringify(config.preset));
  const rows = overlayLog.at(-1)?.options ?? [];
  for (const group of ["Simple", "Protection", "Coverage", "Retry & justification", "Checker", "UI", "Advanced", "Guard", "History"]) {
    check(`the panel has the ${group} section`, rows.some((row) => row.label === group), rows.slice(0, 8).map((row) => row.label).join(" | "));
  }
  check("the panel rows carry explanations", rows.filter((row) => !row.section).every((row) => String(row.description ?? "").trim()), "a panel row has no description");
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
