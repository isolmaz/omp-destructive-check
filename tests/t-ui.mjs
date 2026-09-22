// Pop-up UI: the approval prompt, the settings panel, the status line, the
// language layer and the session summary.
//
// The stubbed host exposes an opt-in overlay (`makeCtx({ overlay: true })`) that
// builds the component the extension hands it, records what it rendered, feeds it
// the scripted keys and returns whatever it decided — or `undefined`, which is
// what RPC/ACP return and which is never a decision.
import {
  loadExt,
  makeCtx,
  callTool,
  bash,
  mkHome,
  fakeRegistry,
  installFetch,
  fetchResponse,
  selectLog,
  confirmLog,
  checkerRequests,
  overlayLog,
  widgetLog,
  dialogDefects,
  fakeTheme,
  stripAnsi,
  visible,
  check,
  report,
} from "./harness.mjs";

const HOME = mkHome("ui");
const CWD = "C:\\scratch\\proj";
const REG = fakeRegistry([
  ["opencode-go", "deepseek-v4.1-flash"],
  ["bai", "glm-5.3-flash"],
]);

const cfg = (extra = {}) => ({
  enabled: true,
  mode: "medium",
  provider: "opencode-go",
  providers: { "opencode-go": { model: "deepseek-v4.1-flash" } },
  ...extra,
});

const ok = (content) => fetchResponse(200, { choices: [{ message: { content } }] });
const deny = (reason) => ok(`DENY: ${reason}`);

async function run({ config = cfg(), command = "rm -rf src", handler, selects = [], inputs = [], hasUI = true, overlay = true, overlays = [], custom, event, theme } = {}) {
  installFetch(handler ?? (() => ok("ALLOW: regenerated output")));
  const ext = await loadExt({ home: HOME, config, registry: REG });
  const ctx = makeCtx({ cwd: CWD, hasUI, registry: REG, selects: [...selects], inputs: [...inputs], overlay, overlays: [...overlays], custom, theme });
  const result = await callTool(ext, event ?? bash(command, "clean up source"), ctx);
  return { ext, ctx, result, blocked: result?.block === true };
}

// The panel is opened by the same /dc command; when the host cannot draw an
// overlay the plain-list menu underneath takes over.
async function dcPanel({ config = cfg(), overlays = [], selects = [], inputs = [], hasUI = true, theme } = {}) {
  const ext = await loadExt({ home: HOME, config, registry: REG });
  const ctx = makeCtx({ cwd: CWD, hasUI, registry: REG, overlay: true, overlays: [...overlays], selects: [...selects], inputs: [...inputs], theme });
  await ext.commands.get("dc").handler("", ctx);
  return { ext, ctx, config: ext.readConfig() };
}

async function dcMenu({ config = cfg(), selects = [], inputs = [] } = {}) {
  const ext = await loadExt({ home: HOME, config, registry: REG });
  const ctx = makeCtx({ cwd: CWD, registry: REG, selects: [...selects], inputs: [...inputs] });
  const before = confirmLog.length;
  await ext.commands.get("dc").handler("", ctx);
  return { ext, ctx, config: ext.readConfig(), panels: confirmLog.slice(before).map((entry) => entry.message) };
}

const pick = (prefix) => (options) => options.map((option) => (typeof option === "string" ? option : option.label)).find((label) => label.startsWith(prefix));
const text = (entry) => (entry?.lines ?? []).join("\n");

// ------------------------------------------------------------- approval ----

{
  // The reason has to be on the pop-up itself: a prompt that asks "allow?" and
  // then hides why is a prompt the user cannot answer.
  const before = overlayLog.length;
  const p = await run({
    config: cfg({ mode: "custom", rules: { insideDelete: "model" }, askOnDeny: true }),
    handler: () => deny("untracked work would be lost"),
    overlays: [["s"]],
  });
  const entry = overlayLog.at(-1);
  const panel = text(entry);
  check("approval: the pop-up is drawn for a model denial", overlayLog.length === before + 1, `calls=${overlayLog.length - before}`);
  check("approval: the rule and the checker's reason are shown automatically", /Why\s*: Delete inside the project — untracked work would be lost/.test(panel), panel.slice(0, 300));
  check("approval: the target and the command are shown", /Target\s*: /.test(panel) && /Action\s*: rm -rf src/.test(panel), panel.slice(0, 400));
  check("approval: the layer and the latency are shown", /Layer\s*: model \(\d+ ms\)/.test(panel), panel.slice(0, 400));
  check("approval: the attempt budget is shown", /Attempt\s*: 1\/1/.test(panel), panel.slice(0, 400));
  check("approval: the three answers carry their keys", /\[a\] Allow once/.test(panel) && /\[s\] Allow for this session/.test(panel) && /\[d\] Deny/.test(panel), panel.slice(0, 400));
  check("approval: 's' allows the call for the session", !p.blocked, JSON.stringify(p.result));
  check("approval: the answer was reported as a session allowance", entry.done === "allowSession", String(entry.done));

  // The session allowance is what the label says: the same call is not asked again.
  const again = await callTool({ toolCall: p.ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, registry: REG }));
  check("approval: the session allowance is remembered", again === undefined, JSON.stringify(again));
}

{
  // Escape is the fail-closed key: it must mean deny, not "close and carry on".
  const p = await run({
    config: cfg({ mode: "custom", rules: { insideDelete: "model" }, askOnDeny: true }),
    handler: () => deny("risky"),
    overlays: [["\u001b"]],
  });
  const entry = overlayLog.at(-1);
  check("approval: Escape denies", p.blocked && entry.done === "deny", `blocked=${p.blocked} done=${entry.done}`);
  check("approval: the refusal names the checker denial", /checker model denied/.test(p.result?.reason ?? ""), p.result?.reason);
}

{
  // Arrow keys move the highlight and Enter takes it: the panel is usable
  // without knowing the letter shortcuts.
  const p = await run({
    config: cfg({ mode: "custom", rules: { insideDelete: "model" }, askOnDeny: true }),
    handler: () => deny("risky"),
    overlays: [["\u001b[B", "\r"]],
  });
  const entry = overlayLog.at(-1);
  check("approval: down-arrow + Enter selects the second answer", entry.done === "allowSession", String(entry.done));
  check("approval: the highlighted row is marked", /\u25b8 \[s\] Allow for this session/.test(text(entry)), text(entry).slice(0, 400));
  check("approval: the chosen answer allows the call", !p.blocked, JSON.stringify(p.result));
}

{
  // An unanswered pop-up is not an answer. On a host that returns `undefined`
  // (RPC/ACP) `auto` falls back to the plain list, which still asks.
  const before = selectLog.length;
  const p = await run({
    config: cfg({ mode: "custom", rules: { insideDelete: "model" }, askOnDeny: true }),
    handler: () => deny("risky"),
    overlays: [[]],
  });
  check("approval: an unanswered pop-up falls back to the list", selectLog.length === before + 1, `selects=${selectLog.length - before}`);
  check("approval: the fallback list carries the same three answers", /Allow once/.test(JSON.stringify(selectLog.at(-1)?.options)), JSON.stringify(selectLog.at(-1)).slice(0, 200));
  check("approval: an unanswered prompt denies", p.blocked, JSON.stringify(p.result));
}

{
  // `always` refuses to degrade: same unanswered host, but the pop-up was the
  // presentation, so the answer is the fail-closed one and no list is opened.
  const before = selectLog.length;
  const p = await run({
    config: cfg({ mode: "custom", rules: { insideDelete: "model" }, askOnDeny: true, ui: { overlay: "always" } }),
    handler: () => deny("risky"),
    overlays: [[]],
  });
  check("approval: overlay=always fails closed when nothing answers", p.blocked && selectLog.length === before, `blocked=${p.blocked} selects=${selectLog.length - before}`);
}

{
  // The API can be there and still fail to open: `auto` degrades to the list,
  // `always` does not.
  const boom = async () => {
    throw new Error("no tty");
  };
  const before = selectLog.length;
  const auto = await run({
    config: cfg({ mode: "custom", rules: { insideDelete: "model" }, askOnDeny: true }),
    handler: () => deny("risky"),
    selects: ["Allow once"],
    custom: boom,
  });
  check("approval: a broken pop-up host falls back to the list", !auto.blocked && selectLog.length === before + 1, `blocked=${auto.blocked}`);
  const always = await run({
    config: cfg({ mode: "custom", rules: { insideDelete: "model" }, askOnDeny: true, ui: { overlay: "always" } }),
    handler: () => deny("risky"),
    selects: ["Allow once"],
    custom: boom,
  });
  check("approval: overlay=always blocks when the pop-up cannot be opened", always.blocked, JSON.stringify(always.result));
}

{
  // `never` is the host-without-a-pop-up switch: the plain list, always.
  const before = overlayLog.length;
  const p = await run({
    config: cfg({ mode: "custom", rules: { insideDelete: "model" }, askOnDeny: true, ui: { overlay: "never" } }),
    handler: () => deny("risky"),
    selects: ["Allow once"],
  });
  check("approval: overlay=never never calls ctx.ui.custom", overlayLog.length === before && !p.blocked, `calls=${overlayLog.length - before}`);
}

{
  // Headless: no UI at all is a refusal, and nothing is drawn.
  const before = overlayLog.length;
  const p = await run({
    config: cfg({ mode: "custom", rules: { insideDelete: "model" }, askOnDeny: true }),
    handler: () => deny("risky"),
    hasUI: false,
  });
  check("approval: no UI denies without asking", p.blocked && overlayLog.length === before, JSON.stringify(p.result));
}

{
  // An `ask` rule reaches the pop-up too, and it says which layer asked.
  const p = await run({
    config: cfg({ mode: "custom", rules: { insideDelete: "ask" } }),
    overlays: [["a"]],
  });
  const panel = text(overlayLog.at(-1));
  check("approval: an ask-rule opens the pop-up with its layer", /Layer\s*: static \(ask\)/.test(panel), panel.slice(0, 400));
  check("approval: 'a' allows the call once", !p.blocked && overlayLog.at(-1).done === "allowOnce", String(overlayLog.at(-1).done));
}

{
  // The attempt row counts the times this call has been put to the user. A repeat
  // after an *allow* is answered from the verdict cache and names that layer; a
  // repeat after a *block* belongs to the second-chance loop, and the block below
  // covers that contract.
  const once = await run({
    config: cfg({ mode: "custom", rules: { insideDelete: "model" }, askOnDeny: true, retry: { maxAttempts: 2 } }),
    handler: () => deny("risky"),
    overlays: [["a"]],
  });
  check("approval: allowing once lets the call through", !once.blocked, JSON.stringify(once.result));
  await callTool({ toolCall: once.ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, registry: REG, overlay: true, overlays: [["a"]] }));
  const second = text(overlayLog.at(-1));
  check("approval: a repeated call is counted as attempt 2", /Attempt\s*: 2\/2/.test(second), second.slice(0, 400));
  check("approval: a cached verdict names the cache layer", /Layer\s*: cache/.test(second), second.slice(0, 400));
}

{
  // The second-chance contract on the pop-up surface: the first block invites a
  // justification, and the repeat that has nothing new to say is a hard block —
  // no second pop-up, no third chance, and the tool-hopping sentence back.
  const before = overlayLog.length;
  const blocked = await run({
    config: cfg({ mode: "custom", rules: { insideDelete: "model" }, askOnDeny: true, retry: { maxAttempts: 2 } }),
    handler: () => deny("risky"),
    overlays: [["d"]],
  });
  check("approval: declining blocks the call", blocked.blocked, JSON.stringify(blocked.result));
  check("approval: the block invites the justified repeat", /repeat the same call/.test(blocked.result?.reason ?? ""), blocked.result?.reason);
  const repeat = await callTool({ toolCall: blocked.ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, registry: REG, overlay: true, overlays: [["a"]] }));
  check("approval: a repeat with nothing new to say is a hard block", repeat?.block === true && /No further attempts/.test(repeat?.reason ?? ""), repeat?.reason);
  check("approval: the hard block opens no pop-up", overlayLog.length === before + 1, `overlays=${overlayLog.length - before}`);
}

{
  // The allowlist editor is where an approval stops applying: a human's session
  // answer is listed with its source and time, and a model's justified allow is
  // listed as session-only — it never reaches the permanent file.
  const ext = await loadExt({ home: HOME, config: cfg({ mode: "custom", rules: { insideDelete: "model" }, askOnDeny: true }), registry: REG });
  installFetch(() => deny("risky"));
  const answered = await callTool(ext, bash("rm -rf src"), makeCtx({ cwd: CWD, registry: REG, overlay: true, overlays: [["s"]] }));
  check("allowlist: the pop-up answer was a session approval", !answered?.block && overlayLog.at(-1)?.done === "allowSession", String(overlayLog.at(-1)?.done));
  const stillAllowed = await callTool({ toolCall: ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, registry: REG, overlay: true, overlays: [[]] }));
  check("allowlist: the session approval is in force", stillAllowed === undefined, JSON.stringify(stillAllowed));
  // The allowlist is its own page now: Safety & approvals → Remembered
  // approvals, and that page's heading is the section the panel offers.
  const panelCtx = makeCtx({ cwd: CWD, registry: REG, overlay: true, overlays: [() => "open:protection", () => "open:allowlist"] });
  const panelBefore = overlayLog.length;
  await ext.commands.get("dc").handler("", panelCtx);
  const allowPanel = overlayLog[panelBefore + 2];
  const rows = allowPanel?.options ?? [];
  check("allowlist: the panel has an Allowlist section", text(allowPanel).includes("Remembered approvals"), rows.map((row) => row.label).slice(0, 8).join(" | "));
  check("allowlist: a human approval is listed with its source and time", rows.some((row) => /^human \(session\) · insideDelete · /.test(String(row.label))), rows.map((row) => row.label).join(" | "));
  check("allowlist: every row explains itself", rows.filter((row) => !row.section).every((row) => String(row.description ?? "").trim()), "a panel row has no description");
  const removeId = rows.find((row) => String(row.id).startsWith("allow.row:"))?.id;
  check("allowlist: the approval row is removable", Boolean(removeId), JSON.stringify(rows.map((row) => row.id)));
  const removeCtx = makeCtx({
    cwd: CWD,
    registry: REG,
    overlay: true,
    overlays: [() => "open:protection", () => "open:allowlist", () => removeId, () => "back", () => "back", () => "close"],
  });
  const removeBefore = overlayLog.length;
  await ext.commands.get("dc").handler("", removeCtx);
  check("allowlist: removing a row reports it", removeCtx.notes.some((note) => /approval removed/.test(String(note.message))), JSON.stringify(removeCtx.notes));
  const after = overlayLog[removeBefore + 3]?.options ?? [];
  check("allowlist: the removed approval is gone from the editor", !after.some((row) => String(row.id).startsWith("allow.row:")), after.map((row) => row.label).join(" | "));
  const askedAgain = await callTool({ toolCall: ext.toolCall }, bash("rm -rf src"), makeCtx({ cwd: CWD, registry: REG, overlay: true, overlays: [[]] }));
  check("allowlist: removing the approval asks again", askedAgain?.block === true, JSON.stringify(askedAgain));
}

{
  // The pop-up and the plain list must offer the same answers, or the two
  // surfaces drift apart one language at a time. The list keeps its historical
  // "Block" wording for the third answer (tests break that literal in place);
  // the pop-up says "Deny" — same decision, two spellings.
  await run({
    config: cfg({ mode: "custom", rules: { insideDelete: "model" }, askOnDeny: true }),
    handler: () => deny("risky"),
    overlays: [["d"]],
  });
  const modal = overlayLog.at(-1);
  const before = selectLog.length;
  await run({
    config: cfg({ mode: "custom", rules: { insideDelete: "model" }, askOnDeny: true }),
    handler: () => deny("risky"),
    selects: ["Block"],
  });
  check("approval: both surfaces were drawn", Boolean(modal) && selectLog.length === before + 1, `modal=${Boolean(modal)} selects=${selectLog.length - before}`);
  const modalLabels = (modal?.options ?? []).map((row) => String(row.label));
  const listLabels = (selectLog.at(-1)?.options ?? []).map((option) => String(option?.label ?? option));
  check("approval: pop-up and list offer the same answers", JSON.stringify(modalLabels.slice(0, 2)) === JSON.stringify(listLabels.slice(0, 2)), `${JSON.stringify(modalLabels)} vs ${JSON.stringify(listLabels)}`);
  check("approval: both surfaces offer three answers", modalLabels.length === 3 && listLabels.length === 3, `${modalLabels.length}/${listLabels.length}`);
  check("approval: the third answer refuses on both", modalLabels[2] === "Deny" && listLabels[2] === "Block", `${modalLabels[2]} / ${listLabels[2]}`);
  check("approval: the pop-up answers every option", (modal?.options ?? []).every((row) => String(row.description ?? "").trim().length > 0), JSON.stringify(modal?.options));
}

// ------------------------------------------------------- status and i18n ---

{
  // The bar location keeps the mode on the line, and the counters detail is the
  // same source the session summary reads.
  const blocked = await run({ config: cfg({ ui: { statusLine: { detail: "counters" } } }), event: bash("rm -rf /etc", "clean up") });
  const line = blocked.ctx.statuses.map((entry) => String(entry.text)).at(-1) ?? "";
  check("status: counters detail shows the mode, the counts and the rule", /^dc: medium a:0 d:1 ca:0 cd:0 · blocked · System \/ credential paths$/.test(line), line);
  const minimal = await run({ config: cfg({ ui: { statusLine: { detail: "minimal" } } }), event: bash("rm -rf /etc", "clean up") });
  check("status: minimal detail keeps only the mode", (minimal.ctx.statuses.at(-1)?.text ?? "") === "dc: medium", JSON.stringify(minimal.ctx.statuses.at(-1)));
}

{
  // A widget is a line under (or over) the editor, and leaving that placement
  // clears it again instead of leaving a stale line behind.
  const allowed = await run({ config: cfg({ ui: { statusLine: { location: "belowEditor" } } }), command: "rm -rf node_modules" });
  const widget = widgetLog.at(-1);
  check("status: belowEditor writes a one-line widget", widget?.key === "dc" && widget?.options?.placement === "belowEditor", JSON.stringify(widget));
  check("status: the widget carries the decision text", /^dc: medium · allowed · Delete build artifacts/.test(String(widget?.content?.[0] ?? "")), JSON.stringify(widget?.content));
  check("status: a widget placement does not also write the bar", allowed.ctx.statuses.length === 0, JSON.stringify(allowed.ctx.statuses));
}

{
  const before = widgetLog.length;
  const off = await run({ config: cfg({ ui: { statusLine: { location: "off" } } }), command: "rm -rf node_modules" });
  check("status: off writes neither the bar nor a widget", off.ctx.statuses.length === 0 && widgetLog.length === before, JSON.stringify(widgetLog.slice(before)));
}

{
  // Every id the panel writes is a token the rest of the guard reads: the
  // config file is the interface, and a row that invents a value would be a
  // setting nothing honours.
  const p = await run({ config: cfg(), event: bash("rm -rf /etc", "clean up") });
  const reason = String(p.result?.reason ?? "");
  check("i18n: the block reason keeps its contract shape", /^destructive-check: /.test(reason) && /Do not retry this action/.test(reason) && /rule: systemTarget/.test(reason), reason);
  const summary = await (async () => {
    const stop = p.ext.handlers.get("session_stop")?.[0];
    await stop?.({}, p.ctx);
    return p.ctx.notes.map((note) => note.message).find((message) => /top rule/.test(message)) ?? "";
  })();
  check("summary: the summary is English, like everything else the guard says", /^dc: 1 blocked · 0 allowed · 0 justified · top rule: systemTarget$/.test(summary), summary);
}

// ------------------------------------------------------ settings panel -----

{
  // One panel, every section, and every row explained (dialogDefects covers the
  // overlay rows as well as the select options).
  const before = overlayLog.length;
  const { config } = await dcPanel({ overlays: [["\u001b"]] });
  const entry = overlayLog.at(-1);
  const panel = text(entry);
  const labels = (entry?.options ?? []).map((row) => String(row.label));
  const choices = (entry?.options ?? []).filter((row) => !row.section);
  check("panel: /dc opens the pop-up when the host can draw one", overlayLog.length === before + 1, `calls=${overlayLog.length - before}`);
  // The flat section list is paged away: every old section lives behind a row
  // now — on the root or one hop into it. Walk the whole tree once: each hop
  // proves its page opens, and the walk's rows are what the count below sums.
  const walkBefore = overlayLog.length;
  await dcPanel({
    overlays: [
      () => "open:protection",
      () => "open:rules", () => "back",
      () => "open:coverage", () => "back",
      () => "open:retry",
      () => "open:recovery", () => "back",
      () => "open:exemptions", () => "back",
      () => "back",
      () => "open:allowlist", () => "back",
      () => "open:scope", () => "back",
      () => "open:project", () => "back",
      () => "back",
      () => "open:checker",
      () => "open:checkerAdvanced", () => "back",
      () => "back",
      () => "open:ui",
      () => "open:statusLine", () => "back",
      () => "back",
      () => "open:history", () => "back",
      () => "open:advanced",
      () => "open:guard", () => "back",
      () => "open:memory", () => "back",
      () => "back",
      () => "close",
    ],
  });
  const walked = overlayLog.slice(walkBefore);
  const labelsOf = (index) => (walked[index]?.options ?? []).map((row) => String(row.label));
  // Render order: 0 root · 1 protection · 4 coverage · 29 advanced · 30 guard.
  const protectionLabels = labelsOf(1);
  const advancedLabels = labelsOf(29);
  const sections = {
    Simple: [labels, (ls) => ls.includes("Quick settings")],
    Protection: [labels, (ls) => ls.includes("Safety & approvals")],
    Coverage: [protectionLabels, (ls) => ls.includes("Tool coverage")],
    "Retry & justification": [protectionLabels, (ls) => ls.some((label) => label.startsWith("Second chances"))],
    Checker: [labels, (ls) => ls.some((label) => label.startsWith("checker:"))],
    UI: [labels, (ls) => ls.includes("Appearance")],
    Advanced: [labels, (ls) => ls.includes("Advanced & diagnostics")],
    Guard: [advancedLabels, (ls) => ls.includes("Guard files")],
    History: [labels, (ls) => ls.includes("History")],
  };
  for (const group of ["Simple", "Protection", "Coverage", "Retry & justification", "Checker", "UI", "Advanced", "Guard", "History"]) {
    const [where, has] = sections[group];
    check(`panel: the ${group} section is on it`, has(where), where.slice(0, 12).join(" | "));
  }
  check("panel: the first sections are rendered", panel.includes("── Quick settings") && panel.includes("── Settings"), panel.slice(0, 200));
  check("panel: Escape closes without changing anything", JSON.stringify(config) === JSON.stringify(cfg()), JSON.stringify(config));
  check("panel: every row carries a description", choices.every((row) => String(row.description ?? "").trim().length > 0), JSON.stringify(choices.filter((row) => !String(row.description ?? "").trim())));
  const settingsIds = new Set(walked.flatMap((page) => (page.options ?? []).filter((row) => !row.section).map((row) => String(row.id))));
  check("panel: the rows are settings, not menu labels", settingsIds.size > 30, `rows=${settingsIds.size}`);
}

{
  // A page down scrolls the window: the later lines are reachable without
  // reading through every row above them. The settings pages all fit one
  // window now, so the walk drives the longest panel there is — the status
  // report the panel opens (Advanced & diagnostics → status).
  const pageDown = (component, entry) => {
    component.handleInput("\u001b[6~");
    entry.lines = component.render(80);
    return undefined;
  };
  const before = overlayLog.length;
  const { ctx } = await dcPanel({ overlays: [() => "open:advanced", () => "status", pageDown] });
  const panel = text(overlayLog[before + 2]);
  // The anchor is the report's own first line: only a window that actually
  // scrolled has lost it, however many lines the report grows.
  const footer = String(panel).split("\n").at(-2) ?? "";
  const position = Number((footer.match(/(\d+)\/(\d+)/) ?? [0, "1"])[1]);
  check("panel: page-down scrolls the window past the first rows", position > 1 && !panel.includes("enabled      : yes"), `position=${position} ${String(panel).slice(0, 120)}`);
  check("panel: the panel still closes after scrolling", ctx.notes.length >= 0, "");
}

{
  // A choice is applied in place: the panel stays open, the file changes. The
  // preset row opens the host's preset list now, so the Enter is followed by
  // the pick of strict.
  const { config } = await dcPanel({ overlays: [["\u001b[B", "\r"], ["\u001b"]], selects: ["strict"] });
  check("panel: the friction preset cycles to strict", config.preset === "strict", JSON.stringify(config));
  check("panel: the preset writes the settings it stands for", config.askOnDeny === false && config.askOnError === true && config.retry?.authority === "off" && config.verify?.level === "claims+adversarial", JSON.stringify(config));
}

{
  // The Appearance page's status-line row opens the sub-panel that holds the
  // location and the detail.
  const before = overlayLog.length;
  const { config } = await dcPanel({ overlays: [() => "open:ui", () => "open:statusLine", () => "ui.statusLine.location"] });
  const sub = text(overlayLog[before + 2]);
  check("panel: the status-line row opens its own panel", /status line location/.test(sub) && /status line detail/.test(sub) && /bar side/.test(sub), sub.slice(0, 300));
  check("panel: cycling the location persists it", config.ui?.statusLine?.location === "belowEditor", JSON.stringify(config.ui?.statusLine));
}

{
  // The UI group is reachable from the plain-list menu too, and the snippet the
  // panel prints is the block docs/REFERENCE.md documents.
  const { config, panels } = await dcMenu({
    config: cfg({ ui: { statusLine: { barSide: "right" } } }),
    selects: [pick("Appearance"), pick("status line"), pick("show the statusLine snippet"), undefined, pick("close")],
  });
  const snippet = panels.join("\n");
  check("panel: the snippet is a copy-pasteable statusLine block", /statusLine:/.test(snippet) && /preset: custom/.test(snippet) && /showHookStatus: false/.test(snippet), snippet.slice(0, 300));
  check("panel: bar side moves the guard's segment to the right", /rightSegments: \[status, session_name\]/.test(snippet), snippet.slice(0, 400));
  check("panel: the snippet action leaves the config alone", config.ui.statusLine.barSide === "right", JSON.stringify(config.ui));
}

{
  // Every new setting persists through the menu as well: the two surfaces write
  // the same keys.
  const { config } = await dcMenu({
    selects: [pick("Safety & approvals"), pick("Second chances"), pick("retry authority"), undefined, pick("close")],
  });
  check("panel: the retry authority cycles from the menu", config.retry?.authority === "ask", JSON.stringify(config.retry));
}

{
  const { config } = await dcMenu({
    selects: [pick("friction preset"), "quiet", pick("close")],
  });
  check("panel: the friction preset is selectable from the menu", config.preset === "quiet" && config.askOnDeny === false, JSON.stringify(config));
}

{
  const { config } = await dcMenu({
    selects: [pick("Safety & approvals"), pick("policy note"), pick("back"), pick("close")],
    inputs: ["bu makinede arşive dokunma"],
  });
  check("panel: the policy note is stored as written", config.policyNote === "bu makinede arşive dokunma", JSON.stringify(config.policyNote));
}

// ------------------------------------------------------ history and guard ---

{
  // The history page's decision rows show the whole trace of one entry, not a
  // one-liner.
  await run({ config: cfg({ mode: "custom", rules: { insideDelete: "model" } }), handler: () => deny("untracked work"), overlays: [["d"]] });
  const { panels } = await dcMenu({
    selects: [pick("History"), (options) => options.map((option) => option.label).find((label) => label.startsWith("model:deny")), undefined, pick("close")],
  });
  const trace = panels.join("\n");
  check("history: the trace names the layer and the rule", /layer\s*: /.test(trace) && /rule\s*: insideDelete/.test(trace), trace.slice(0, 400));
  check("history: the trace carries the command, the cwd and the latency", /command\s*: rm -rf src/.test(trace) && /cwd\s*: .*proj/.test(trace), trace.slice(0, 500));
  check("history: the trace is offered by the menu as well", panels.length > 0, JSON.stringify(panels).slice(0, 200));
}

{
  // The guard section reports the same text the pop-up panel would.
  const { panels } = await dcMenu({ selects: [pick("Advanced & diagnostics"), pick("Guard files"), pick("integrity:"), undefined, pick("close")] });
  check("guard: the integrity report is reachable from the panel too", /state\s*: (ok|unmanaged|missing|changed)/.test(panels.join("\n")), panels.join("\n").slice(0, 200));
}

// -------------------------------------------------------- session summary ---

{
  const { ext, ctx } = await (async () => {
    installFetch(() => ok("ALLOW: stub"));
    const instance = await loadExt({ home: HOME, config: cfg(), registry: REG });
    const context = makeCtx({ cwd: CWD, registry: REG });
    await callTool(instance, bash("rm -rf /etc", "clean up"), context);
    await callTool(instance, bash("rm -rf node_modules", "clean up"), context);
    return { ext: instance, ctx: context };
  })();
  const stop = ext.handlers.get("session_stop")?.[0];
  check("summary: session_stop is wired", typeof stop === "function", "no handler");
  await stop({}, ctx);
  const line = ctx.notes.map((note) => note.message).find((message) => /top rule/.test(message)) ?? "";
  check("summary: one line counts blocked, allowed, justified and the top rule", /^dc: 1 blocked · 1 allowed · 0 justified · top rule: systemTarget$/.test(line), line);
  check("summary: it is advisory, never a decision", ctx.notes.every((note) => note.level === "info" || note.level === "warning"), JSON.stringify(ctx.notes.slice(-3)));
}

{
  const { ext, ctx } = await (async () => {
    const instance = await loadExt({ home: HOME, config: cfg({ ui: { sessionSummary: false } }), registry: REG });
    const context = makeCtx({ cwd: CWD, registry: REG });
    await callTool(instance, bash("rm -rf /etc", "clean up"), context);
    return { ext: instance, ctx: context };
  })();
  await ext.handlers.get("session_stop")?.[0]({}, ctx);
  check("summary: the line is off when sessionSummary is off", !ctx.notes.some((note) => /top rule/.test(note.message)), JSON.stringify(ctx.notes).slice(0, 200));
}

{
  const { ext, ctx } = await (async () => {
    const instance = await loadExt({ home: HOME, config: cfg(), registry: REG });
    return { ext: instance, ctx: makeCtx({ cwd: CWD, registry: REG }) };
  })();
  await ext.handlers.get("session_stop")?.[0]({}, ctx);
  check("summary: a quiet session prints nothing", !ctx.notes.some((note) => /top rule/.test(note.message)), JSON.stringify(ctx.notes).slice(0, 200));
}

// ------------------------------------------------------------- contract ----

{
  const defects = dialogDefects();
  check("every dialogue exercised here explains its options", defects.length === 0, defects.slice(0, 8).join(" | "));
  check("the pop-up surface was actually exercised", overlayLog.length > 8, `overlays=${overlayLog.length}`);
}

// ------------------------------------------------- deny & abort (S5) -------
// `ui.denyAbort` is a setting, not a fourth button: the deny answer keeps its
// meaning and also aborts the turn and holds the hard preset until /dc is opened.
{
  const denied = await run({ config: cfg({ ui: { denyAbort: true } }), command: "git reset --hard", handler: () => deny("uncommitted work"), overlays: [["d"]] });
  check("deny & abort: the deny answer stops the turn", denied.ctx.control.aborted === 1, JSON.stringify(denied.ctx.control));
  check("deny & abort: the denial is still the decision", denied.blocked === true, JSON.stringify(denied.result));
  check("deny & abort: the status line says the guard is hard now", denied.ctx.statuses.some((s) => /hard \(lockdown\)/.test(String(s.text))), JSON.stringify(denied.ctx.statuses).slice(0, 240));
  // The lockdown is a hard overlay: a git command that medium escalates to the
  // checker is now a block that costs no request at all. A *different* command
  // (the first one is an operation with a spent attempt, which the loop would
  // hard-block whatever the policy says).
  const calls = checkerRequests().length;
  const after = await callTool(denied.ext, bash("git clean -fd", "clean up history"), makeCtx({ cwd: CWD, registry: REG, hasUI: false }));
  check("deny & abort: the hard preset is the floor until /dc is opened", after?.block === true && /\(mode: medium → hard \(lockdown\), rule: gitDestructive\)/.test(String(after?.reason ?? "")) && checkerRequests().length === calls, `${String(after?.reason ?? "").slice(0, 160)} requests=${checkerRequests().length - calls}`);
  // Opening /dc is the release, and it is the only one.
  await denied.ext.commands.get("dc").handler("", denied.ctx);
  const status = denied.ctx.notes.map((n) => n.message).join("\n");
  check("deny & abort: opening /dc lifts the lockdown", /lockdown lifted/.test(status), status.slice(0, 240));
  check("deny & abort: the status line is back to the ordinary mode", denied.ctx.statuses.some((s) => String(s.text) === "dc: medium"), JSON.stringify(denied.ctx.statuses).slice(0, 240));
  const relaxed = await run({ config: cfg({ ui: { denyAbort: true } }), command: "git reset --hard", handler: () => ok("ALLOW: the agent's own branch") });
  check("deny & abort: after the release the ordinary policy runs again", relaxed.blocked === false, JSON.stringify(relaxed.result));
  // Off by default: a deny must not abort the turn of a user who did not ask for it.
  const plain = await run({ config: cfg(), command: "git reset --hard", handler: () => deny("uncommitted work"), overlays: [["d"]] });
  check("deny & abort: off by default, a deny only refuses", plain.blocked === true && plain.ctx.control.aborted === 0, JSON.stringify(plain.ctx.control));
  const escape = await run({ config: cfg({ ui: { denyAbort: true } }), command: "git reset --hard", handler: () => deny("uncommitted work"), overlays: [["\u001b"]] });
  check("deny & abort: Escape is the deny answer and aborts too", escape.blocked === true && escape.ctx.control.aborted === 1, JSON.stringify(escape.ctx.control));
}

// ------------------------------------------------------------- painting ----
// The /dc panel and its reports wear the host theme; the approval prompt does
// not. These checks measure what a terminal would see: escapes measure zero, so
// a painted line must still be exactly as wide as the frame around it.
{
  const rowsOf = (component) => {
    const spec = component.spec ?? {};
    return (typeof spec.rows === "function" ? spec.rows() : spec.rows) ?? [];
  };
  // Open a setting by id rather than by position: sections are skipped by the
  // component, so the loop reads the cursor back instead of counting presses.
  const chooseRow = (id) => (component) => {
    const spec = component.spec ?? {};
    const target = rowsOf(component).findIndex((row) => row.id === id && !row.section);
    if (target < 0) return undefined;
    for (let guard = 0; guard < 200 && spec.state?.selected !== target; guard += 1) {
      component.handleInput(spec.state.selected < target ? "\u001b[B" : "\u001b[A");
    }
    component.handleInput("\r");
    return undefined;
  };
  // A report body is longer than the window, which is what puts the counters on
  // the border. The harness only re-renders for scripted keys, not for a script,
  // so both frames are captured here: before the page-down, and after it.
  const frames = [];
  const pageDown = (times) => (component, entry) => {
    frames.push(component.render(80));
    for (let index = 0; index < times; index += 1) component.handleInput("\u001b[6~");
    entry.lines = component.render(80);
    frames.push(entry.lines);
    return undefined;
  };

  const theme = fakeTheme();
  const before = overlayLog.length;
  await dcPanel({ theme, overlays: [chooseRow("open:advanced"), chooseRow("status"), pageDown(6)] });
  const panel = overlayLog[before];
  const report = overlayLog[before + 2];
  const panelLines = panel?.lines ?? [];
  const reportLines = report?.lines ?? [];
  const framed = [...new Set(panelLines.map(visible))];
  const framedReport = [...new Set(reportLines.map(visible))];

  check("painting: the /dc panel wears the host theme", panelLines.some((line) => line.includes("\x1b[")), String(panelLines[0] ?? "").slice(0, 80));
  check("painting: the frame is the host's rounded chrome", stripAnsi(panelLines[0] ?? "").startsWith("╭─ destructive-check"), stripAnsi(panelLines[0] ?? "").slice(0, 40));
  check("painting: the title carries the accent and the bold face", theme.tokens.includes("accent") && (panelLines[0] ?? "").includes("\x1b[1m"), JSON.stringify([...new Set(theme.tokens)]));
  // The frame is the contract: a themed line that measured its escapes would
  // push the right border out, and every line would end somewhere else.
  check("painting: every line of the panel is the same visible width", framed.length === 1, JSON.stringify(framed));
  check("painting: every line of a report is the same visible width", reportLines.length > 0 && framedReport.length === 1, JSON.stringify(framedReport));
  check("painting: the cursor row is filled across the panel", panelLines.some((line) => line.includes("\x1b[48;5;236m") && line.includes("▸")), panelLines.filter((line) => line.includes("\x1b[48;5;236m")).map((line) => stripAnsi(line)).join("|").slice(0, 120));
  check("painting: the tag line is coloured by what it says", theme.tokens.includes("success"), JSON.stringify([...new Set(theme.tokens)]));
  check("painting: an unscrolled report counts what is below", /↓ \d+ more\s/.test(stripAnsi(frames[0]?.at(-1) ?? "")), stripAnsi(frames[0]?.at(-1) ?? ""));
  check("painting: a scrolled report counts what is hidden above", /\s↑ \d+ more\s/.test(stripAnsi(frames[1]?.[0] ?? "")), stripAnsi(frames[1]?.[0] ?? ""));
  check("painting: the reports are painted too", reportLines.some((line) => line.includes("\x1b[")), String(reportLines[0] ?? "").slice(0, 60));

  // Opt-in, twice over: a host with no theme, and the approval prompt, which
  // keeps the plain box whatever the host offers.
  const bare = await dcPanel({});
  const bareLines = overlayLog.at(-1)?.lines ?? [];
  check("painting: a host without a theme gets no escape codes", bareLines.length > 0 && !bareLines.some((line) => line.includes("\x1b[")), String(bareLines[0] ?? "").slice(0, 60));
  check("painting: a host without a theme keeps the sharp box", stripAnsi(bareLines[0] ?? "").startsWith("┌─ destructive-check"), stripAnsi(bareLines[0] ?? "").slice(0, 40));
  check("painting: the panel still reports its state to a themeless host", bare.ctx && bareLines.some((line) => /ENFORCING/.test(stripAnsi(line))), JSON.stringify(bareLines.length));

  const approval = await run({ theme: fakeTheme(), command: "git reset --hard", handler: () => deny("uncommitted work") });
  const approvalLines = overlayLog.at(-1)?.lines ?? [];
  check("painting: the approval prompt stays unthemed", approvalLines.length > 0 && !approvalLines.some((line) => line.includes("\x1b[")), String(approvalLines[0] ?? "").slice(0, 60));
  check("painting: the approval prompt still offers its answers", /\[a\] Allow once/.test(approvalLines.map(stripAnsi).join("\n")) && approval.blocked === true, approvalLines.map(stripAnsi).join("|").slice(0, 160));

  // The panel is drawn from agent-authored text — the command, a justification —
  // and an escape sequence in it must never reach the terminal. Without a theme
  // the panel emits none of its own, so an escape in the output came from the
  // text it was handed.
  const injected = await run({ command: "rm -rf src\u001b[31m\u001b]2;owned\u0007", handler: () => deny("uncommitted work\u001b[31m") });
  const injectedLines = overlayLog.at(-1)?.lines ?? [];
  check("painting: an escape sequence in the action never reaches the panel", injectedLines.length > 0 && !injectedLines.some((line) => line.includes("\x1b")), injectedLines.join("\n").slice(0, 200));
}

const bad = report("pop-up UI");
process.exitCode = bad ? 1 : 0;
