// Test harness: isolated HOME, stubbed extension host, real module import.
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const EXT_PATH = process.env.DC_EXT ?? path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "destructive-check.ts");
const HERE = path.dirname(fileURLToPath(import.meta.url));

export const results = [];
export function check(name, cond, detail = "") {
  results.push({ name, ok: Boolean(cond), detail: cond ? "" : detail });
}
export function report(title) {
  const bad = results.filter((r) => !r.ok);
  console.log(`\n### ${title}`);
  for (const r of results) if (!r.ok) console.log(`  FAIL ${r.name}${r.detail ? ` | ${r.detail}` : ""}`);
  console.log(`  ${results.length - bad.length}/${results.length} passed`);
  return bad.length;
}

// Scratch root for every suite. Deliberately outside the OS temp directory: the
// guard treats temp paths as disposable artifacts, and an isolated HOME under
// %TEMP% would quietly change what several cases are testing.
export const mkHome = (name) => path.join(process.env.DC_TEST_ROOT ?? path.join(os.homedir(), ".omp-destructive-check-tests"), name);

let seq = 0;

// ------------------------------------------------------------------ loader --
export async function loadExt({ home, config, registry, exec } = {}) {
  fs.mkdirSync(path.join(home, ".omp"), { recursive: true });
  const configPath = path.join(home, ".omp", "destructive-check.json");
  fs.writeFileSync(configPath, JSON.stringify(config ?? {}, null, 2));
  delete process.env.OMP_DC_DISABLE;
  for (const key of ["OMP_DC_MODE", "OMP_DC_PROVIDER", "OMP_DC_MODEL", "OMP_DC_ENGINE", "OMP_DC_TIMEOUT_MS"]) delete process.env[key];
  process.env.USERPROFILE = home;
  process.env.HOME = home;

  const mod = await import(`${pathToFileURL(EXT_PATH).href}?v=${++seq}`);
  const handlers = new Map();
  const commands = new Map();
  const execCalls = [];
  const pi = {
    on(event, handler) {
      if (!handlers.has(event)) handlers.set(event, []);
      handlers.get(event).push(handler);
    },
    registerCommand(name, def) {
      commands.set(name, def);
    },
    setLabel() {},
    async exec(cmd, args, opts) {
      execCalls.push({ cmd, args, opts });
      if (exec) return exec(cmd, args, opts);
      return { stdout: "ALLOW: default stub", stderr: "", code: 0, killed: false };
    },
    pi: {
    },
    logger: { debug() {}, info() {}, warn() {}, error() {} },
  };
  mod.default(pi);
  return {
    pi,
    handlers,
    commands,
    execCalls,
    configPath,
    toolCall: handlers.get("tool_call")?.[0],
    readConfig: () => JSON.parse(fs.readFileSync(configPath, "utf8")),
  };
}

// -------------------------------------------------------------------- ctx ---
export function fakeRegistry(entries) {
  return {
    getAvailable: () =>
      entries.map(([provider, id, extra = {}]) => ({
        provider,
        id,
        api: extra.api ?? "openai-completions",
        reasoning: extra.reasoning ?? false,
        baseUrl: extra.baseUrl ?? `https://${provider}.example/v1`,
        compat: extra.compat ?? {},
      })),
    getApiKeyAndHeaders: async (model) => ({ ok: true, apiKey: `key-${model.provider}`, headers: {} }),
    getProviderBaseUrl: (provider) => `https://${provider}.example/v1`,
  };
}

export function makeCtx({ cwd, hasUI = true, selects = [], inputs = [], registry = null, branch = [] } = {}) {
  const notes = [];
  const statuses = [];
  const ui = {
    notify: (message, level) => notes.push({ message, level }),
    setStatus: (key, text) => statuses.push({ key, text }),
    select: async (_title, options) => {
      if (!selects.length) return undefined;
      const next = selects.shift();
      return typeof next === "function" ? next(options) : next;
    },
    input: async () => (inputs.length ? inputs.shift() : undefined),
    confirm: async () => true,
  };
  return {
    ui,
    notes,
    statuses,
    hasUI,
    cwd,
    modelRegistry: registry,
    models: { resolve: (spec) => (registry ? registry.getAvailable().find((m) => `${m.provider}/${m.id}` === spec) : undefined) },
    sessionManager: { getBranch: () => branch },
  };
}

export function callTool(ext, event, ctx) {
  if (!ext.toolCall) return Promise.resolve("NO-HANDLER");
  const payload = typeof event === "string" ? { toolName: "bash", input: { command: event } } : { toolName: "bash", ...event };
  return ext.toolCall(payload, ctx);
}

export function bash(command, intent) {
  return { toolName: "bash", input: { command, i: intent ?? "run command" } };
}

// Checker requests captured by the fetch stub installed per test.
// Minimal fetch Response: json() for verdicts, text() for error bodies.
export function fetchResponse(status, payload) {
  const body = typeof payload === "string" ? payload : JSON.stringify(payload);
  return { ok: status >= 200 && status < 300, status, text: async () => body, json: async () => JSON.parse(body) };
}

export function installFetch(handler) {
  const calls = [];
  globalThis.__dcFetchCalls = calls;
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    return handler(String(url), init);
  };
  return calls;
}

export function checkerHeaders() {
  return checkerRequests().at(-1)?.init?.headers ?? {};
}

export function checkerRequests() {
  return globalThis.__dcFetchCalls ?? [];
}

export function lastCheckerRequest() {
  const call = checkerRequests().at(-1);
  if (!call) return { url: "", body: {} };
  let body = {};
  try {
    body = JSON.parse(call.init?.body ?? "{}");
  } catch {
    /* non-JSON body */
  }
  return { url: call.url, body };
}

export function checkerUserPrompt() {
  const { body } = lastCheckerRequest();
  const message = (body.messages ?? []).at(-1);
  return typeof message?.content === "string" ? message.content : "";
}

export function checkerPrompt() {
  const { body } = lastCheckerRequest();
  const messages = body.messages ?? [];
  return messages.map((m) => (typeof m.content === "string" ? m.content : "")).join("\n");
}
