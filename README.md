# destructive-check

A guard for destructive tool calls issued by the [omp](https://github.com/can1357/oh-my-pi) coding agent.
It decides **before** a command runs, in three layers — cheapest first:

| Layer | Cost | What it does |
| --- | --- | --- |
| 1. static deny | 0 ms, no model | filesystem roots, system and credential locations, known catastrophic signatures |
| 2. static allow | 0 ms, no model | build artifacts and temp paths inside the project scope |
| 3. model | one HTTPS request, ~0.2k tokens, 1.7–3.0 s | everything the static layers cannot classify — in-process, no subprocess, cached |

A checker failure or timeout is **never** reported as a model denial: the guard asks the user when a UI is
available, and otherwise blocks with the real error text so the failure is debuggable.

---

## Protection modes

`mode` selects a preset; `custom` starts from `medium` and lets every rule be set individually.

| Rule | simple | medium | hard |
| --- | --- | --- | --- |
| `systemTarget` — filesystem roots, `C:\Windows`, `/etc`, `~/.ssh`, `~/.config` | block | block | block |
| `outsideDelete` — deletes whose target is outside the project | block | block | block |
| `outsideMove` — moving data that lives outside the project, or moving it out | block | block | block |
| `insideDelete` — deletes inside the project that are not artifacts | allow | block | block |
| `artifactDelete` — `node_modules`, `dist`, `build`, `.next`, temp dirs | allow | allow | allow |
| `dynamicTargets` — targets that cannot be resolved statically (`$VAR`, `rm -rf *`) | model | model | block |
| `gitDestructive` — `git clean`/`rm`, `reset --hard`, `push --force`, `branch -D`, `stash drop`, bare `restore` / `checkout -- `/`switch -f`, `worktree remove --force`, `reflog expire --expire=now`, `gc --prune=now`, history rewrites | allow | model | block |
| `scriptExec` — running `.bat` / `.cmd` / `.ps1` files | allow | allow | ask |
| `codeDelete` — deletes issued through eval with a computed target | allow | block | block |

In `medium`, destructive git commands are escalated to the checker rather than allowed: they are the most common way an agent silently destroys uncommitted work.

Project scope = the session `cwd` + the nearest `.git` root + any directory added to `allowDirs`.
Artifacts are only recognized **inside** that scope or under the OS temp directory: `rm -rf D:\other-project\out`
is not treated as a build-artifact cleanup.

Each rule can be set to one of four actions:

- `block` — refuse the call, no model, no prompt.
- `ask` — ask the user in the TUI (headless sessions fail closed).
- `model` — ask the checker model (bounded, cached).
- `allow` — let it through.

## Coverage

| Tool | Covered |
| --- | --- |
| `bash` | delete/move verbs, wrappers (`sudo`, `xargs`, `env`, `timeout`), shells (`bash -c`, `cmd //c`, `powershell -Command`, `wsl`), nested wrappers (up to 3 levels, deeper ones escalate), `find -delete`/`-exec`/`-execdir`, package runners (`npx rimraf`, `yarn run rimraf`), compound commands (`&&`, `\|`, `;`, `for … do`), inline `cd` tracking |
| `git` | destructive subcommands: `clean`/`rm`, `reset --hard`, `push --force`/`--delete`, `branch -D` (and `-d --force`), `stash drop`/`clear`, bare `restore` (but not `--staged`, which only unstages), `checkout -f` and the `checkout [ref] -- <path>` form, `switch -f`/`--discard-changes`, `worktree remove --force`, `reflog expire --expire=now`, `gc --prune=now`, `filter-branch`/`filter-repo`. Git arguments are not path-classified: the subcommand decides, so this list is the coverage. |
| `eval` | delete APIs in Python (`shutil.rmtree`, `os.remove`, …) and JS/TS (`fs.rmSync`, `fs.unlinkSync`, `Deno.remove`, …), plus destructive shell strings inside the code |
| `edit`, `apply_patch` | hashline `REM` / `MV`, `*** Delete File:`, `*** Move to:` |

Deleting a project directory through `eval` was a real bypass in earlier versions; it is covered now.

## Install

```bash
node install.mjs            # copies the extension to ~/.omp/shared/ and prints the config.yml snippet
node install.mjs --force    # overwrite without asking (a .bak copy is kept)
```

Then make sure `~/.omp/agent/config.yml` references it (the installer prints the exact block):

```yaml
extensions:
  - ~/.omp/shared/destructive-check.ts
```

Alternatively drop the file into the auto-discovered extension directory
(`~/.omp/agent/extensions/destructive-check.ts`).

The guard is shared by all omp profiles; per-profile opt-out:

```yaml
disabledExtensions:
  - extension-module:destructive-check
```

## Configuration

`~/.omp/destructive-check.json` (created by the `/dc` menu):

```jsonc
{
  "enabled": true,
  "mode": "medium",                 // simple | medium | hard | custom
  "rules": {},                      // custom mode: { "insideDelete": "ask", ... }
  "coverage": { "bash": true, "eval": true, "fileTools": true },
  "engine": "auto",                 // auto | in-process | cli
  "provider": "opencode-go",
  "providers": { "opencode-go": { "model": "deepseek-v4.1-flash" } },
  "timeoutMs": 20000,
  "maxCommandChars": 240,           // action text sent to the checker
  "maxPromptChars": 700,            // hard cap on the whole checker prompt
  "maxIntentChars": 240,            // how much agent intent is forwarded
  "maxOutputTokens": 0,             // 0 = no cap; a cap truncates reasoning models mid-verdict
  "reasoning": "off",
  "includeIntent": true,
  "cacheEnabled": true,
  "askOnDeny": true,                // model denies -> ask the user instead of blocking blind
  "askOnError": true,               // checker fails  -> ask the user instead of blocking blind
  "allowDirs": [],                  // extra directories that count as project scope
  "logSize": 25                     // entries kept for "/dc > recent decisions"
}
```

Environment overrides (win over the file): `OMP_DC_DISABLE=1`, `OMP_DC_MODE`, `OMP_DC_PROVIDER`,
`OMP_DC_MODEL`, `OMP_DC_ENGINE`, `OMP_DC_TIMEOUT_MS`, `OMP_DC_BIN` (CLI engine binary).

## Status line

The guard keeps one short status next to the model segment — `dc: medium` while it is protecting,
`dc: medium · blocked · Destructive git commands` after a decision — instead of a line under the
editor:

```yaml
statusLine:
  preset: custom
  showHookStatus: false          # no duplicate line beneath the editor
  leftSegments: [pi, vim, model, status, mode, collab, path, git, pr, context_pct, cost]
  rightSegments: [session_name]
  segmentOptions:
    model: { showThinkingLevel: true }
    path: { abbreviate: true, maxLength: 40, stripWorkPrefix: true }
    git: { showBranch: true, showStaged: true, showUnstaged: true, showUntracked: true }
```

The extension writes through `ctx.ui.setStatus("dc", …)`, so the built-in presets show it in the
footer right away; the `custom` preset above is what moves it next to the model. `/dc → status` always
has the full picture.

## `/dc` menu

Every option in every menu (and in the approval prompt) carries a one-line explanation; a choice
without one is treated as a defect by the tests.

```
protection: medium          simple | medium | hard | custom
checker                     model, engine, timeout, reasoning, token cap, self-test
ask on deny / ask on error  toggles
rules                       per-rule action editor (switches to custom mode)
coverage                    bash / eval / fileTools on-off
intent                      forward the agent's one-line intent
cache                       toggle, clear verdicts, clear session approvals
allowed dirs                extra project directories
test checker                one sample check: engine, latency, verdict, real error text
recent decisions            last checks with their outcomes (rule + latency)
status                      full configuration dump
```

## Checker

- **In-process** (default): one HTTPS request straight to the provider, credentials resolved from the
  model registry. No subprocess, no agent session, no tool schemas. OpenAI-compatible
  (`openai-completions`, `openrouter`) and Anthropic Messages providers are spoken natively; anything
  else falls back to the CLI. Measured against OpenCode Go over four real sessions: 1.7–3.0 s,
  ~120 input / ~100 output tokens per gray-zone decision (the CLI path cost 8.6 s).
- Requests identify themselves (`user-agent: omp-destructive-check/x`) and carry a stable
  `x-opencode-session` for OpenCode-style gateways, which reject requests without one
  (`400 MissingSessionID`). A gateway that answers `MissingSessionID` is retried once with a session id,
  so unknown providers self-heal instead of dropping to the slow path.
- **CLI**: one nested `omp -p` run for providers that need the CLI's own auth plumbing (Gemini CLI,
  OAuth-only APIs, `openai-responses`). Correct but slower (process boot per check).
- **`engine: "auto"`** (default) picks in-process when the provider's API is supported, and falls back
  to the CLI once if the request fails. A failed check is never a denial: with a UI the user is asked,
  headless it blocks with the real error text (HTTP status and body included).
- The verdict prompt is bounded: action text (`maxCommandChars`), `cwd`, the static rule that fired,
  and — when `includeIntent` is on — the agent's one-line intent or the last assistant sentence.
- Verdicts are cached per `(cwd, action)` for the session; `askOnDeny` turns a model denial into a
  user prompt (allow once / allow for this session / block) instead of a blind refusal.
- Every model decision records its latency, visible in `/dc > recent decisions` and in the tool result
  (`(checker: 2274 ms)`).
- Output tokens are **uncapped by default**: a tight ceiling truncates reasoning models before they emit
  the verdict line. Spend fewer tokens by keeping the prompt small (the action line plus a one-line
  intent) and by caching verdicts — not by starving the reply.

## Tests

```bash
node tests/t-static.mjs   # policy layers: modes, rules, coverage, path classification
node tests/t-llm.mjs      # checker: HTTP verdicts, fallback, failure policy, cache, prompt
node tests/t-menu.mjs     # /dc menu: modes, rule edits, toggles, persistence
node tests/mutation-check.mjs  # breaks the extension in 9 places and requires the suites to fail
node tests/t-e2e.mjs           # real omp sessions against a real provider (slower, needs auth)
```

`t-static` / `t-llm` / `t-menu` use an isolated `HOME` (default `~/.omp-destructive-check-tests`,
override with `DC_TEST_ROOT`), a stubbed extension host and a stubbed `fetch`, so they run offline. `mutation-check` re-runs them against deliberately broken copies of
the extension: a check that still passes is a check that asserts nothing.
`t-e2e` spawns real sessions; `OMP_BIN`, `DC_E2E_MODEL` (default `opencode-go/deepseek-v4.1-flash`),
`DC_E2E_HOME` and `DC_E2E_AGENT_DIR` override the binary, model and scratch locations.

## Known limitations

- `write` is not guarded: creating or overwriting files is normal editing work. Deletes go through
  `bash`, `eval`, `edit` or `apply_patch`, which are covered.
- Script **contents** are not read — only running a `.bat` / `.cmd` / `.ps1` file is flagged.
- Interpreters other than the `eval` tool (`node -e`, `python -c` from bash) are not parsed; their
  payloads are opaque strings. Wrapping the same logic in `eval` is covered.
- Wrapper nesting is followed 3 levels deep (`bash -c '…'`). Commands wrapped deeper than that are
  not silently ignored: they raise a `dynamicTargets` violation, so simple/medium ask the checker and
  hard blocks. Escaped quotes inside nested shell bodies are unwrapped before scanning.
- Symlinks are not resolved, so a link inside the project can point outside it.
- Path handling targets Windows + Git Bash; POSIX roots are recognized but not exhaustively.
- An omp profile selected on the command line (`omp --profile x`) is invisible to the extension, so the
  CLI engine would run under the default profile's credentials. The in-process engine resolves the
  provider by name and is unaffected.
- The in-process engine speaks OpenAI-compatible and Anthropic Messages APIs. Providers behind OAuth
  flows (Gemini CLI, Codex, Cursor) always take the CLI path.

## Repository layout

```
destructive-check.ts   the extension (single file, no dependencies)
install.mjs            copy it into ~/.omp/shared and print the config snippet
tests/                 harness + suites + the mutation gate
AGENTS.md              invariants and conventions for agents working on the repo
```
