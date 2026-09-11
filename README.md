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
| `catastrophic` — fork bombs, `mkfs`, `dd of=/dev/…`, `format C:`, `diskpart`, `shutdown`/`reboot`, `reg delete HK*`, `cipher /w` | block | block | block |
| `systemTarget` — filesystem roots, `C:\Windows`, `/etc`, `~/.ssh`, `~/.config` | block | block | block |
| `outsideDelete` — deletes whose target is outside the project | block | block | block |
| `outsideMove` — moving data that lives outside the project, or moving it out | block | block | block |
| `insideDelete` — deletes inside the project that are not artifacts | allow | block | block |
| `artifactDelete` — `node_modules`, `dist`, `build`, `.next`, temp dirs | allow | allow | allow |
| `dynamicTargets` — targets that cannot be resolved statically (`$VAR`, `rm -rf *`) | model | model | block |
| `gitDestructive` — `git clean`/`rm`, `reset --hard`, `push --force`/`--delete`, `branch -D`, `stash drop`, bare `restore` / `checkout -- `/`switch -f`, `worktree remove --force`, `reflog expire --expire=now`, `gc --prune=now`, history rewrites | allow | model | block |
| `scriptExec` — a script whose body could not be read (missing, >64 KiB, binary, nested deeper than 2, changed while reading) | allow | model | ask |
| `codeDelete` — deletes issued through eval with a computed target | allow | block | block |

`artifactDelete` is a rule like any other, not an early return: in `custom` you can set it to `ask`,
`model` or `block` and artifact cleanup stops being free. A call that produces several violations is
decided by the **most restrictive** action among them (ties go to the higher-severity rule), so an
allowed target can never release a blocked one.

`gitDestructive` follows what git actually does, not one spelling of it: `--force-with-lease` is
deliberately **allowed** (it refuses to overwrite a ref that moved since the last fetch), `+HEAD:main`
refspecs and combined short flags (`branch -Df`, `git clean -qD`) are not, `git --git-dir=… reset
--hard` is found through global options, and `restore --staged` only unstages (safe) while
`restore --staged -W` puts the worktree back (destructive).

`catastrophic` is the one class with no path to the checker: these signatures have no legitimate use
inside an agent session, so they are denied statically in every mode and are matched on command
positions — `git commit -m "shutdown the api"` is a commit, `shutdown /s` is not.

In `medium`, destructive git commands are escalated to the checker rather than allowed: they are the most common way an agent silently destroys uncommitted work.

A script that *can* be read is not judged by `scriptExec` at all: its body is scanned with the same
rules (`sh ./cleanup.sh` is blocked because of the `rm` inside it, not because it is a script), and the
block reason names the file and the first 12 hex characters of the SHA-256 of the bytes that were read.

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
| `bash` | delete/move verbs, wrappers (`sudo`, `xargs`, `env`, `timeout`), shells (`bash -c`, `cmd //c`, `powershell -Command`, `wsl`), nested wrappers (up to 3 levels, deeper ones escalate), `find -delete`/`-exec`/`-execdir`, package runners (`npx rimraf`, `yarn run rimraf`), compound commands (`&&`, `\|`, `;`, `for … do`), inline `cd` tracking, **script bodies** (`sh ./x.sh`, `bash -x x.sh`, `./x.sh`, `cmd /c x.cmd`) up to 64 KiB and 2 files deep |
| `git` | destructive subcommands: `clean`/`rm`, `reset --hard`, `push --force`/`--delete`, `branch -D` (and `-d --force`), `stash drop`/`clear`, bare `restore` (but not `--staged`, which only unstages), `checkout -f` and the `checkout [ref] -- <path>` form, `switch -f`/`--discard-changes`, `worktree remove --force`, `reflog expire --expire=now`, `gc --prune=now`, `filter-branch`/`filter-repo`. Git arguments are not path-classified: the subcommand decides, so this list is the coverage. |
| `eval` | delete APIs in Python (`shutil.rmtree`, `os.remove`, …) and JS/TS (`fs.rmSync`, `fs.unlinkSync`, `Deno.remove`, …), plus destructive shell strings and catastrophic one-liners inside the code |
| `edit`, `apply_patch` | hashline `REM` / `MV`, `*** Delete File:`, `*** Move to:` — every file section in the payload, each move paired with the section above it — and the structured form (`{path, edits: [{op: "delete"}]}`), which is its own schema and used to be read as JSON text that matched nothing |
| `hub` | `start` / `restart`: `application` + `args` are scanned like a command line; `detached` / `persist` add a `dynamicTargets` violation because the process outlives the session. Disable with `coverage.processes: false`. |

Deleting a project directory through `eval` was a real bypass in earlier versions; it is covered now.
So was the pair this release closes: a delete loop moved into a script file, and the same payload
launched through `hub` — command *strings* were the only thing the scanner ever saw.

## Install

```bash
node install.mjs            # copies the extension to ~/.omp/shared/ and prints the config.yml snippet
node install.mjs --force    # overwrite without asking (a .bak copy is kept)
node install.mjs --unlock   # allowed to replace a copy locked from /dc; the mode is restored after
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
  "coverage": { "bash": true, "eval": true, "fileTools": true, "processes": true },
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
enabled: yes                master switch — off means no checking at all (status line: dc: off)
protection: medium          simple | medium | hard | custom
checker                     model, engine, timeout, reasoning, token cap, self-test
ask on deny / ask on error  toggles
rules                       per-rule action editor (switches to custom mode)
coverage                    bash / eval / fileTools / processes on-off
intent                      forward the agent's one-line intent
cache                       toggle, clear verdicts, clear session approvals
allowed dirs                extra project directories
test checker                one sample check: engine, latency, verdict, real error text
recent decisions            last checks with their outcomes, read from the audit log
audit log                   recent entries, chain verification, log path
guard                       integrity vs the install manifest, read-only lock, restore the .bak
status                      full configuration dump
```

## Audit log

Every decision is appended to `~/.omp/logs/destructive-check.jsonl`, one JSON object per line
(`ts`, `tool`, `rule`, `action`, `detail`, `command`, `cwd`, `mode`, `ms`). The in-memory list behind
`recent decisions` dies with the session; the file is what makes a decision reviewable afterwards.
It rotates to `.1` at 5 MiB and keeps the last two files.

Each line carries `prev` (the previous line's `chain`) and `chain`, the SHA-256 of the line without
`chain`. The previous hash is read from the **tail of the file** on every append — two omp sessions
share the log, and a hash cached in memory would let the second writer chain onto a line that is no
longer last. Command text is masked for credentials (`token=…`, `api_key: …`, `authorization: …`,
`bearer …`) before it is written and the file is created `0600`: the log records the decision, not the
secret.

`node tools/dc-audit.mjs` (or `/dc → audit log → verify the audit chain`) re-walks the file with an
independent implementation: editing, reordering or removing a line in the middle is reported with its
line number. Trimming the tail is not detectable, and anything that can write the file can re-chain it
— the log is a record, not a vault. A checker or config failure never fails a decision because the log
could not be written; `/dc → status` says the log path either way.

## Guard integrity, lock and restore

`install.mjs` writes `~/.omp/shared/destructive-check.manifest.json` (file hash, byte count, version,
timestamp). At load the guard hashes **the copy it was loaded from** — the path is shown in the panel —
against the manifest sitting next to that file:

- `ok` — byte-identical to what the installer wrote.
- `changed` — the file that is running differs from its manifest: `/dc → guard → integrity` shows the
  loaded path, both hashes and the reinstall command.
- `unmanaged` / `missing` — a copy with no manifest beside it (hand-copied, vendored, auto-discovered),
  or the file is gone. A hash taken from a manifest that describes a *different* file is never reported
  as `ok`.

`/dc → guard → lock` sets the read-only attribute on the loaded extension (and optionally on the
config). That is not a security boundary — the same user can clear it — but an accidental in-place edit
fails instead of silently changing the policy, and an edit that clears the attribute is visible as a
changed hash. `install.mjs` will not replace a locked copy unless you pass `--unlock`, and it puts the
mode back afterwards (a locked guard stays locked); `/dc → guard → restore the previous guard (.bak)`
and `install.mjs --restore` do the same for the backup.

## Threat B: an out-of-band boundary (runbook)

Everything above is in-band: same process, same user, same filesystem rights as the agent it judges. A
text layer cannot be a boundary against an agent that can edit the files it is judged by. If you want a
real one, apply it outside the extension:

1. **Lock the policy.** `/dc → guard → lock` makes the guard and its config read-only.
2. **Deny, do not trust.** Deny ACEs beat the allow ACEs your account already holds, and the agent runs
   as that account:
   ```bat
   icacls "%USERPROFILE%\.omp\shared\destructive-check.ts" /deny "%USERDOMAIN%\%USERNAME%:(W,D)"
   icacls "%USERPROFILE%\.omp\destructive-check.json"       /deny "%USERDOMAIN%\%USERNAME%:(W,D)"
   icacls "D:\work" /deny "%USERDOMAIN%\%USERNAME%:(OI)(CI)(D)"
   ```
   `tests/t-isolation.mjs` runs the delete half of this in a scratch directory on this machine and
   asserts the ACE blocks both the file delete and an `rm -rf`, and that `/remove:d` restores access.
3. **Separate the principal.** Run the agent as another local user/AppContainer/job object whose token
   has no delete rights on the directories that matter. The zekâ gap stops mattering: a smarter model
   does not get more access.
4. **Keep the record off-machine.** `node tools/dc-audit.mjs --json` on a schedule, or copy
   `~/.omp/logs/destructive-check.jsonl*` somewhere the agent cannot write.
5. **WSL2/VM.** Heaviest option, and the only one that holds against a fully compromised tool process:
   mount the host's data read-only, or keep the working copy inside the guest.

Measured on omp 18.x: the host emits `tool_call` for the `hub` tool, so the process channel above is
reachable in-band; `tools/` and the guard itself are outside the agent's ordinary reach only through
the ACLs in this list.

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
  to the CLI once if the request fails, inside the same `timeoutMs` budget — a fallback never restarts
  the clock. A failed check is never a denial: with a UI the user is asked, headless it blocks with the
  real error text (HTTP status and body included).
- **Only the assistant's message counts.** A verdict in `reasoning_content` (or any thinking trace) is
  ignored, and an empty or truncated reply fails with the reason named (`finish_reason: length` points
  at `maxOutputTokens` / `reasoning`, not at a denial) — that is one more way an ALLOW can never be
  invented.
- **The checker is asked for one binary answer per call**: `block` / `ask` / `model` / `allow`. When a
  call fires several rules, the most restrictive action wins (ties: higher-severity rule), so a
  "model"-action finding and a "block"-action finding on the same call end in a block.
- The verdict prompt is bounded: action text (`maxCommandChars`), `cwd`, each fired rule with the target
  the classifier resolved for it, and — when `includeIntent` is on — the agent's one-line intent,
  explicitly labelled as agent-written and untrusted (it is context for the checker, never evidence,
  and the system prompt says so).
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
node tests/t-coverage.mjs # script bodies, hub launches, probes, catastrophic class, audit log
node tests/t-review.mjs   # the external review's 19 finding groups (paths, git, eval, hub, audit, …)
node tests/t-isolation.mjs    # deny-ACE mechanics from the README runbook (Windows)
node tests/mutation-check.mjs  # breaks the extension in 25 places and requires the suites to fail
node tests/t-e2e.mjs           # real omp sessions against a real provider (slower, needs auth)
```

`t-static` / `t-llm` / `t-menu` / `t-coverage` / `t-review` use an isolated `HOME` (default `~/.omp-destructive-check-tests`,
override with `DC_TEST_ROOT`), a stubbed extension host and a stubbed `fetch`, so they run offline. The
stubs fail closed: the default `exec` (CLI checker) answers with exit code 1 rather than a friendly
`ALLOW`, so a test cannot accidentally pass on a path it did not exercise. `mutation-check` re-runs them against deliberately broken copies of
the extension: a check that still passes is a check that asserts nothing.
`t-e2e` spawns real sessions; `OMP_BIN`, `DC_E2E_MODEL` (default `opencode-go/deepseek-v4.1-flash`),
`DC_E2E_HOME` and `DC_E2E_AGENT_DIR` override the binary, model and scratch locations. Its hub case
needs a driver model that will issue the call at all; `deepseek-v4.1-flash` often refuses, and a refusal
is reported as a skip, never as a pass.

## Known limitations

- `write` is not guarded: creating or overwriting files is normal editing work. Deletes go through
  `bash`, `eval`, `edit` or `apply_patch`, which are covered.
- Script bodies are read up to 64 KiB and 2 files deep, and only for shells on the command line
  (`sh ./x.sh`, `./x.sh`, `cmd /c x.cmd`). Anything else — a missing file, a binary, a script over the
  limit, a chain nested deeper, a file that changed while it was being read — falls back to
  `scriptExec`, which is `ask` in hard, `model` in medium and `allow` in simple. Interpreting a script
  with something other than a shell (`node x.js`, `python x.py`) is not classified; the `eval` tool is.
- The hash in the block reason proves which bytes were analysed, not which bytes ran: a script can be
  replaced between the check and its execution (the same TOCTOU window every pre-execution hook has).
- Interpreters other than the `eval` tool (`node -e`, `python -c` from bash) are not parsed; their
  payloads are opaque strings. Wrapping the same logic in `eval` is covered.
- The `catastrophic` class matches signatures, not intent: `mkfs` inside a string passed to a program
  the agent runs, or an unusual alias spelling, may be missed; conversely a quoted mention inside a
  command position is judged. It is a static deny list, not a proof.
- Wrapper nesting is followed 3 levels deep (`bash -c '…'`). Commands wrapped deeper than that are
  not silently ignored: they raise a `dynamicTargets` violation, so simple/medium ask the checker and
  hard blocks. Escaped quotes inside nested shell bodies are unwrapped before scanning.
- The guard lock is a read-only attribute, not an ACL: it stops accidental edits and makes deliberate
  ones visible as a changed hash, but the same user can clear it. Real boundaries are in "Threat B".
- The audit chain is tamper-*evident*: an edited or reordered line is reported, a trimmed tail is not,
  and whoever can write the file can recompute the chain.
- Symlinks are not resolved, so a link inside the project can point outside it.
- Path handling targets Windows + Git Bash; POSIX roots are recognized but not exhaustively.
- In an unquoted shell word, a backslash is read as an escape for the *command* position (`r\m` is
  `rm`) while the argument text keeps its literal backslashes, so a Windows path still resolves
  (`C:\Users\x` does not become `C:Usersx`). Quoting the path is still the clearest spelling.
- `git push --force-with-lease` is allowed on purpose (it refuses to overwrite a ref that moved since
  the last fetch); `--force` and `+refspec` pushes are not. The lease is only as good as the last
  fetch: a stale remote-tracking ref makes it as destructive as `--force`.
- `maxOutputTokens` is a real trap door: a provider that truncates the message (`finish_reason:
  length`) produces an error, not a verdict, so every gray-zone call blocks until the cap or
  `reasoning` is fixed in `/dc`.
- An omp profile selected on the command line (`omp --profile x`) is invisible to the extension, so the
  CLI engine would run under the default profile's credentials. The in-process engine resolves the
  provider by name and is unaffected.
- The in-process engine speaks OpenAI-compatible and Anthropic Messages APIs. Providers behind OAuth
  flows (Gemini CLI, Codex, Cursor) always take the CLI path.

## Repository layout

```
destructive-check.ts   the extension (single file, no dependencies)
install.mjs            copy it into ~/.omp/shared, write the manifest, print the config snippet
tools/dc-audit.mjs     independent verifier for the audit log (node:crypto, exit 1 on a broken chain)
tests/                 harness + suites + the mutation gate
AGENTS.md              invariants and conventions for agents working on the repo
```
