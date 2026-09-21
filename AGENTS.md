# AGENTS.md

`destructive-check` is a guard for [omp](https://github.com/can1357/oh-my-pi): it intercepts
destructive tool calls (`bash`, `eval`, `edit`, `apply_patch`) before they run and decides with
three layers, cheapest first — static deny, static allow, then one bounded model request.

## Layout

```
destructive-check.ts   the whole extension (single file, zero dependencies)
install.mjs            copies the extension into ~/.omp/shared/, writes the manifest, --restore
tools/dc-audit.mjs     independent audit-log verifier (node:crypto, exit 1 on a broken chain)
tests/                 stubbed-host suites + real-session e2e + a mutation gate
README.md              user-facing documentation (keep it in sync with behavior)
```

Everything the guard needs ships in `destructive-check.ts`: no build step, no imports outside
`node:fs` / `node:path` / `node:os` / `node:crypto` / `node:url`. Keep it that way — the file is copied
verbatim into `~/.omp/shared/` and loaded by every omp profile. The audit chain uses `node:crypto`'s
SHA-256, and `tools/dc-audit.mjs` re-implements the walk with its own digest so the two agree.

## Invariants (change these only with evidence)

1. **Never report a checker failure as a model denial.** A failed or empty check asks the user when
   a UI exists and otherwise blocks *with the real error text* (HTTP status and body included).
2. **Fail closed on ambiguity.** Missing UI, unparsable verdict, unknown header, unmatched answer —
   all resolve to "do not run". The single deliberate exception is an internal error in the tool_call
   handler itself (fail-open so a bug cannot brick every tool call), and that path must always write
   a `rule: "internal"` entry to the decision log.
3. **Verdicts are fail-closed and come from the assistant message only.** Any `DENY` in the reply
   wins, anchored or not. A stray `ALLOW` mentioned in prose must never open the gate. A
   `reasoning_content` / thinking trace is never evidence: an empty message, a truncated one
   (`finish_reason: length`, reported with that name) or a reply without a line is an error, not an
   ALLOW. The whole decision — including the CLI fallback — runs inside one `timeoutMs` budget.
4. **`mode` picks the action for a rule; classification is mode-independent.** Do not encode
   per-mode parsing paths. `medium` escalates destructive git commands to the checker: they destroy
   uncommitted work, which is exactly what this guard exists for.
   `resolveAction` merges **every** effect a call produced and takes the most restrictive action, with
   ties broken by rule order: an allowed target must never release a blocked one. `artifactDelete` is
   a real rule on that path (a delete whose targets are all artifacts), not an early return, so
   `custom` can block artifact cleanup.
5. **`git` subcommands return from the scanner unconditionally.** Once a `git` command word is seen,
  the rest goes to `isDestructiveGit` and the scan stops — no path rule applies to git arguments or
  targets. That decision list *is* the coverage: a missing subcommand is invisible, not merely
  misclassified, and a lost flag test (`branch -d` vs `-D`, `restore --staged` vs bare `restore`,
  `switch -f`) is a silent hole. Add a case here and a row in the git tests together.
6. **The scanner never fails open by accident.** Bailing out — wrapper nesting past `MAX_SCAN_DEPTH`,
   unresolvable targets, escaped shell bodies — records a violation for `dynamicTargets` instead of
   returning clean. Script bodies are the same rule: a body that cannot be read (missing, over 64 KiB,
   binary, nested past `MAX_SCRIPT_DEPTH`, changed while being read) records `scriptExec`, and a body
   that *can* be read is judged by its own rules — never by the fact that it is a script.
7. **Signatures with no legitimate use are denied statically, in every mode.** The `catastrophic`
   class (fork bombs, `mkfs`, `dd of=/dev/…`, `format C:`, `diskpart`, `shutdown`/`reboot`,
   `reg delete HK*`, `cipher /w`) is matched on command positions, so a quoted mention inside a commit
   message is not a hit; it never reaches the model layer. New signatures go in with a test for the
   command and one for the nearest quoted decoy.
8. **A decision is never lost to I/O, and the record survives two writers.** The audit append, the
   rotation and the config write all fail soft: the guard keeps deciding, and `/dc → status` shows what
   failed. The chain (`prev` + `chain` per line, SHA-256) is what makes an edit visible; do not trade it
   for a "simpler" counter, and keep `tools/dc-audit.mjs` an independent walk. The previous hash is read
   from the **tail of the file** for every append, never cached in memory: two omp sessions share one
   log, and a cached hash would let the second writer chain onto a line that is no longer last. Command
   text is masked for credentials (`token=`, `api_key:`, `bearer …`) and the file is created `0600` —
   the log records the decision, not the secret.
9. **Integrity is about the file that is running.** `guardIntegrity()` hashes the loaded copy
   (`import.meta.url`) against the manifest next to *it*; the shared install directory is a layout, not
   an assumption. A copy with no manifest beside it is `unmanaged` — never `ok` by comparing against a
   manifest that describes some other file. The lock and the restore act on the same loaded path.
10. **The installer never silently unlocks.** A guard locked from `/dc` is read-only on purpose:
   `install.mjs` refuses to replace it without `--unlock`, and restores the previous mode after the
   copy (locked stays locked). `--restore` preserves it too.
11. **Probes are not destructive calls.** `command -v|which|type|hash <name>` runs nothing and must pass
   without a model call; only the query flags count, so `command -p rm -rf x` stays on the launcher
   path. The false positive this removes is what taught a real agent to move its payload into a script.
12. **Every option in a dialogue explains itself.** The `/dc` menus and the approval prompt are the
   only configuration surface users touch; `tests/t-menu.mjs` and `tests/t-llm.mjs` both call
   `dialogDefects()` from the harness and fail on any label without a description.
13. **The status line carries the mode, nothing else.** `ctx.ui.setStatus(dc, …)` renders next to the
   model segment (`statusLine.preset: custom`, `showHookStatus: false`); the resting text is
   `dc: <mode>` and decisions append `· blocked · <rule label>`. Integrity, lock state and the audit
   path belong in `/dc → status`, not on that line.
14. **Block reasons stay structured**: `destructive-check: <what> (mode: …, rule: …) — <detail>` plus
   the "do not retry this through another tool" sentence. Tests and users match on that shape.

## Checker wiring (the parts that actually bite)

- Requests go out as plain `fetch` — no pi-ai RPC, no subprocess, no agent session. OpenAI-compatible
  (`openai-completions`, `openrouter`) and Anthropic Messages are spoken natively; anything else
  (Gemini CLI OAuth, Codex, Cursor) routes to the CLI engine via `engine: "auto"`.
- **OpenCode-style gateways require `x-opencode-session`.** Without it they answer
  `400 MissingSessionID` and every check silently pays for a CLI run (measured 8.6 s vs 1.7-3.0 s).
  The client also sends `user-agent`. An unknown gateway gets exactly one retry with a session id.
- **Never cap output tokens by default.** A tight cap truncates reasoning models before they emit the
  verdict line; `maxOutputTokens: 0` (default) omits the field. Anthropic still needs `max_tokens`,
  so it gets a generous ceiling. When a provider does truncate (`finish_reason: length`), the checker
  reports that: an empty message is an error, never a silent ALLOW.
- **Only the assistant message is a verdict.** `reasoning_content` is dropped — a verdict parsed out of
  a thinking trace is text the model wrote while thinking, not a decision.
- **The CLI binary is resolved, not assumed.** `OMP_DC_BIN` / `OMP_BIN` win; otherwise
  `process.execPath` when it *is* omp (the normal case, extensions run inside omp), else `omp` from
  PATH. A test runner or editor host must not spawn its own runtime as the checker.
- **Command words are read the way the shell reads them.** An unquoted `r\m`/`"r""m"` is `rm`: the
  tokenizer keeps the literal text for targets (a Windows path keeps its separators) and a
  backslash-collapsed `word` for command-position tests. Use `t.word ?? t.text` for the latter.
- Prompts are deliberately tiny (action + cwd + fired rule + one line of intent) and verdicts are
  cached per `(cwd, action)`. Spend fewer tokens there, not by starving the reply.

## Tests

```bash
node tests/t-static.mjs        # policy layers, classification, coverage, internal errors
node tests/t-llm.mjs           # checker: wire contract, verdicts, failure policy, cache, prompt
node tests/t-menu.mjs          # /dc menu: every setting persists, self-test, escape handling
node tests/t-coverage.mjs      # script bodies, hub launches, probes, catastrophic class, audit log
node tests/t-review.mjs        # the external review's findings D01–D23, one block per finding
node tests/t-isolation.mjs     # deny-ACE mechanics from the README runbook (Windows only)
node tests/t-install.mjs       # the installer's pre-install gate and its --skip-tests bypass
node tests/mutation-check.mjs  # test-quality gate (see below)
node tests/t-e2e.mjs           # real omp sessions; needs auth, slower, some cases skip
```

- Suites use an isolated `HOME`, a stubbed extension host and a stubbed `fetch` — no network, no
  credentials, no real deletions. Keep them that way. Overrides for a machine that differs:
  `DC_TEST_ROOT` (scratch root, default `~/.omp-destructive-check-tests`), `OMP_BIN`
  (the `omp` binary the e2e spawns), `DC_E2E_HOME`, `DC_E2E_AGENT_DIR`, `DC_E2E_MODEL`,
  `DC_E2E_DUMP=1` (print the raw session transcript).
- Scratch paths stay **outside** the OS temp directory on purpose: the guard treats temp paths as
  disposable artifacts, so an isolated HOME under `%TEMP%` would silently change what the policy
  cases actually test.
- **A check must be able to fail.** Before adding one, name the plausible bug it catches. No
  tautologies (`x !== undefined` on a value you just built), no re-asserting the same path across
  modes, no asserting source text or mock echoes.
- `tests/mutation-check.mjs` enforces that: it breaks the extension in 25 places and requires the
  suites to catch every break. **Run it after touching policy or checker code**; a "PATTERN NOT
  FOUND" line means the mutation went stale and the gate fails.
- The harness **fails closed**: `loadExt`'s default `exec` stub returns exit code 1, so a test that
  silently depends on the CLI checker fails instead of passing on a stub's `ALLOW`. Pass an explicit
  `exec` to test the CLI path, and pass `extPath` to load a copy (the installed layout) when the case
  is about the guard's own file.
- `t-e2e` drives real models that sometimes refuse to run destructive commands at all. Those cases
  are reported as `SKIP` (guard never exercised) — never fake a pass there, and never "fix" a skip by
  weakening the assertion.
- After changing the extension: run the three stub suites, the mutation gate, then
  `DC_E2E_ONLY=checker node tests/t-e2e.mjs` to confirm the in-process path still answers in ~2-3 s.

## Shipping

```bash
node install.mjs --force     # sync ~/.omp/shared/destructive-check.ts (keeps a .bak)
git add -A && git commit && git push
```

`install.mjs` refuses to install a guard that fails its own suites: it runs `t-static`, `t-llm`,
`t-menu`, `t-coverage` and `t-review` first and stops before copying when one of them fails
(`--skip-tests` is the deliberate bypass, and `--force` does not skip the gate). `tests/t-install.mjs`
asserts both halves, so a change to the installer or to the suite list has to keep that contract.

`README.md` documents user-visible behavior; change it in the same commit as the behavior.
The `/dc` menu is the only configuration UI users are expected to touch — a new setting needs a menu
entry, a default in `DEFAULTS`, and a persistence check in `tests/t-menu.mjs`.
