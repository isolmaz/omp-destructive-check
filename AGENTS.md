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
README.md              user-facing overview: levels, coverage, install, docs map (keep it in sync with behavior)
docs/SETTINGS.md       every configuration key: what it does and why
docs/REFERENCE.md      deep reference: rules, coverage, UI, audit, runbook, limitations
```

Everything the guard needs ships in `destructive-check.ts`: no build step, no imports outside
`node:fs` / `node:path` / `node:os` / `node:crypto` / `node:url` — plus `node:child_process`, which
exists for exactly one thing and is imported for it: the persistent `omp --mode rpc` checker child on
the CLI path (invariant 22). Keep it that way — the file is copied verbatim into `~/.omp/shared/` and
loaded by every omp profile. The audit chain uses `node:crypto`'s SHA-256, and `tools/dc-audit.mjs`
re-implements the walk with its own digest so the two agree.

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
   log, and a cached hash would let the second writer chain onto a line that is no longer last. The
   append, tail read, rotation and quarantine share one exclusive `${LOG}.lock`. Never read the tail
   outside that transaction and claim an atomic append makes the chain concurrent-safe. Lock
   acquisition is bounded; failure retains the decision in session history and reports degraded
   auditing rather than mutating the file without ownership. A tail that stops mid-line or has an invalid
   entry, is **quarantined** (`<path>.corrupt.<ts>`, kept whole, fresh chain, `degraded` entry) instead
   of being chained onto: a partial read would produce a break no verifier could explain. Command text
   is masked for credentials (`token=`, `api_key:`, `bearer …`) and the file is created `0600` — the log
   records the decision, not the secret.
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
    the "do not retry this through another tool" sentence, and — where a rule has one — the near-miss
   sentence between them (25). Tests and users match on that shape.
    For a rule that is not exempt the block ends with the retry invitation instead of the flat refusal —
    that sentence *is* how the loop is announced, so it is part of the contract too.
15. **The second chance is bounded and recorded.** `guardSelf`, `catastrophic`, `systemTarget` and
    `protectSecrets` are a floor `retry.exempt` can only add to — no setting re-opens the loop for them, and a repeat of
    one is an ordinary block. A repeat without a justification is a block with nothing new to say
    (`No further attempts…`): the guard never spends a checker call on it, and the same operation is
    only ever retried once (`retry.maxAttempts`, `retry.sessionBudget`, `0` = off). One retry means one
    extra checker call inside the **same** `timeoutMs` budget as the first request (invariant 3) — a
    deadline shared, never restarted. A retry verdict is JSON or it is nothing: prose, a missing reason,
    an unknown enum value or a claim the guard cannot check are all blocks, and every retry records
    `attempt`, `authority`, the justification hash/length, the claim verdicts, the recovery path and any
    erosion **inside the hashed audit payload** (invariant 8), so none of it can be edited out of a line.

## Checker wiring (the parts that actually bite)

- Requests go out as plain `fetch` — no pi-ai RPC, no extra process, no agent session. OpenAI-compatible
  (`openai-completions`, `openrouter`) and Anthropic Messages are spoken natively; anything else
  (Gemini CLI OAuth, Codex, Cursor) routes to the CLI engine via `engine: "auto"`, which is the one
  persistent `omp --mode rpc` child (invariant 22) with a one-shot `omp -p` run as its documented
  fallback.
- **OpenCode-style gateways require `x-opencode-session`.** Without it they answer
  `400 MissingSessionID` and every check silently pays for a CLI run (measured 8.6 s vs 1.7-3.0 s).
  The client also sends `user-agent`. An unknown gateway gets exactly one retry with a session id.
- **Never cap output tokens by default.** A tight cap truncates reasoning models before they emit the
  verdict line; `maxOutputTokens: 0` (default) omits the field. Anthropic still needs `max_tokens`,
  so it gets a generous ceiling. When a provider does truncate (`finish_reason: length`), the checker
  reports that: an empty message is an error, never a silent ALLOW.
- **Only the assistant message is a verdict.** `reasoning_content` is dropped — a verdict parsed out of
  a thinking trace is text the model wrote while thinking, not a decision. The *retry* verdict is not
  even that: it is the JSON object `{decision, confidence, reason, claims}` or nothing, and a prose
  reply fails closed like any other unparsable answer.
- **The second chance is a channel the agent can see.** `dc_justify` is registered with `approval:
  "read"` and a one-line `before_agent_start` custom message names it; the *automatic* half reads the
  last assistant message from the branch, and the *user* half reads the `context` event (the `input`
  event never fires in RPC/print). Both halves are agent text: they travel to the checker inside an
  `<untrusted_justification>` block and are never evidence — the claims are what the guard checks.
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
node tests/t-isolation.mjs     # deny-ACE mechanics from the docs/REFERENCE.md runbook (Windows only)
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
- `tests/mutation-check.mjs` enforces that: it breaks the extension in 67 places and requires the
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

`README.md` and the files under `docs/` document user-visible behavior; change them in the same
commit as the behavior.
The `/dc` menu is the only configuration UI users are expected to touch — a new setting needs a menu
entry, a default in `DEFAULTS`, and a persistence check in `tests/t-menu.mjs`.

16. **One table, one template.** Every covered tool is an entry in `ADAPTERS` (`kind`, `coverage`,
    `scope`, `extract`, `scan`, `secrets`, `readOnly`) and `analyzeCall` is the single template over
    it: scope → extract → scan, then the call-level layers (a project's deny patterns, the readonly
    gate). A new tool is one entry — do not add a branch to a chain that no longer exists, and do not
    let a tool reach the decision path without an entry (an uncovered tool is not judged at all, so
    the table *is* the coverage).

17. **The read-only class is an allow, never a release.** `readOnlyCommand` recognizes a line every
    one of whose sub-commands is a verb that cannot change anything, with that verb's own flags
    (`sort -o`, `find -delete`, `git clean -f`, `uniq in out` are outside it; `git clean -n` and
    `tar -t` are inside). It runs *after* the catastrophic signatures and it short-circuits the
    scanners only for a line they would otherwise misjudge; a finding from those scanners is never
    released by it. Interpreters and code runners are never in it. `mode: "readonly"` is built on
    top: in it, everything that is not provably read-only blocks, whatever its target.

18. **Read-only surfaces stay read-only.** `dc_inspect` (status | config | rules | recent |
    explain) changes no config, no session state, no cache and no audit line: `explain` re-runs the
    static layers only and never asks the model. It refuses to answer unless it can prove the
    running definition is this module's own (the definition the registry holds, and any source path
    the host records, against the loaded module path), and its model-visible output carries rule
    names, actions and timings — never the guard's full reasons or the action payload.

19. **A project file may only tighten.** `<cwd>/.omp/destructive-check.json` may make a rule action
    more restrictive and add deny patterns; `mode`, `enabled`, the checker settings, `allowDirs` and
    any loosening value are refused, recorded, and shown in `/dc → status` and `dc_inspect config`.
    The merge is most-restrictive-wins (`ruleAction`), so a project file cannot release a rule even
    if the merge were wrong, and `RULE_FLOORS` keeps `guardSelf`, `projectDeny`, `readonlyMutation`
    and `unreadTarget` from being set to `allow` in *any* file. This host exposes no project-trust
    signal; that is reported rather than assumed.

20. **The guard's own controls are not editable.** `guardSelf` blocks writes and deletes aimed at
    `~/.omp/shared/destructive-check.ts`, its manifest, `~/.omp/destructive-check.json`, the approval
    list, the project policy file, a directory containing one of them, and `~/.omp/agent/config.yml`
    when the edit touches `extensions`/`disabledExtensions`. The lock and the installer stay the
    reactive half; this is the half that stops the write from happening at all.

21. **The policy is re-read, and one budget covers one decision.** The config is reloaded on
    `session_start` (a child session must not run the parent's snapshot) and re-stat'ed by mtime+size
    before a decision — **at most once per second** (`FRESHNESS_TTL_MS`), because a `statSync` per call
    was the whole static-path regression (measured: 930 µs → 1464 µs on the heaviest case, against a
    +500 µs budget). `session_start` and every `/dc` open force it, so the two moments a human is
    looking are always current; a hand-edited file is otherwise picked up by the next check after the
    second it was saved. Writes go through a temporary file and a rename, every key is validated against
    its type/enum with the default kept on an invalid value, and the rejected keys are listed in
    `/dc → status`. The two-stage checker (`checker.twoStage`) runs a one-digit pre-filter and then the
    detailed call inside the **same** `timeoutMs` budget the single request always had: a fast stage that
    answers anything other than `0`/`1` is a checker failure (invariant 1), never an allow.
22. **One subprocess, and only for the CLI checker.** The persistent `omp --mode rpc` child is the only
    process this extension ever owns: started lazily on the first CLI check, one prompt frame per check,
    the assistant's `text_delta` frames are the verdict (a `thinking_delta` never is), killed on
    `session_shutdown`, idle-reaped after two minutes, and a decision that runs out of its `timeoutMs`
    forwards `{"type":"abort"}` and drops the child. Any failure to get an answer travels the ordinary
    failure policy after **one** `omp -p` fallback inside the remaining budget (never a restarted clock)
    and is recorded in `degraded`. A host that owns its process table may take over the spawn
    (`EXT_PI.spawnChild`); no test may ever spawn a real process.
23. **The action is never trimmed.** `maxCommandChars` may cap the command text and
    `maxPromptChars` may trim the rule lines, the intent and the session-context block, but a request
    whose *action line* does not fit the budget is a checker failure (ask, or block with that text) —
    never a verdict on a clipped command the agent did not write. The fast stage is skipped rather than
    asked about an action it cannot see, because its `0` is an allow.
24. **Read-only scope only narrows.** `readOnlyDirs` maps a target to the *outside* class before the
    artifact/inside branches, so an entry can only ever move a target from inside/artifact to outside:
    it cannot widen the delete/write scope, it overrides an overlapping `allowDirs` entry, and it keeps
    an artifact name inside it away from the artifact allow. Entries are validated exactly like
    `allowDirs` entries (root, home, system tree refused and reported).
25. **A block reason may add a near miss, never a new shape.** The near-miss sentence ("what would have
    allowed this call") is appended between the detail and the "what to do next" sentence, so
    `<what> (mode: …, rule: …) — <detail>. <near miss> <what next>` still matches; it names policy facts
    (a scope root, a rule class, the read-before-write rule) and the exempt floor carries none.
26. **Every decision carries its trace, and the diagnostics must agree.** Each audit line names
    `ruleId`, `layer`, `scope` and the `degraded` list of its moment; a blocked call that later comes
    back through a `tool_result` gets its own chained line (`outcome: ran|not-run`, `link` = the decision
    line's chain); `/dc → doctor` and `dc_inspect doctor` print the live half (enforcement, integrity,
    lock, chain, checker, child, config, degraded) and must agree with the file half
    (`node tools/dc-audit.mjs doctor`) on the chain verdict and the entry count.
27. **The panel is measured as raw text and coloured afterwards.** `spec.paint` opts a surface into the
    host theme (`/dc` and its reports); the approval prompt stays out of it, and a host that hands over
    no theme gets the plain box with no escape code at all, so the theme is never required. All width
    math is ANSI-aware (`visibleWidth`/`clipVisible`/`padVisible`) with measurement done on the
    sanitized raw string *before* the theme touches it — colour must never move the frame. Foreign text
    goes through `plain()` before it enters a line: the panel never forwards an escape it did not put
    there itself, and `tests/t-ui.mjs` fails if one gets through.
