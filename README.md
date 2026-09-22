# destructive-check

![platform](https://img.shields.io/badge/platform-omp%20extension-4c8dff)
![source](https://img.shields.io/badge/source-single%20file%20%C2%B7%200%20deps-brightgreen)

A guard for the [omp](https://github.com/can1357/oh-my-pi) coding agent. **Before a destructive
tool call runs, the guard decides whether it is allowed** — deletes, moves, writes outside the
project, destructive `git`, credential files, fork bombs.

Three promises, no fine print:

- **A broken check is never blamed on the model.** If the checker itself fails or times out, the
  guard asks you (headless: blocks with the real error text) — never "the model said no".
- **You hold the keys.** One config file, edited through the `/dc` menu; a project file can only
  make the policy stricter, never looser.
- **Everything is recorded.** Each decision lands in a hash-chained audit log you can verify with
  an independent tool.

## How it decides

Every call passes through three layers, cheapest first. Most calls never reach the model at all:

| # | Layer | What it catches | Cost |
| --- | --- | --- | --- |
| 1 | **static deny** | things that are never acceptable: system paths, secret files, fork bombs | instant, no model |
| 2 | **static allow** | things that are provably safe: build artifacts and temp files inside the project | instant, no model |
| 3 | **model check** | everything the first two layers cannot classify | one small request, ~2 s |

The model check is a single bounded request to your configured model — in-process, cached, about
0.2k tokens and 1.7–3.0 s measured.

## Guard levels

Five presets decide how much is checked:

| Mode | In one line |
| --- | --- |
| `simple` | only the truly dangerous stuff blocks; project-internal work stays free |
| `medium` *(default)* | secrets and project deletes block; risky `git`, unreadable scripts and unknown targets go to the model |
| `hard` | block by default — only artifact cleanup stays free |
| `custom` | starts from `medium`, every rule settable by hand |
| `readonly` | anything that could change something blocks |

Each rule resolves to one of four actions:

- `block` — refuse the call; no model, no prompt.
- `ask` — ask you in the TUI (headless sessions fail closed).
- `model` — one bounded check with your model.
- `allow` — let it through.

Several rules on one call? The **most restrictive** wins. `guardSelf`, `catastrophic`,
`systemTarget` and `protectSecrets` are a floor no setting can re-open. Want to watch first?
`dryRun` (**watch mode**) logs every decision as `would-block` without enforcing anything
([details](docs/REFERENCE.md#watch-mode-dry-run)).

→ Full per-rule matrix: [docs/REFERENCE.md](docs/REFERENCE.md#protection-modes) ·
second-chance loop for recoverable blocks: [justification](docs/REFERENCE.md#the-second-chance-justification-loop)

## Install

```bash
node install.mjs              # copies the extension to ~/.omp/shared/ and prints the config.yml snippet
node install.mjs --force      # overwrite without asking (a .bak copy is kept)
node install.mjs --unlock     # replace a copy locked from /dc; the lock mode is restored after
node install.mjs --skip-tests # skip the pre-install gate; --force does not skip it
```

The installer refuses to copy a guard that cannot pass its own offline suites (`t-static`,
`t-llm`, `t-menu`, `t-coverage`, `t-review`); `--skip-tests` is the deliberate bypass.

Point `~/.omp/agent/config.yml` at it (the installer prints the exact block):

```yaml
extensions:
  - ~/.omp/shared/destructive-check.ts
```

All profiles share the guard; opt out per profile with:

```yaml
disabledExtensions:
  - extension-module:destructive-check
```

## Configuration

`~/.omp/destructive-check.json`, created and edited by the `/dc` menu:

```jsonc
{
  "enabled": true,
  "mode": "medium",   // simple | medium | hard | custom | readonly
  "dryRun": false     // watch mode: log every decision, enforce nothing
}
```

Every key — what it does and why — is in **[docs/SETTINGS.md](docs/SETTINGS.md)**. A project's own
`.omp/destructive-check.json` may only **tighten** the policy, never loosen it.

## What gets checked

| Tool | What is judged |
| --- | --- |
| `bash` | delete/move verbs, redirects, write verbs, wrappers, nested shells, script bodies |
| `git` | destructive subcommands: `clean`, `reset --hard`, `push --force`, `branch -D`, history rewrites, … |
| `eval` | delete/write APIs in Python and JS/TS, embedded shell strings, computed targets |
| `write`, `edit`, `apply_patch` | every path named: credential stores, system files, outside-project writes, read-before-write |
| `hub` | process launches (`start`/`restart` payloads; `detached`/`persist` flagged) |

Deleting through `eval`, a script file, or a `hub` launch is covered too — command *strings* are
not the only thing the scanner sees. → Full table: [docs/REFERENCE.md](docs/REFERENCE.md#coverage)

## Diagnostics & trust

- Every decision lands in a SHA-256 hash-chained audit log; `node tools/dc-audit.mjs` verifies the
  chain with an independent implementation.
- `/dc → doctor` shows what is actually enforced right now: integrity, lock, checker, degraded
  capabilities.
- The guard's own files are integrity-checked against the installer's manifest and can be locked
  read-only — and a real boundary needs the OS: [out-of-band runbook](docs/REFERENCE.md#threat-b-an-out-of-band-boundary-runbook).

→ [audit log](docs/REFERENCE.md#audit-log) · [doctor](docs/REFERENCE.md#doctor--what-is-enforced-right-now) · [integrity](docs/REFERENCE.md#guard-integrity-lock-and-restore)

## Tests

```bash
node tests/t-static.mjs        # policy layers: modes, rules, coverage, path classification
node tests/t-llm.mjs           # checker: wire contract, verdicts, failure policy, cache, prompt
node tests/t-menu.mjs          # /dc menu: every setting persists, self-test, escape handling
node tests/t-coverage.mjs      # script bodies, hub launches, probes, catastrophic class, audit log
node tests/t-review.mjs        # the external review's findings D01–D23, one block per finding
node tests/t-ui.mjs            # pop-up, panel, status line, fail-closed paths
node tests/t-isolation.mjs     # deny-ACE mechanics from the runbook (Windows only)
node tests/t-install.mjs       # the installer's pre-install gate and its --skip-tests bypass
node tests/mutation-check.mjs  # test-quality gate: every injected break must fail a suite
node tests/t-e2e.mjs           # real omp sessions (needs auth, slower)
```

Suites run offline against an isolated `HOME` with a stubbed host and stubbed `fetch`; the stubs
fail closed. → Conventions: [AGENTS.md](AGENTS.md)

## Documentation

| File | What it covers |
| --- | --- |
| [docs/SETTINGS.md](docs/SETTINGS.md) | every configuration key: default, values, purpose |
| [docs/REFERENCE.md](docs/REFERENCE.md) | rule matrix, coverage, UI, audit log, checker, runbook, known limitations |
| [skills/destructive-check/SKILL.md](skills/destructive-check/SKILL.md) | what the agent does after a block |
| [AGENTS.md](AGENTS.md) | invariants and conventions for agents contributing to the repo |

## Known limitations

The honest list lives in [docs/REFERENCE.md](docs/REFERENCE.md#known-limitations): recovery covers
the simple delete, hard links are invisible to `realpath`, the audit chain is tamper-*evident* (not
tamper-proof), and path handling targets Windows + Git Bash.

## Repository layout

```
destructive-check.ts   the extension (single file, zero dependencies)
install.mjs            copy it into ~/.omp/shared, write the manifest, print the config snippet
tools/dc-audit.mjs     independent verifier for the audit log (node:crypto, exit 1 on a broken chain)
tests/                 stubbed-host suites + real-session e2e + a mutation gate
docs/SETTINGS.md       every configuration key: what it does and why
docs/REFERENCE.md      deep reference: rules, coverage, UI, audit, runbook, limits
skills/                the companion skill: what the agent does after a block
AGENTS.md              invariants and conventions for agents working in the repo
```
