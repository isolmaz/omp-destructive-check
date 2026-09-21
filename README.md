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
| `protectSecrets` — a mutating target that resolves to a credential store: `.env` (but not `.env.example`/`.env.sample`), `.ssh/**`, `.aws/credentials`, `.kube/config`, `.git-credentials`, `id_rsa*`, `*.pem`/`*.key`/`*.p12`/`*.kdbx`, `auth.json`, `.npmrc`, `.config/gh/hosts.yml` | ask | block | block |
| `outsideDelete` — deletes whose target is outside the project | block | block | block |
| `outsideMove` — moving data that lives outside the project, or moving it out | block | block | block |
| `outsideWrite` — a write-like effect outside the project: `>`/`>>`/`>|`/`>&file` destinations, the write positions of `cp`/`mv` (including `-t DIR`/`--target-directory=DIR`), `rsync`, `truncate`, `tee`, `dd of=`, `chmod`/`chown`/`chgrp`, `ln`/`mklink`, `install`, `sed -i`, `curl -o`/`wget -O`, `tar -C`, `unzip -d` and `git clone`'s destination, plus every file a `write`/`edit`/`apply_patch` call rewrites | ask | model | block |
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

`protectSecrets` is the one rule that is decided without a model in every mode and never takes a
second chance: rewriting or deleting a credential store is not a judgement call, and the block reason
names the file (`"C:\proj\.env" is a credential or secret file`), never the pattern that matched it.
It reaches `write`, `edit` and `apply_patch` (the `path` field, every `*** … File:` section, the
hashline headers and the structured `{path, edits:[…]}` form), plus deletes, moves and write effects
issued through `bash` and `eval` — including the write APIs in eval code (`open(path, 'w')`,
`Path(p).write_text(…)`, `writeFileSync`, `shutil.copy/move`, `os.replace/rename`, `fs.linkSync`),
whose destination is read from the first argument (or the second one for a copy/move/link pair).
`.env.example` and `.env.sample` are templates, so they stay free.

`outsideWrite` reads a command the way the shell does. Redirect destinations come from the command
text with quoting respected: `>`, `>>`, the noclobber override `>|` and `>&file` (both streams to a
file) all write their target, while `2>&1`, `>&2` and `>&-` are file-descriptor copies, not files.
Here-document bodies are read once for the whole scanner and both halves use that one decision: a body
handed to a shell or an interpreter (`bash <<'EOF'`, `python <<'EOF'`) runs as code — its redirects,
verbs and deletes are judged at one nesting level deeper — while a body handed to a plain reader
(`cat`, `tee`, `awk`) is data and is not scanned. An *unterminated* here-document is never blanked, so
a `<<` that the shell would read as something else cannot hide the lines after it. `> /dev/null` (and
`NUL`) writes nowhere and stays silent. Each verb names its own write positions, with its own option
grammar: `cp`/`mv`/`install` their destination (or the `-t DIR`/`--target-directory=DIR` they were
given — with that flag every operand is a source, and a lone operand is a source too), `rsync` its
destination (all sources with `--delete`), `dd` only `of=` (a block device stays `catastrophic`),
`chmod`/`chown`/`chgrp` every argument after the mode/owner, `ln`/`mklink` both the target and the link
path, `sed -i` every operand (without `-i` sed writes nothing), `curl -o`/`wget -O`, `tar -C`,
`unzip -d` and `git clone`'s final operand. `--opt=value` is an option, not a path, so a trailing
`--backup=numbered` is not mistaken for the destination. So `cp ../outside/a .` is not flagged while
`cp a ../outside/` is, and `cp -t ../outside a b` is. An inline `cd`/`pushd` moves where the *relative*
targets of the rest of the line resolve, in the write scan exactly as in the delete scan
(`cd ..; echo pwn > target.js` is an outside write). A destination that cannot be resolved — a
variable, a glob, a brace expansion like `{../outside,../tmp2}/x.txt`, or a remote
`user@host:/path` — is a `dynamicTargets` violation, never a clean pass.

The file tools are judged by the same write rules as the shell channel: every path a `write`, `edit`
or `apply_patch` call rewrites is classified, so rewriting a system file or a file outside the project
is a `systemTarget`/`outsideWrite` (it used to be judged by the secret check alone and stayed free),
and a target the guard cannot resolve (`%APPDATA%\.env`) is a `dynamicTargets` violation. Ordinary
editing inside the project stays free.

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

Scope and targets are compared as **real** paths: `realpathSync` — through the nearest existing
ancestor when the target does not exist yet — resolves junctions and symlinks, so a link inside the
project that points outside is classified as outside, and a link that points back in is classified as
inside. Only paths the filesystem actually resolved are cached (15 s, per session), which is what
keeps the static layers at 0 ms; the ancestor walk for a path that does not exist yet is recomputed on
every call, so a link created after the first check is picked up by the next one.

Each rule can be set to one of four actions:

- `block` — refuse the call, no model, no prompt.
- `ask` — ask the user in the TUI (headless sessions fail closed).
- `model` — ask the checker model (bounded, cached).
- `allow` — let it through.

## Watch mode (dry-run)

`dryRun: true` (or `OMP_DC_DRYRUN=1`) computes and logs **every** decision and enforces none of them:
nothing is blocked and nothing is asked, and the audit entry says `would-block` instead of `block`. A
`model` rule is still put to the checker — the point of a calibration run is to see what the policy
would have caught on real traffic before you turn it on. The status line reads `dc: WATCH · <mode>` at
rest and `dc: WATCH · would block: <rule>` after a decision, and `session_start` prints a warning, so
it cannot be left on by accident. Toggle it in `/dc → watch (dry-run)`.

## Coverage

| Tool | Covered |
| --- | --- |
| `bash` | delete/move verbs, wrappers (`sudo`, `xargs`, `env`, `timeout`), shells (`bash -c`, `cmd //c`, `powershell -NoProfile -Command`, `bash -o pipefail -c`, `wsl bash -c`), nested wrappers (up to 3 levels, deeper ones escalate), `find -delete`/`-exec`/`-execdir`, package runners (`npx rimraf`, `yarn run rimraf`), compound commands (`&&`, `\|`, `;`, `for … do`), inline `cd` tracking (deletes **and** writes), **script bodies** (`sh ./x.sh`, `bash -x x.sh`, `./x.sh`, `cmd /c x.cmd`) up to 64 KiB and 2 files deep, **redirect destinations** (`>`, `>>`, `>|`, `>&file`; here-document bodies scanned as code when the reader is a shell, dropped when it is `cat`/`tee`/`awk`, `2>&1`/`>&2`/`>&-` skipped, `/dev/null` and `NUL` silent) and **write verbs** with their own option grammar (`cp`/`mv`/`install` incl. `-t DIR`, `rsync` incl. `--delete`, `dd of=`, `truncate`, `tee`, `chmod`/`chown`/`chgrp`, `ln`/`mklink`, `sed -i`, `curl -o`/`wget -O`, `tar -C`, `unzip -d`, `git clone`) |
| `write` | every path it names is classified: a credential store (`.env`, `id_rsa`, `*.pem`, `.ssh/**`, `.aws/credentials`, …) is `protectSecrets`, a system file is `systemTarget`, a path outside the project is `outsideWrite`, and a target the guard cannot resolve (`%APPDATA%\.env`) is `dynamicTargets`. Editing inside the project is ordinary work and stays free |
| `git` | destructive subcommands: `clean`/`rm`, `reset --hard`, `push --force`/`--delete`, `branch -D` (and `-d --force`), `stash drop`/`clear`, bare `restore` (but not `--staged`, which only unstages), `checkout -f` and the `checkout [ref] -- <path>` form, `switch -f`/`--discard-changes`, `worktree remove --force`, `reflog expire --expire=now`, `gc --prune=now`, `filter-branch`/`filter-repo`. Git arguments are not path-classified: the subcommand decides, so this list is the coverage. |
| `eval` | delete APIs in Python (`shutil.rmtree`, `os.remove`, …) and JS/TS (`fs.rmSync`, `fs.unlinkSync`, `Deno.remove`, …) and write APIs (`open(p, 'w')`, `Path(p).write_text(…)`, `writeFileSync`, `shutil.copy/move`, `os.replace/rename`, `fs.linkSync`), with a literal or single-binding target classified and a computed one recorded as `dynamicTargets`, plus destructive shell strings and catastrophic one-liners inside the code |
| `edit`, `apply_patch` | hashline `REM` / `MV`, `*** Delete File:`, `*** Move to:` — every file section in the payload, each move paired with the section above it — and the structured form (`{path, edits: [{op: "delete"}]}`), which is its own schema and used to be read as JSON text that matched nothing. Every path the payload names is also classified like a shell write target, so an `*** Add File:`/`*** Update File:` section outside the project or in a system tree is caught |
| `hub` | `start` / `restart`: `application` + `args` are scanned like a command line — each argument is quoted before it joins, so a destination holding a space stays one path; `detached` / `persist` add a `dynamicTargets` violation because the process outlives the session. Disable with `coverage.processes: false`. |

Deleting a project directory through `eval` was a real bypass in earlier versions; it is covered now.
So was the pair this release closes: a delete loop moved into a script file, and the same payload
launched through `hub` — command *strings* were the only thing the scanner ever saw.

## Install

```bash
node install.mjs            # copies the extension to ~/.omp/shared/ and prints the config.yml snippet
node install.mjs --force    # overwrite without asking (a .bak copy is kept)
node install.mjs --unlock   # allowed to replace a copy locked from /dc; the mode is restored after
node install.mjs --skip-tests  # skip the pre-install gate (see below); --force does not skip it
```

Before copying anything, the installer runs the five offline stub suites (`t-static`, `t-llm`,
`t-menu`, `t-coverage`, `t-review`) and refuses to install when one of them fails: the file it writes
is the one every omp profile loads, so a build that cannot pass its own tests must not get there.
`--skip-tests` is the deliberate bypass; `tests/t-install.mjs` asserts both halves.

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
  "maxPromptChars": 1200,           // hard cap on the whole checker prompt, policy block included
  "maxIntentChars": 240,            // how much agent intent is forwarded
  "maxOutputTokens": 0,             // 0 = no cap; a cap truncates reasoning models mid-verdict
  "reasoning": "off",
  "includeIntent": true,
  "cacheEnabled": true,
  "askOnDeny": true,                // model denies -> ask the user instead of blocking blind
  "askOnError": true,               // checker fails  -> ask the user instead of blocking blind
  "allowDirs": [],                  // extra project dirs; a root, the home or a system tree is refused and reported
  "dryRun": false,                  // watch mode: log every decision as would-block, enforce nothing
  "logSize": 25,                    // entries kept for "/dc > recent decisions"

  "preset": "balanced",             // quiet | balanced | strict — the friction preset (see below)
  "policyNote": "",                 // free text the checker receives with every request, in the policy block
  "retry": {                        // the second-chance loop (see below)
    "authority": "model",           // model | ask | off
    "maxAttempts": 1,               // justified repeats per operation (0 = none)
    "sessionBudget": 3,             // justified repeats per session (0 = none)
    "rememberApproved": "session",  // session | once | permanent (only human approvals are ever permanent)
    "exempt": []                    // extra rules that never enter the loop (adds to the fixed three)
  },
  "justifyTool": { "enabled": true }, // offer dc_justify to the agent
  "verify": { "level": "claims" },              // claims | claims+adversarial | off
  "recovery": { "mode": "justified", "dir": "~/.omp/dc-trash", "ttlHours": 72 },  // justified | high | off
  "erosion": { "mode": "session" },             // session | log | off

  "ui": {
    "overlay": "auto",              // auto | always | never — the pop-up vs the plain-list dialogue
    "statusLine": {
      "location": "bar",            // bar | belowEditor | aboveEditor | off
      "detail": "standard",         // minimal | standard | counters
      "barSide": "host"             // host | left | right — where the guard's segment sits in the footer
    },
    "popupButtons": ["allowOnce", "allowSession", "deny"],
    "sessionSummary": true          // one advisory line when the session ends
  }
}
```

`preset` writes the settings it stands for, so the file never shows a preset name that
disagrees with the values beside it: `quiet` = allow-on-deny off, retry authority off,
verification off; `balanced` = the defaults above; `strict` = allow-on-deny off, retry
authority off, adversarial verification. The panel shows `custom` when the values were
changed one by one.

## The second chance (justification loop)

A destructive call the guard refuses is not always a call the user would refuse. For rules that
are not exempt, the block reason ends with an invitation instead of the flat refusal:

```
This action is recoverable and may be intended. If it is, explain in your next message what will
change and why that is safe (which paths, which data), then repeat the same call. A repeat without
a concrete justification is blocked again. Do not attempt it through another tool.
```

Exempt rules (`catastrophic`, `systemTarget`, `protectSecrets`) never get that sentence — and never
enter the loop, whatever `retry.exempt` says: the fixed three are a floor the config can only add to.
A repeat with nothing new to say is a hard block too (`No further attempts on this operation; ask the
user to confirm it in /dc before repeating it.`), as is a second refusal of any kind.

The loop is bounded four ways:

| Bound | Setting | Effect |
| --- | --- | --- |
| attempts per operation | `retry.maxAttempts` (1) | justified repeats of one operation; `0` disables the loop for every operation |
| budget per session | `retry.sessionBudget` (3) | total justified repeats in a session; `0` disables the loop |
| second-chance request | — | exactly **one** extra checker request, inside the same `timeoutMs` budget as the first |
| authority | `retry.authority` | `model` = the checker may allow it · `ask` = the user decides every repeat · `off` = no loop at all |

An operation is `tool + workspace + the call text` (whitespace is not part of it), so the repeat has
to be the same call — a different target or a different command is a new decision, and a retry through
another tool is still refused.

**Two ways to justify.** The agent's next message is read automatically (the text that preceded the
first attempt is *not* a justification — it has to be new), and `dc_justify` adds a structured record:

```
dc_justify({ target: "src", intent: "src is regenerated output, the .gitignore covers it",
             evidence: "git status --porcelain src is empty", policyClause: "…" })
```

The tool is visible, read-only, and records nothing but that record; it never changes the policy and
never allows anything on its own. A one-line note about it is injected on every turn where the loop
is live.

**The retry verdict is JSON and nothing else** — `{"decision":"allow"|"block","confidence":"low"|"high",
"reason":"…","claims":[…]}`. Prose, a missing reason or an unknown enum value is not a verdict: the
repeat is blocked exactly like any other unparsable answer, and the line parser that reads the normal
verdict is never used on this path.

**Claims are checked by the guard, not by the model.** An `allow` counts only when at least one claim
verifies:

| Claim | What dc checks |
| --- | --- |
| `committed` | `git status --porcelain -- <path>` is empty **and** `git log -1 --format=%H -- <path>` is not |
| `ignored` | `git check-ignore -q <path>` exits 0 |
| `artifact` | the path classifies as a build artifact or temp path (confirmed with `check-ignore` when git can answer) |
| `user_authorized` | the target is named in one of the last 12 user messages, collected from the `context` event |
| `resolved_targets` | the list matches the targets the classifier resolved, exactly — a call with unresolved targets fails this |

Git runs read-only, only on the retry path, through the host's own `exec` (never a process of the
guard's own). `verify.level: claims+adversarial` adds one more request for the high-severity rules
(`outsideDelete`, `outsideMove`, `outsideWrite` and the fixed three) that asks only for a
counterexample: a counterexample, or an answer that is neither `COUNTEREXAMPLE:` nor `NONE`, blocks.
`verify.level: off` skips the whole claim table — the model's own confidence is then the only signal.

**The authority matrix** (a stricter signal always wins):

| Verdict | `retry.authority: model` | `ask` |
| --- | --- | --- |
| `allow` + `high` + a verified claim | allowed, audit `authority: model` | pop-up |
| `allow` + `low` | pop-up | pop-up |
| `block`, unverified claim, unparsable answer | hard block | hard block |

**Recovery.** With `recovery.mode: justified` (the default), a delete that a justification got
approved is rewritten before it runs: the guard returns a revised input to the host, so the command
that executes — and that the host's own approval gate re-resolves — is a move into the trash instead
of a delete.

```
rm -rf src
→ mkdir -p "C:/Users/you/.omp/dc-trash/<session>/20260922-140312" && mv -f -- "src" "…/1-src" &&
  echo "destructive-check: moved src to …/1-src"
```

The `echo` is what makes the tool result say what actually happened to the files, and the move is a
rename, not a copy — the bytes never pass through the guard. Entries older than `recovery.ttlHours`
are removed on the next session start, bounded and silent. `high` limits the rewrite to the
high-severity rules, `off` never rewrites. A delete the guard cannot express as a single move (a
`git reset`, an eval loop, a compound command, several targets in one line) keeps its allow and runs
unchanged: recovery covers the simple `rm`, and the audit line records whether it was applied.

**Trust erosion.** The claim that was verified is the one thing a justification adds, so a claim that
turns out to be false has to cost something. Verified `committed` claims are re-checked once, at the
next tool call; when git now reports changes for that path, the audit gets
`action: "erosion", justification: false` and — in `erosion.mode: session` — `retry.authority` drops
to `ask` for the rest of the session (the panel shows `retry authority: ask (eroded by a false claim)`).
`log` records the contradiction without the drop, `off` ignores it.

## The checker knows the user's policy

Every checker request — the normal one and the retry one — starts with a block generated from your own
settings, never from agent text:

```
=== User policy (authoritative, set by the human) ===
mode: medium · friction: balanced (the default: ask when the model denies, second chances allowed, claims verified)
rules that do not simply block: outsideWrite=model, artifactDelete=allow, dynamicTargets=model, …
second chance: model · 1 per action · 3 left this session
verification: claims · recovery: justified · trust erosion: session
note from the user (trusted, written by the human): "Bu makinede arşiv klasörüne dokunma."
=== end policy ===
```

`quiet` adds "low-risk, recoverable work is not worth a block — still block anything suspicious or
irreversible"; `strict` adds "block when in doubt, and do not expect a second chance". The system prompt
names the block authoritative, it is written first, and it gets its budget before the action text is
trimmed — a `maxPromptChars` small enough to clip the block itself is one you set on purpose. The whole
request stays inside `maxPromptChars` (1200 by default; the retry request gets at least 1600, because it
carries the justification).

Every retry leaves an audit line with `attempt`, `authority`, `justificationHash`/`justificationLen`,
`claims` (type, and `!` when the guard could not verify it), `recovery` (the trash path) and `erosion`
— all inside the hash chain, so a claim or an authority cannot be edited out of a line.

`allowDirs` entries must be absolute or start with `~/`. An entry that names a filesystem root
(`C:\`, `/`), the user's home, `~/.omp` or a system tree (`C:\Windows`, `C:\Program Files*`, `/etc`,
`/usr`, `/bin`, `/var`) is **not** added to the scope: widening the guard to those would switch it off.
The check runs on the entry as written *and* on its canonical form, so a link that resolves into the
home is refused too, and `/dc → allowed dirs` (and `/dc → status`) list every refused entry with the
reason instead of leaving a setting that looks applied and is not.

Environment overrides (win over the file): `OMP_DC_DISABLE=1`, `OMP_DC_MODE`, `OMP_DC_PROVIDER`,
`OMP_DC_MODEL`, `OMP_DC_ENGINE`, `OMP_DC_TIMEOUT_MS`, `OMP_DC_DRYRUN=1` (watch mode for one session),
`OMP_DC_UI_STATUS` (`bar` / `belowEditor` / `aboveEditor` / `off` — where the status line goes for one
session), `OMP_DC_BIN` (CLI engine binary).

## Approval pop-up

When the guard has to ask, it asks in a pop-up (`ctx.ui.custom`) instead of a bare list, and the
reason is on the panel itself — no extra key press: the rule and what it decided, the target, the
command, the layer that decided (`static` / `model` / `cache` / `checker error`) with its latency, and
the attempt count against `retry.maxAttempts`.

```
┌─ destructive-check — approval needed ─────────────────────────────────────┐
│ Delete inside the project                                       dc: medium │
│ ───────────────────────────────────────────────────────────────────────── │
│ Why: Delete inside the project — "src" is inside the project              │
│ Action: rm -rf src                                                       │
│ Layer: model (justified, low confidence) (2210 ms)                       │
│ Attempt: 2/2 · model                                                     │
│ Justify: "src is regenerated output and .gitignore covers it — git        │
│           status --porcelain src is empty, the file is committed"        │
│ ───────────────────────────────────────────────────────────────────────── │
│ ▸ [a] Allow once        run this command now; the next one is checked …   │
│   [s] Allow for this session                                             │
│   [d] Deny              refuse the command; nothing is executed           │
└───────────────────────────────────────────────────────────────────────────┘
```

The `Justify:` row appears only when there is a justification to show — the retry path, where the
checker allowed the repeat with low confidence and the decision comes back to you. The `Layer:` row
names the layer *and* the authority (`model (justified, high confidence)` never opens this pop-up
under `retry.authority: model`; `ask` always does).

- `a` / `s` / `d` answer directly; the arrow keys move the highlight and Enter takes it.
- **Esc is Deny** — the fail-closed answer, never "close and carry on". So is a host that hands the
  pop-up back without an answer.
- `ui.popupButtons` trims the answers the pop-up offers. The deny button always stays: a pop-up that
  cannot refuse is not a guard.
- `ui.overlay` picks the surface: `auto` (the pop-up when the host offers `ctx.ui.custom`, the plain
  `select` list otherwise — RPC and ACP return `undefined` from `custom`, which is never a decision),
  `always` (no silent degradation: an overlay that cannot be drawn or an unanswered prompt is a
  refusal), `never` (never call `ctx.ui.custom` and always use the list).
- The session counters behind the status line's `counters` detail and the end-of-session summary come
  from the same place, so the line and the summary can never disagree.
- Waiting for an answer does not consume the host's handler budget (dialogs and overlays pause it).
  The guard's own `timeoutMs` plus one retry stays well inside the default
  `extensionHandlers.toolCallTimeoutMs` (30 s).

## Settings panel

`/dc` opens the same component as a settings panel when the host can draw one, and the original
select-based menu when it cannot. The panel is one scrolling list — `↑`/`↓` move, `PgUp`/`PgDn` page,
Enter opens or cycles the highlighted row, Esc closes:

```
Simple                 friction preset · policy note · status line
Protection             mode · every rule's action · watch (dry-run) · agent intent
Coverage               bash · eval · fileTools · processes
Retry & justification  authority · attempts per action / per session · remembering approvals ·
                       justify tool · verification · recovery (+ directory, retention) ·
                       trust erosion · which rules are exempt from the loop
Allowlist              every approval in force: session and permanent, one row per entry · clear all
Checker                model · engine · timeout · reasoning · token cap · self-test
UI                     pop-up mode · status line · pop-up buttons · session summary
Advanced               allowed dirs · rejected entries · history size · cache clears · env overrides
Guard                  integrity · lock · restore the previous guard (.bak)
History                the last decisions · explain a decision · audit entries · chain check
```

The **Allowlist** section is the editor for the approvals the guard is holding: one row per entry with
its source and time (`human (session) · insideDelete · rm -rf src`, `model (session only) · …`,
`permanent · …`). Activating a row removes that approval, so the operation is checked again; `clear all`
empties the session list and the permanent file. A model's justified allow is **never** written to
`~/.omp/destructive-check-allow.json` — only an answer you gave yourself can become permanent
(`retry.rememberApproved: permanent`).

Cycles and toggles are applied in place and written to the config immediately. Rows that need a real
prompt (the policy note, the checker model, the trash directory, allowed dirs) close the panel first,
so the host's own input owns the keyboard. Every row carries a one-line explanation, and the tests
treat a row without one as a defect — the same rule the plain menu has always had.

### Decision history and explain

The History section lists the last decisions from the audit file (newest last) with their rule, layer,
latency, directory and a short command. Activating one shows the whole trace: rule, layer, action,
tool, mode, time, latency, attempt, authority, justification hash and length, claims, recovery path,
erosion, cwd, target, command and session. `/dc → explain a decision` does the same from the plain menu.

### Session summary

At `session_stop` the guard prints one advisory line and stops there (it never asks for the session to
continue):

```
dc: 3 blocked · 2 allowed · 0 justified · top rule: outsideDelete
```

It only appears when something was decided, and only while `ui.sessionSummary` is on. In watch mode it
is prefixed `dc: WATCH ·` and the counts are what the policy would have done.

## Status line

The guard keeps one short status next to the model segment — `dc: medium` while it is protecting,
`dc: medium · blocked · Destructive git commands` after a decision — instead of a line under the
editor. `ui.statusLine` moves it and decides how much it says:

| Setting | Values | Effect |
| --- | --- | --- |
| `location` | `bar` (default) | `ctx.ui.setStatus("dc", …)` — the host's own segment |
| | `belowEditor` / `aboveEditor` | a one-line widget under (or over) the editor, cleared again after a few seconds |
| | `off` | nothing is written |
| `detail` | `minimal` | `dc: medium` — the mode and nothing else |
| | `standard` (default) | `dc: medium · blocked · Destructive git commands` |
| | `counters` | `dc: medium a:12 d:2 ca:5 cd:1` — allowed, blocked, checker-allowed, checker-denied (plus `w:` for watch-mode would-blocks) |
| `barSide` | `host` (default) / `left` / `right` | which side the guard's segment sits on in the footer |

`/dc → ui → show the statusLine snippet` prints a copy-pasteable block for
`~/.omp/agent/config.yml`:

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
friction preset: balanced   quiet ("do not bother me") | balanced | strict — sets ask-on-deny, ask-on-error, the retry authority and the verification level together
policy note: none           free text that goes with the checker request; a human wrote it, so unlike the agent's text it is trusted
ui: bar · standard · host   pop-up mode, status line, session summary
retry: model · 1/3          retry authority and budgets, remembering approvals, verification, recovery, erosion
allowlist: 2 session · 0 permanent  the approvals in force — remove one, or clear them all (model approvals are session-only)
checker                     model, engine, timeout, reasoning, token cap, self-test
ask on deny / ask on error  toggles
rules                       per-rule action editor (switches to custom mode)
coverage                    bash / eval / fileTools / processes on-off
watch (dry-run)             decide and log everything, enforce nothing (status line: dc: WATCH)
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
(`ts`, `tool`, `rule`, `action`, `detail`, `command`, `cwd`, `mode`, `ms`). A retry decision adds
`attempt`, `authority` (`model` or `user`), `justification` (whether a claim backed it),
`justificationHash` and `justificationLen`, `claims` (each type, `!` when the guard could not verify
it), `recovery` (the trash path the delete was moved to) and `erosion`. The in-memory list behind
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
- The verdict prompt is bounded: the authoritative user-policy block, then the action text
  (`maxCommandChars`), `cwd`, each fired rule with the target
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
node tests/t-ui.mjs       # pop-up UI: approval, panel, status line, fallback, fail-closed, summary
node tests/t-coverage.mjs # script bodies, hub launches, probes, catastrophic class, audit log
node tests/t-review.mjs   # the external review's 19 finding groups (paths, git, eval, hub, audit, …)
node tests/t-isolation.mjs    # deny-ACE mechanics from the README runbook (Windows)
node tests/t-install.mjs      # the installer's pre-install test gate and its --skip-tests bypass
node tests/mutation-check.mjs  # breaks the extension in 48 places and requires the suites to fail
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

- **Recovery covers the simple delete.** The rewrite to a trash move understands one sub-command with
  one delete verb whose operands the classifier resolved statically, and nothing else in the line. A
  `git reset --hard`, an `eval` loop, `rm -rf a && npm ci`, a glob or a `~` path keeps its allow and
  runs unchanged — the audit line simply carries no `recovery` field. `mv` is a rename on the same
  volume and a copy-plus-unlink across volumes, so a target on another drive is recovered more slowly.
- **The loop is a judgement, not a proof.** The checker can still be talked into an `allow` by a
  plausible-sounding justification; what the guard adds is that at least one *claim* has to survive its
  own check, that the same operation is only repeated once, that the whole thing is bounded per
  session, and that exempt rules never enter it at all. `verify.level: off` removes the claim check and
  leaves the model's confidence as the only signal — it is a deliberate setting, not a default.
- **`user_authorized` is a substring check** against the last twelve user messages. It proves the user
  named the target, not that they authorized this call; a message that mentions the path for another
  reason counts as well.
- **Erosion re-checks `committed` claims only**, once, at the next tool call. A claim that becomes
  false later in the session (or a claim that was never `committed`) leaves no trace.
- **`dc_justify` is not a promise.** It records what the agent says; the guard decides whether the
  record is worth anything, and a record that names a target the classifier did not resolve never
  matches the call.

- `write` is guarded by classification, not by a sandbox: a credential store, a system tree or a path
  outside the project is caught through `bash`, `eval` and the file tools, and a target the guard
  cannot resolve is a `dynamicTargets` violation. An ordinary edit inside the project stays free.
- The write-verb list is a whitelist, not a proof of completeness. Everything outside it is invisible
  as a *write*: PowerShell cmdlets (`Set-Content`, `Out-File`, `Copy-Item`), `mkdir`/`touch`,
  `python -c "open(…,'w')"` and `node -e`, `find … -exec <writer> {} \;`, `cpio`/`pax`/`7z x -o`,
  `git checkout` writing a worktree, and any script whose reader is not a shell. A shell body is read
  (`powershell -NoProfile -Command "…"`), so a redirect inside it is judged, but the verb inside it
  still has to be one the list knows. Adding a verb means adding a row to the write tests with it.
- A hard link is a second name for one file and `realpath` cannot see through it: `mklink /H` and
  `New-Item -ItemType HardLink` are covered as *link creation* (both ends are classified), but a link
  that already exists when the session starts is judged as the ordinary file it is spelled as.
- Paths are resolved with `realpathSync` through the nearest existing ancestor, so a junction or
  symlink is judged where it lands. Only paths the filesystem resolved are cached (15 s); the
  ancestor walk for a path that does not exist yet runs again on every call, and a link created
  between two calls is picked up by the second one. A link swapped in *after* a path was resolved
  keeps the earlier verdict for up to the TTL.
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
