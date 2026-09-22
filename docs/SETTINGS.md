# destructive-check — settings

What every line of the configuration does and why it exists. The [README](../README.md) is the
overview; the deep behavior behind these keys lives in [REFERENCE.md](REFERENCE.md).

## Where settings live

`~/.omp/destructive-check.json` — created and edited by the `/dc` menu, the only configuration UI
you are expected to touch. The file is re-read without a restart: at `session_start`, on every `/dc`
open, and otherwise at most once per second (see [Freshness](REFERENCE.md#freshness-one-stat-a-second)).
A key that fails validation keeps its default and is listed in `/dc → status`.

A project may add its own `<cwd>/.omp/destructive-check.json`; it can only **tighten** the policy,
never loosen it — see *Project policy file* at the bottom of this page.

## Key reference

### Core

| Key | Default | What it does |
| --- | --- | --- |
| `enabled` | `true` | Master switch. `false` = the guard sits out the session (`dc: off`), nothing is checked. |
| `mode` | `"medium"` | Protection preset that maps every rule to an action: `simple`, `medium`, `hard`, `custom`, `readonly` — matrix in the [README](../README.md#guard-levels) and [REFERENCE](REFERENCE.md#protection-modes). |
| `rules` | `{}` | `custom` mode only: per-rule overrides like `{ "insideDelete": "ask" }`. Actions are `block`, `ask`, `model`, `allow`; the most restrictive one wins. |
| `dryRun` | `false` | Watch mode: every decision is computed and logged as `would-block`, nothing is enforced. For calibrating a policy on real traffic before arming it. |
| `logSize` | `25` | Decisions kept in memory for `/dc → recent decisions`. The audit file keeps everything regardless. |
| `preset` | `"balanced"` | Friction preset — `quiet`, `balanced`, `strict`. It *writes* the settings it stands for (allow-on-deny, retry authority, verification), so the file never disagrees with the label; `/dc` shows `custom` once you change values individually. |
| `policyNote` | `""` | Free text you write once; forwarded to the checker inside the authoritative policy block on every request (e.g. "never touch the archive folder"). |

### Coverage

| Key | Default | What it does |
| --- | --- | --- |
| `coverage.bash` | `true` | Judge shell commands (deletes, moves, redirects, write verbs, wrappers, scripts). Off = those calls are not judged at all; the gap shows up in `degraded`. |
| `coverage.eval` | `true` | Judge code passed to `eval` (delete/write APIs, embedded shell). Off = an in-process bypass channel. |
| `coverage.fileTools` | `true` | Judge `write` / `edit` / `apply_patch` paths (secrets, system files, outside-project writes, read-before-write). |
| `coverage.processes` | `true` | Judge `hub` launches (`start`/`restart` payloads). Off = processes can be spawned unjudged. |

### Scope

| Key | Default | What it does |
| --- | --- | --- |
| `allowDirs` | `[]` | Extra project roots: deletes/writes *inside* them count as in-scope. Must be absolute or `~/…`; a root, the home, `~/.omp` or a system tree is refused and reported — widening the scope to those would switch the guard off. |
| `readOnlyDirs` | `[]` | The other half: a delete or write inside these always classifies as **outside** the project, whatever `allowDirs` says. Can only narrow, never widen; it overrides an overlapping `allowDirs` entry and keeps an artifact name inside it from being treated as an artifact. |


`allowDirs` entries must be absolute

### Checker

| Key | Default | What it does |
| --- | --- | --- |
| `engine` | `"auto"` | How checker requests go out: `auto` (HTTP where the provider supports it, persistent CLI checker otherwise), `in-process` (HTTP only), `cli` (always the isolated omp checker process). |
| `provider` | `""` | Which provider the checker talks to, resolved through omp's model registry — pick it in `/dc → checker`, which lists what you are logged in to. |
| `providers` | `{}` | Per-provider model overrides: `{ "opencode-go": { "model": "deepseek-v4.1-flash" } }`. |
| `timeoutMs` | `20000` | One budget for the whole decision — both checker stages, any fallback and the second-chance request all share it; a fallback never restarts the clock. |
| `maxCommandChars` | `240` | How much action text is sent to the checker. An action that does not fit the prompt budget is a *checker failure* (ask, or block with that text) — never a verdict on a clipped command. |
| `maxPromptChars` | `1200` | Hard cap on the entire prompt, user-policy block included. The policy block gets its room first; the body is trimmed rather than the block. On the retry path the justification blocks are guarded the same way — a budget too small to carry them is a checker failure, never a verdict given without them. |
| `maxIntentChars` | `240` | How much of the agent's one-line intent is forwarded — labelled untrusted, context the checker may weigh, never evidence for a claim. |
| `maxOutputTokens` | `0` | Output cap for the reply. `0` = no cap (default): a tight cap truncates reasoning models before they emit the verdict line, and every gray-zone call then blocks. |
| `reasoning` | `"off"` | Reasoning effort requested from the checker model: `off`, `minimal`, `low`, `medium`, `high`. `off` uses the provider default. |
| `includeIntent` | `true` | Send the agent's stated intent with the check (see `maxIntentChars`). |
| `cacheEnabled` | `true` | Cache verdicts per `(cwd, action)` for the session — the static layers stay at 0 ms and repeats cost nothing. |
| `askOnDeny` | `true` | A model denial asks you (allow once / allow for session / block) instead of refusing blind. |
| `askOnError` | `true` | A checker failure (timeout, HTTP error, unparsable reply) asks you when a UI exists; headless it blocks **with the real error text** — a failure is never reported as a model denial. |
| `checker.twoStage` | `false` | Ask a one-digit pre-filter first (`0` = clearly allowed) and only pay for the detailed request when it answers `1`. Same `timeoutMs` budget; a non-digit answer is a checker failure, never an allow. |
| `checker.fastStageMaxTokens` | `512` | Output cap for that pre-filter stage. |
| `checker.includeContext` | `false` | Send the last user + assistant message wrapped in `<untrusted_context>` so the checker can weigh intent — quoted material, never instructions to follow. |
| `checker.contextMaxChars` | `600` | Cap for that context block. The action itself is never trimmed (see `maxCommandChars`). |

### Second chance (justification loop)

| Key | Default | What it does |
| --- | --- | --- |
| `retry.authority` | `"model"` | Who may open the gate on a justified repeat: `model` (checker decides, low confidence still pops up), `ask` (you decide every repeat), `off` (no loop). Cannot re-open the exempt floor. |
| `retry.maxAttempts` | `1` | Justified repeats allowed per operation. `0` disables the loop entirely. |
| `retry.sessionBudget` | `3` | Total justified repeats per session. `0` disables the loop. |
| `retry.rememberApproved` | `"session"` | How approvals are remembered: `session`, `once`, or `permanent` — and only a human answer ever becomes permanent, never a model's justified allow. |
| `retry.exempt` | `[]` | Extra rules that never enter the loop. Adds to the fixed floor (`guardSelf`, `catastrophic`, `systemTarget`, `protectSecrets`), never replaces it. |
| `justifyTool.enabled` | `true` | Offer `dc_justify` to the agent — a read-only channel that records what the agent claims; it never decides anything by itself. |
| `verify.level` | `"claims"` | How retry claims are checked: `claims` (each claim verified against the resolved target), `claims+adversarial` (plus a counterexample request for high-severity rules), `off` (model confidence only). |
| `recovery.mode` | `"justified"` | Rewrite an approved delete into a move into the trash before it runs: `justified` (only deletes a justification unlocked), `high` (every allowed delete), `off` (never). Preparation failure blocks the call. |
| `recovery.dir` | `~/.omp/dc-trash` | Trash root; every recovery gets a unique subdirectory so repeats cannot overwrite an earlier one. |
| `recovery.ttlHours` | `72` | Dirs carrying dc's ownership marker are auto-cleaned after this long; anything else is left alone. |
| `erosion.mode` | `"session"` | What happens when a verified `committed` claim turns false: `session` (retry authority drops to `ask` for the rest of the session), `log` (record it only), `off` (ignore). |

### UI

| Key | Default | What it does |
| --- | --- | --- |
| `ui.overlay` | `"auto"` | Approval surface: `auto` (pop-up where the host offers one, plain list otherwise), `always` (an overlay that cannot be drawn counts as a refusal — no silent degradation), `never` (always the plain list). |
| `ui.statusLine.location` | `"bar"` | Where the status sits: `bar` (the host's own footer segment), `belowEditor`, `aboveEditor` (one-line widget, cleared after a few seconds), `off`. |
| `ui.statusLine.detail` | `"standard"` | How much it says: `minimal` (`dc: medium`), `standard` (+ last decision), `counters` (+ session allowed/blocked counts). |
| `ui.statusLine.barSide` | `"host"` | Which side of the footer the guard's segment claims: `host`, `left`, `right`. |
| `ui.popupButtons` | all three | Which answers the pop-up offers (`allowOnce`, `allowSession`, `deny`). `deny` always stays — a pop-up that cannot refuse is not a guard. |
| `ui.sessionSummary` | `true` | One advisory summary line at session end (never asks to continue). |
| `ui.denyAbort` | `false` | Deny does more than refuse: it also aborts the turn and holds the guard on the hard preset (lockdown) until you open `/dc` again. Off by default — a user who did not ask for it is not aborted. |

### Guard

| Key | Default | What it does |
| --- | --- | --- |
| `projectPolicy.enabled` | `true` | Honour a project's own `.omp/destructive-check.json`. |
| `projectPolicy.requireTrusted` | `true` | Require a host project-trust signal before honouring that file. This host exposes no such signal, so the flag is reported as unenforceable rather than pretended — what protects you is the tighten-only merge plus the visible record of every refused entry. |

## Configuration file

`~/.omp/destructive-check.json` (created by the `/dc` menu):

```jsonc
{
  "enabled": true,
  "mode": "medium",                 // simple | medium | hard | custom | readonly
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
  "readOnlyDirs": [],                // extra READ-ONLY dirs: a delete or write inside one is outside the scope, always
  "dryRun": false,                  // watch mode: log every decision as would-block, enforce nothing
  "logSize": 25,                    // entries kept for "/dc > recent decisions"

  "preset": "balanced",             // quiet | balanced | strict — the friction preset (see below)
  "policyNote": "",                 // free text the checker receives with every request, in the policy block
  "retry": {                        // the second-chance loop (see "Second chance" above)
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
    "sessionSummary": true,         // one advisory line when the session ends
    "denyAbort": false              // the deny answer also aborts the turn and holds dc in hard mode
  },
  "checker": {
    "twoStage": false,              // one-digit pre-filter before the detailed call (same timeout)
    "fastStageMaxTokens": 512,
    "includeContext": false,        // send the last user + assistant message inside <untrusted_context>
    "contextMaxChars": 600          // cap for that block; the action itself is never trimmed
  }
}
```

`readOnlyDirs` is the other half of the scope: an entry is validated exactly like an `allowDirs` entry
(a filesystem root, the home, `~/.omp` and system trees are refused and reported), and a delete or a
write inside one classifies as **outside** the project whatever `allowDirs` says. It can only ever
narrow the delete/write scope — an entry that overlaps an allowed directory turns that directory's
deletes back into `outsideDelete`, and an artifact name (`node_modules`) inside a read-only directory is
no longer an artifact. `/dc → read-only dirs` edits it, `/dc → status` and `doctor` list it, and
`dc_inspect config` reports it with the refused entries.

`preset` writes the settings it stands for, so the file never shows a preset name that
disagrees with the values beside it: `quiet` = allow-on-deny off, retry authority off,
verification off; `balanced` = the defaults above; `strict` = allow-on-deny off, retry
authority off, adversarial verification. The panel shows `custom` when the values were
changed one by one.

## Environment overrides

These win over the file: or start with `~/`. An entry that names a filesystem root
(`C:\`, `/`), the user's home, `~/.omp` or a system tree (`C:\Windows`, `C:\Program Files*`, `/etc`,
`/usr`, `/bin`, `/var`) is **not** added to the scope: widening the guard to those would switch it off.
The check runs on the entry as written *and* on its canonical form, so a link that resolves into the
home is refused too, and `/dc → allowed dirs` (and `/dc → status`) list every refused entry with the
reason instead of leaving a setting that looks applied and is not.

Environment overrides (win over the file): `OMP_DC_DISABLE=1`, `OMP_DC_MODE`, `OMP_DC_PROVIDER`,
`OMP_DC_MODEL`, `OMP_DC_ENGINE`, `OMP_DC_TIMEOUT_MS`, `OMP_DC_DRYRUN=1` (watch mode for one session),
`OMP_DC_UI_STATUS` (`bar` / `belowEditor` / `aboveEditor` / `off` — where the status line goes for one
session), `OMP_DC_BIN` (CLI engine binary).

## Project policy file (`<cwd>/.omp/destructive-check.json`)

A project may **tighten** the policy it runs under, never loosen it:

```jsonc
{
  "rules": { "insideDelete": "block", "artifactDelete": "ask" },  // more restrictive only
  "denyPatterns": ["\\bprod-secrets\\b", "terraform destroy"],       // extra denies, regex, matched case-insensitively
  "note": "never touch the archive folder"
}
```

- `mode`, `enabled`, `coverage`, the checker settings, `allowDirs`, `timeoutMs`, `retry.*`, `ui.*` and
  any value that would make a rule **less** restrictive are refused. Each refusal is recorded with its
  reason and shown in `/dc → status`, in the `Checker` panel's *Project policy* group and in
  `dc_inspect config`. `rules.guardSelf`, `rules.projectDeny`, `rules.readonlyMutation` and
  `rules.unreadTarget` cannot be set to `allow` in **any** file (`RULE_FLOORS`).
- The merge is most-restrictive-wins, so the file cannot release a rule even in principle
  (`ruleAction()` is what every decision reads).
- `projectPolicy.enabled` turns the file off; `projectPolicy.requireTrusted` asks for a host
  project-trust signal before the file is honoured. **This host version exposes no such signal to an
  extension** (there is no `trusted`/`isProjectTrusted` field on the extension or tool context and no
  trust event), so `requireTrusted` is reported as unenforceable in `/dc → status` instead of being
  pretended. What does protect you is the tighten-only merge plus the visible record of every refused
  entry — a checked-in file cannot hand itself more rope than the human's own config.
- The file is re-read when its mtime/size changes and at `session_start`, like the shared config —
  and like the shared config, at most once per second (see [Freshness](REFERENCE.md#freshness-one-stat-a-second)).
