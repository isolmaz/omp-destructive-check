---
name: destructive-check
description: Use when a destructive-check (dc) block stopped a bash, git, eval, edit, apply_patch or hub call: why it was blocked, and how to proceed — report it to the user, or justify and repeat the same call exactly once.
---

# destructive-check (`/dc`): after a block

`/dc` inspects destructive tool calls **before** they run, in three layers, cheapest first: static deny
(filesystem roots, system and credential locations, catastrophic signatures — no model), static allow
(build artifacts and temp paths inside the project scope — no model), then one bounded model request
(~0.2k tokens, 1.7–3.0 s, cached). Each rule is set to `block`, `ask`, `model` or `allow`; `mode`
(`simple`/`medium`/`hard`/`custom`) picks them per rule, and a call that fires several rules takes the
**most restrictive** action (ties to the higher-severity rule), so an allowed target never releases a
blocked one.

## Stop, then report

1. **Stop.** Do not re-issue the call and do not reach the same effect through another tool — a
   different verb, a script file, a direct `eval` or a `hub` launch are the same effect, and all are covered.
2. **Tell the user** which call was blocked (tool + action), quoting the `mode`, `rule` and `detail`.
3. **Wait for their answer**, unless the reason invites a justification (below).

A block reads `destructive-check: <reason> (mode: medium, rule: insideDelete) — <detail>. <tail>`.
Rule ids: `catastrophic`, `systemTarget`, `protectSecrets`, `outsideDelete`, `outsideMove`,
`outsideWrite`, `insideDelete`, `artifactDelete`, `dynamicTargets`, `gitDestructive`, `scriptExec`,
`codeDelete`. A "checker could not produce a verdict" reason is a **checker failure, not a model
denial** — nothing was approved, and the real error text (status and body) is in the reason.

## The second chance

For a rule that is not exempt, a first block ends with this invitation instead of the flat refusal:

    This action is recoverable and may be intended. If it is, explain in your next message what will
    change and why that is safe (which paths, which data), then repeat the same call. A repeat without
    a concrete justification is blocked again.

`catastrophic`, `systemTarget` and `protectSecrets` are an exemption floor: no setting re-opens the
loop for them, and a repeat of one is an ordinary block. If the reason ends with `Do not retry this
action or an equivalent one through another tool; if it is genuinely required, ask the user to change
the /dc settings.`, there is no loop for that call — the rule is exempt, the authority is off, or the
budget is spent. Report the block and ask the user.

When you do see the invitation, use it **once**: write the explanation in your **next message** (what
preceded the first attempt is not a justification — it has to be new) and repeat the **same** call; or
call `dc_justify` first, then repeat the same call. `dc_justify` takes `target` (the path or name the
guard flagged; it must be one of the targets the guard resolved) and `intent` (what will change and why
that is safe), plus optional `evidence` and `policyClause`. It only records that text: it never changes
the policy and never allows anything by itself.

The checker judges the repeat, and its `allow` counts only when the guard itself verifies at least one
**claim** in the verdict — so put the checkable facts in the justification:

- `committed` — the path is committed: `git status --porcelain -- <path>` is empty and a commit exists for it.
- `ignored` — git ignores the path (`git check-ignore -q <path>` exits 0).
- `artifact` — the target is a build artifact or temp path.
- `user_authorized` — the target is named in one of the last 12 user messages.
- `resolved_targets` — your list matches exactly the targets the guard resolved.

A claim the guard cannot check is refused: it verifies nothing and no `allow` rests on it. Prose, a
missing reason or an unknown value is not a verdict either — it is blocked like any other unparsable
answer. The same operation (tool + workspace + call text) is repeated once, inside a bounded
per-session budget (both set in `/dc`); a different target or a different command is a new decision,
and a retry through another tool is still refused.

**A second block ends the loop**: `No further attempts on this operation; ask the user to confirm it
in /dc before repeating it.` — stop and ask the user.

## An approved delete

With the default recovery setting, an approved delete may come back **rewritten**: the guard revises
the input so the command moves the target into `~/.omp/dc-trash/<session>/<timestamp>/` instead of
deleting it, and the tool result says so (`destructive-check: moved <src> to <dest>`). A delete the
guard cannot express as a single move keeps its allow and runs unchanged.

## What the user has

- the `/dc` panel (or plain menu), in sections: `Simple` · `Protection` · `Coverage` ·
  `Retry & justification` · `Allowlist` · `Checker` · `UI` · `Advanced` · `Guard` · `History`;
- the approval pop-up, answered `Allow once` / `Allow for this session` / `Deny` (Esc is Deny);
- decision history (`recent decisions`, `explain a decision`) and the audit log at
  `~/.omp/logs/destructive-check.jsonl` — hash-chained, rotating, with a chain check;
- `node tools/dc-audit.mjs doctor [--json]` — the chain, the installed guard against its manifest, the
  config file and the decision counts (exit 1 when broken).

Only a human approval can become permanent; a model's justified allow is session-only.
