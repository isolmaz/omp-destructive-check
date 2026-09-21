---
name: destructive-check
description: Use when a destructive-check (dc) block stopped a bash, git, eval, edit, apply_patch or hub call, and you need to explain why it was blocked and what to do next.
---

# destructive-check: a blocked call

`destructive-check` (`/dc`) inspects destructive tool calls **before** they run, in three layers,
cheapest first:

1. **static deny** — filesystem roots, system and credential locations, catastrophic signatures. No model.
2. **static allow** — build artifacts and OS temp paths inside the project scope. No model.
3. **model** — one bounded HTTPS request for what the static layers cannot classify, ~0.2k tokens,
   1.7–3.0 s, cached per `(cwd, action)`.

Each rule is set to one of four actions: `block` (refuse — no model, no prompt), `ask` (ask the user),
`model` (ask the checker), `allow` (let it through). When a call fires several rules the **most
restrictive** action wins (ties to the higher-severity rule), so an allowed target never releases a
blocked one. `mode` (`simple`/`medium`/`hard`/`custom`) picks those actions; classification is
mode-independent.

A block looks like:

    destructive-check: <what> (mode: medium, rule: gitDestructive) — destructive git operation: …
    Do not retry this action or an equivalent one through another tool; if it is genuinely required, ask the user to change the /dc settings.

## What you do now

1. **Stop.** Do not re-issue the call, and do not reach the same effect through another tool: a different
   verb, a script file, a direct `eval`, or a `hub` launch are the same effect, and the guard covers each.
2. **Tell the user** which call was blocked (tool + action) and quote the `rule` and `detail` from the
   reason text.
3. **Ask the user how to proceed**, then wait. Do not work around the block or argue that it is safe.

There is no retry-and-justify path: a block stands until the user changes the policy.

## Reading the reason

`(mode: …, rule: …)` names the active mode and the rule that fired. Rule ids: `catastrophic` (fork bombs,
`mkfs`, `dd of=/dev/…`, `shutdown`), `systemTarget`, `protectSecrets`, `outsideDelete`, `outsideMove`,
`outsideWrite`, `insideDelete` (deletes inside the project that are not artifacts), `artifactDelete`
(`node_modules`, `dist`, temp), `dynamicTargets` (targets that cannot be resolved statically),
`gitDestructive`, `scriptExec` (script body that could not be read), `codeDelete` (delete through eval
with a computed target). `catastrophic` is denied in every mode and never reaches the checker.

A "checker could not produce a verdict" reason is a **checker failure, not a model denial** — nothing was
approved, and the real error text (HTTP status and body) is in the reason.

## What the user can do

`/dc` explains every option: `recent decisions` (last checks and their outcomes), `status` (full config
dump), `guard` (loaded-guard integrity vs the install manifest, the read-only lock, restore the `.bak`),
`audit log` (recent entries, chain verification, the log path). They can also relax a rule, switch
`protection`, add `allowed dirs`, and answer the approval prompt with "Allow once" / "Allow for this session".

## Audit log

Every decision is appended to `~/.omp/logs/destructive-check.jsonl` — one hash-chained JSON object per
line, rotating at 5 MiB. The list behind `recent decisions` dies with the session; the file outlives it.
