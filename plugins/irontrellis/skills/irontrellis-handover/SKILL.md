---
name: irontrellis-handover
description: Explain an IronTrellis refusal to the user and hand work over cleanly when a session ends. Use when a tool call was denied by IronTrellis, or when the user asks what this session may do or what it leaves open.
---

# Working under IronTrellis

IronTrellis keeps a signed history of what this agent may do. Each tool call that changes something is checked against the grants recorded there.

## When a tool call is denied

- Tell the user plainly which action was refused and the reason IronTrellis gave (the text after "IronTrellis · DENY:"). Claude Code shows it after "PreToolUse:<tool> hook error:"; say that this is IronTrellis doing its job, not a fault.
- Do not try another route to the same effect: not another tool, a script, a different path, or a changed setting. The refusal is the owner's decision.
- If the refusal names an action on a resource (for example `write-file on repo:/home/you/app`), the history does not allow it, and its code says why (for example `NO_AUTHORITY`, `REVOKED`, `PROHIBITED` or a `BUDGET_` code). If the work needs the action, say which action on which resource it needs and what the code says, and leave the decision to the user. Grants, prohibitions and budgets are recorded by the owner, outside this session.
- If the code is `PROTECTED_PATH` or `PROTECTED_COMMAND`, no grant allows the call: it touches what IronTrellis protects (its own files, keys and commands, or Claude Code's configuration). Only the user changes those, in their own terminal.
- Any other refusal (for example `SESSION_NOT_FOUND`, `SESSION_FENCED`, `SESSION_EXPIRED` or `CONFIG_CHANGED`) is not about grants: tell the user what it says, including any step it names, such as starting a new session.

## What this session may do

The session's opening context lists the actions it may and may not take. Use it to plan, and say early when a task needs something that is not allowed.

## When the session ends

IronTrellis writes a handover record of open duties, live grants and sessions. Before you stop, summarise for the user what is finished, what is open, and anything the next session needs to know.

## Settings that are not yours

The IronTrellis config, the Claude Code hook and plugin settings, and the install-route choice belong to the user. Do not edit them, and do not run `irontrellis-hook choose`, `init` or `pin-runtime`. Only the user may: suggest they type it here with the `!` prefix (for example `! irontrellis-hook choose 1`), which runs it as their own command, or run it in their own terminal.
