# @ramex-labs/irontrellis-hooks

`irontrellis-hook` runs Claude Code, OpenAI Codex CLI and Cursor sessions under IronTrellis (formerly Continuity): each session is admitted in a signed history, each side-effecting tool call routed through the hook is checked against the recorded grants, and a handover record is written at the end.

## Read this first: the same-user limit

On one OS user there is no hard boundary between the agent and the owner key: anything the agent can run can read the key and record grants the owner never made, and the history verifies clean. **Under the default layout, a run-shell grant is equivalent to owner authority**, so `init --allow run-shell` needs `--i-understand-same-user-risk`. A real boundary is a key the agent's user cannot use: a separate OS user for the hook and its state, or a signer the agent cannot reach (docs/CUSTODY.md). This package sets up neither; the protective rules (below) are only a tripwire.

The hook needs the single owner key beside the history (`<history>.owner-key.json`: a key file, or a reference to a signer) to admit each new session. It cannot collect co-signatures, so in 1.0.0-rc.2 it can't be used with an owner approval policy that needs two or more signatures, or with an owner key kept offline.

## 60-second quickstart

```sh
npm install -g @ramex-labs/irontrellis-hooks@next
cd /work/app
irontrellis-hook init --agent claude-code --allow write-file --expires +7d
irontrellis-hook install claude-code --write          # adds the hooks to .claude/settings.json
irontrellis-hook check claude-code Write --input '{"file_path":"/work/app/a.txt"}'   # DEFER … ALLOW
irontrellis-hook check claude-code Bash --input '{"command":"npm test"}'             # DENY  ACTION_NOT_ALLOWED
```

`init` creates, by default outside the project in `~/.irontrellis/projects/<hash>/` (0700), a format-2 history with its owner key, the agent, its role and appointment and the hook's connector session (below); the project gets `irontrellis-hook.json`. `--allow` records one grant on `repo:<project>`; otherwise grant with the CLI (`init` prints the path):

```sh
irontrellis --history ~/.irontrellis/projects/<hash>/history.jsonl grant g1 --to claude-code --actions write-file --resources repo:/work/app --expires +7d
```

`init --history <file>` reuses a format-2 history with the same owner and controller; a legacy or format-1 one must be migrated first.

## What happens at each event

| moment | what the hook does | writes |
|---|---|---|
| session start | Creates the agent, role and appointment if missing; admits `session:<host session id>` with a fresh key in `<history>.sessions/` (only the public key enters the history). A second session of the agent is **not admitted** until the first ends or is released; one started after that is admitted and fences it. | admission (and epoch advance) |
| tool call | Protective rules, then the session check (`SESSION_NOT_FOUND`, `SESSION_FENCED`, `SESSION_EXPIRED`), then the policy maps the tool to an action and resource. Read-only tools: no decision. ALLOW → no decision (the host's own check runs); DENY → deny; INDETERMINATE or unmapped → ask, or `askFallback` (deny) where the host cannot ask. | a refusal for a deny by the grants or without a session (below); none for a protective-rule deny |
| stop / session end | Writes the handover record (open duties, live grants, sessions, tenures); at the end, releases the session key. Revokes nothing. | nothing |

`"decisions": {"onAllow": "allow"}` lets an ALLOW skip the host's own prompt, leaving the grant as the only check. Unreadable events, missing histories and replay errors are refused (exit 2); with `"failOpen": true` (off by default) they go to the host's own permissions with a warning (on Cursor they stay refused), but a protective-rule refusal never does.

## Refusal records

The verdict comes first, then the record:

| deny | recorded as |
|---|---|
| by the grants, when the rule's resource renders tool input (`${file_path}`, `${command}` …) | a CONNECTOR refusal: the template and a sha256 of the rendered request (the text stays in a deletable side log, `<history>.refusals.rendered.log`) |
| by the grants, otherwise | a CORE (or BUDGET) refusal signed by **the agent's own session**; replay decides it again |
| of an agent with no current session | a CONNECTOR refusal |
| by a protective rule | nothing in 1.0.0-rc.2: those rules decide before the history is opened |

CONNECTOR refusals are signed by the hook's own **connector session** (agent `hooks:<host>`), which signs nothing else: they mean "the hook says so", not that the agent signed. Neither session key is the owner key, so a recorded refusal has no owner attestation or witness statement until the next owner write, such as the next session's admission.

Recording waits about `recordBudgetMs` (250 ms), shared with the drain of refusals spooled before it (plus one read and one rewrite of the spool and a write in progress; not a hard real-time bound): a slower write is spooled and recorded, decided again, with a later recorded refusal (allowed calls do not drain the spool), and a hook that cannot record in time still denies. That budget plus opening the history must fit well inside the host's 30 s `PreToolUse` timeout.

## Configuration: `irontrellis-hook.json`

Found through `IRONTRELLIS_HOOK_CONFIG` or by walking up from the working directory. No secret, but whoever edits it decides what is checked.

```json
{
  "version": "irontrellis-hook-config/1",
  "history": "/home/you/.irontrellis/projects/3f1c9a0b7d2e4c61/history.jsonl",
  "historyId": "0x…",
  "owner": "principal:owner", "controller": "controller:irontrellis-hook",
  "agentId": "claude-code", "roleId": "role:coding-agent", "protocol": "claude-code",
  "connector": { "agentId": "hooks:build-host" },
  "sessionTtlMs": 86400000, "askFallback": "deny", "failOpen": false,
  "decisions": { "onAllow": "defer", "onReadOnly": "defer" },
  "policy": {
    "sideEffecting": [
      { "tool": "Bash",   "action": "run-shell",  "resource": "repo:${project}" },
      { "tool": "Write",  "action": "write-file", "resource": "repo:${project}" },
      { "tool": "mcp__*", "action": "call-mcp",   "resource": "mcp:${server}" }
    ],
    "readOnly": ["Read", "Grep", "Glob", "WebSearch"],
    "unmapped": "ask"
  }
}
```

* `historyId` (written by `init`): a file whose first record hash differs is refused (`HISTORY_IDENTITY_MISMATCH`).
* `policy.sideEffecting`: the first matching rule wins; `resource` is a template over `${project}`, `${cwd}`, `${tool}`, `${server}`, `${mcpTool}` and top-level string fields of the tool input.
* `enforceFromReadOnlyHistory`: set by hand only, to enforce from a never-migrated legacy or format-1 history; every open warns and no session is admitted, so every tool call is denied (`FORMAT_READ_ONLY`). A fenced history is refused regardless.

## Protective rules

They run first and cannot be configured away. A tool call that names the history or any file sharing its name (pin, lock, keys, connector key, sessions, handovers), the hook config, key references or the out-of-band witness policy is refused (`PROTECTED_PATH`; paths are resolved against the cwd and through symlinks). So is a write to a host's own configuration, so an agent cannot switch its hooks off for a later session: Claude Code's (`.claude/`, `.mcp.json`, `~/.claude`, `~/.claude.json`), Codex's (the project's `.codex/`, and `config.toml` and `hooks.json` in `CODEX_HOME` or `~/.codex`) and Cursor's (`.cursor/`, `~/.cursor/hooks.json`). So is a shell call that runs `irontrellis`, `irontrellis-hook` or `irontrellis-mcp-ops` with a writing subcommand (`PROTECTED_COMMAND`), also through `npx`, `env`, `sudo`, `$(…)` and quoting, and, with the owner key in an ssh-agent or Vault, `ssh-add` and `vault`. They match text: a variable, an alias or an earlier script still gets past them. The boundary is owner-key custody.

## Hosts

| host | settings file `install --write` edits | notes |
|---|---|---|
| Claude Code | `.claude/settings.json` | `SessionStart`, `PreToolUse`, `Stop`, `SessionEnd`; "no decision" is exit 0 with no output |
| OpenAI Codex CLI | `.codex/hooks.json` | same wire shape; "ask" is not supported, so it becomes `askFallback` |
| Cursor | `.cursor/hooks.json` | `sessionStart`, `beforeShellExecution`, `beforeMCPExecution`, `preToolUse`, `stop`, `sessionEnd`; installed with `failClosed: true`; "no decision" is sent as `allow` |

`install` prints the entries; `--write` merges them atomically, changing only IronTrellis's own entries, and `--dry-run` shows the diff. It refuses a file it cannot merge safely, or one with `"disableAllHooks": true` (unless `--allow-disabled`). Use `--command "npx --no-install irontrellis-hook"` if the host's PATH lacks the bin. `install codex` and `install cursor` write the bare `irontrellis-hook`, so a program earlier on PATH can stand in for the guard.

### Codex: the first run

After `init --agent codex` and `install codex --write`, Codex needs two things once per project, and until then runs no hooks:

1. **Trust the folder** when Codex asks.
2. **Review the hooks:** type `/hooks`, check that the four IronTrellis hooks in `.codex/hooks.json` each run `irontrellis-hook codex <Event>`, and trust them (`t`).

Two Codex settings can still leave the project unguarded:

- **Hooks turned off:** `[features] hooks = false` (or the older `codex_hooks`) in `~/.codex/config.toml` or the project's `.codex/config.toml` stops all hooks: nothing is checked or recorded, and nothing warns you during the session. A live check on 23 October 2026 (Codex 0.163.0) saw a write the grants did not allow go through unrecorded. `init --agent codex` and `irontrellis doctor` (`HOOKS_DISABLED`) warn about the setting: run `doctor` after changing Codex's config. In a guarded project the agent cannot change these files.
- **A hook that times out:** Codex 0.163.0 lets the call through when a PreToolUse hook times out; `install codex` gives PreToolUse 120 seconds.

## Remote witnesses

The hook uses the history's bound witnesses and `<history>.witness.json`. A history rolled back behind a witness is refused (`ROLLBACK_DETECTED`), and `IRONTRELLIS_WITNESS_POLICY` adds an out-of-band minimum; docs/WITNESS.md says when each applies.

## Cost per call

Each call is a separate process that replays the history from a valid snapshot, else from the start. At 10,000 events a check takes about a second (docs/BENCHMARKS.md). Keep histories small.

## Limitations

* Only calls routed through the hook are checked; a call the host makes without asking, or a token the agent already holds, is outside it.
* Allowed calls are not recorded; use the gateway or runtime API for receipts. Hook checks never charge a budget.
* Grants are coarse by default (`repo:<project>`); the hook does not classify shell commands.
* One live session per agent; one that ended without a SessionEnd blocks the next until it expires or `session release` frees it.

## Commands

```
irontrellis-hook <agent> <event>
irontrellis-hook init [--agent a] [--dir p] [--history p] [--owner id] [--controller id] [--agent-id id] [--role id] [--allow a,b] [--expires t] [--i-understand-same-user-risk] [--force] [--verbose] [--json]
irontrellis-hook install <agent> [--dir p] [--command cmd] [--replace-command cmd] [--allow-disabled] [--write | --dry-run] [--json]
irontrellis-hook check <agent> <tool> [--input json] [--dir p] [--json]
irontrellis-hook session list [--dir p] [--json]
irontrellis-hook session release <host-session-id> | --all [--dir p]
irontrellis-hook choose 1 | 2 | 3 | --status | --decline | --use-hook | --reset [--dir p]
irontrellis-hook statusline [--dir p]
irontrellis-hook pin-runtime
irontrellis-hook plugin claude-code <event>
```

`check` evaluates one call without a host or the session check. Depends on `@ramex-labs/irontrellis` only. Apache-2.0.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
