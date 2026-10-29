# The IronTrellis™ plugin for Claude Code

This plugin runs Claude Code under IronTrellis (formerly Continuity). Each session is admitted in a signed history, each tool call that changes something is checked against the grants recorded there, and a handover record is written when the session ends. It is the same guard as the hook route (`irontrellis-hook install claude-code --write`), delivered as a plugin.

**Choose one route per project.** If a project has the hook route installed, the plugin sees it and steps aside, so only one copy decides. The hook route says so when a session starts.

The plugin runs on macOS and Linux. On Windows, use the hook route.

## Install

1. Install the guard: `npm install -g @ramex-labs/irontrellis-hooks@next`.
2. In Claude Code: `/plugin marketplace add zerohourzulu/irontrellis`, then `/plugin install irontrellis@irontrellis`.
3. In each project you want guarded, set IronTrellis up: `irontrellis-hook init --agent claude-code`. This creates the history outside the project and writes `irontrellis-hook.json`.

`init` also records which node and which `irontrellis-hook` the plugin runs (`~/.irontrellis/plugin-runtime`), so the plugin never looks either up on PATH. After upgrading node or IronTrellis, run `irontrellis-hook pin-runtime` in your own terminal.

If the plugin is enabled in a project when you run `init` there, `init` sees it and says you're on the plugin route, so it doesn't suggest the hook route's install step.

## Which scope to install at

Claude Code installs a plugin at one of three scopes:

- **user**: every project you open;
- **project**: this project, for everyone who uses it (stored in its `.claude/settings.json`);
- **local**: this project, for you only (stored in `.claude/settings.local.json`).

To try IronTrellis out, install it at local or project scope, for example `claude plugin install irontrellis@irontrellis --scope local` in the project's folder. At user scope, the plugin shows its setup notice in every project you haven't set up or declined.

Re-enabling the plugin from the `/plugin` screen can install it at user scope (Claude Code 2.1.309 did so in our live check in October 2026), so check the scope afterwards. To remove it, uninstall it at the scope it has (`claude plugin uninstall irontrellis@irontrellis --scope user`, or `--scope local` in the project's folder); `/plugin` shows which.

## In a project that is not set up

When the plugin is enabled in a project without IronTrellis, it tells you when a session starts (again when you resume or clear it, not after a compaction) and asks you to choose. Type the choice in Claude Code with the `!` prefix (Claude Code then runs it as your own command), or run it in your own terminal:

1. `! irontrellis-hook choose 1` (or `choose --decline`): proceed without IronTrellis in this project. The plugin then stays silent here.
2. `! irontrellis-hook choose 2` (or `init --agent claude-code`): set IronTrellis up here, the plugin route. Then start a new session.
3. `! irontrellis-hook choose 3` (or `choose --use-hook`): use the hook route instead, then `init` and `install claude-code --write`.

If you leave without choosing, you'll see the notice again next time.

`irontrellis-hook choose --status` shows the project's setting, and `irontrellis-hook choose --reset` undoes a choice. The choice is stored per user in `~/.irontrellis/route-choices.json`, never in the project. A choice applies only to a project without IronTrellis: once a project is set up, the guard runs whatever was chosen before.

Until you choose, Claude Code's own permission rules apply: nothing is set up, so there is nothing to enforce. The agent still cannot make the choice or set IronTrellis up for you: IronTrellis refuses its `irontrellis-hook choose`, `init` and `pin-runtime`, and it suggests the `!` command to you instead.

## Seeing whether a session is guarded

`irontrellis-hook statusline` prints one line, such as `IronTrellis: guarded (plugin route)`, `IronTrellis: not set up` or `IronTrellis: declined for this project`. Right after you set a project up from inside a session, it says `guarded from the next session`. The guard admits a session when it starts, so it refuses the current session's tool calls until you start a new one. To show it under Claude Code's prompt, add this to your own `~/.claude/settings.json` (IronTrellis never writes your settings, and in a guarded project the agent cannot change them):

```json
{ "statusLine": { "type": "command", "command": "irontrellis-hook statusline" } }
```

If you already have a status line, run `irontrellis-hook statusline` from your own status line script instead.

## What the guard protects in a set-up project

In a guarded project, the agent cannot change Claude Code's own configuration; the user changes it in their own terminal. The agent may read these files but not write, delete, rename or move them:

- the Claude Code settings files: yours (`~/.claude/settings.json`, or in `CLAUDE_CONFIG_DIR`), the project's and the local one;
- `~/.claude.json` and the project's `.mcp.json`;
- every `.claude/` folder (the project's, nested ones and your `~/.claude/`), with its agents, skills, commands, hooks, plugins and the plugin cache, and any `.claude.json` or `.mcp.json`. Three folders are left out, because Claude Code itself has the agent write there: `projects/` (its memory), `plans/` and `todos/` in your Claude Code folder;
- this plugin and the installed IronTrellis packages, and the node and launcher the guard runs with. Against package managers this is best effort: `npm`, `pnpm`, `yarn` and `bun` commands that install, remove or link globally or name an IronTrellis package, and `brew` commands that change node (or upgrade everything), are refused;
- IronTrellis's own files: `irontrellis-hook.json`, the history and its keys, the session keys and `~/.irontrellis`.

Names are compared without regard to case on macOS and Windows, where the file system ignores case; on Linux a name in different case is a different file, which Claude Code does not read.

A folder that holds any of these, the history's folder among them, cannot be moved or deleted either, and `git clean` and `git stash -u` are refused. A shell command that names any of these may only read it (best effort), with programs such as `cat`, `grep`, `ls`, `jq` and `git log` or `git diff`; others are refused, and so are extracting, patching or checking out files into a folder that holds them (`tar -x`, `unzip`, `patch`, `git apply`, `git checkout`, `git switch`, `git restore`, `git stash`, `git reset --hard`). If the config disappears during a session, the session's tool calls are refused until it is back.

One exception: when you develop IronTrellis in its own checkout (its root `package.json` is the IronTrellis workspace), the guard's code inside that checkout is not protected, except under any `node_modules` folder. A project that installs IronTrellis into its `node_modules` keeps it protected.

These are tripwires, not a boundary. File tools are checked by the path they write, through symlinks. Shell commands are matched by pattern, which is best effort: a command can build a path at run time. A same-user agent with an unrestricted shell can always find another way, which is why the grants matter. The real boundary for the owner key is a separate operating-system user or a key held by a signer (see the hooks README, "Read this first: the same-user limit").

## Refusals as Claude Code shows them

A refused tool call starts "IronTrellis · DENY:", then the plain fact and, in parentheses, the code and detail. Claude Code puts its own label in front ("PreToolUse:Write hook error:", followed by the hook's command in square brackets), and after it a line saying the hook came from the irontrellis plugin. The refusal itself starts on its own line under the label. That is the guard doing its job, not a fault. When the guard times out, Claude Code says "timed out; blocking because onFailure is "block"" instead, and shows the hook's command with `${CLAUDE_PLUGIN_ROOT}` as written. The plugin's own skill, `irontrellis:irontrellis-handover`, which explains a refusal and the handover, runs without asking you; other skills are as your policy says.

## Limits

- Protective-rule refusals, such as an attempt to edit your Claude Code settings, are not recorded in 1.0.0-rc.2: the guard decides them before it opens the history, so Claude Code shows the refusal but the history holds no record of it. Refusals by the grants are recorded, bounded and best effort (see the hooks README).
- A refusal the guard records is signed with a session key, not the owner key. It carries no owner attestation, and no remote witness covers it, until the owner's next write, such as the admission of the next session.
- The guard needs the single owner key beside the history (the key file, or a reference to the signer that holds it) to admit each new session. It cannot collect co-signatures, so it can't yet be used with an owner approval policy that needs two or more signatures, or with an owner key kept offline.
- If the node, the launcher or the guard's built code (`dist/`) is deleted, or the guard crashes, both routes refuse tool calls; the other events only warn.
- The PreToolUse hook sets `"onFailure": "block"` on both routes, so a guard that times out, cannot start or fails refuses the call. Claude Code 2.1.309 honours it. Claude Code 2.1.100, 2.1.200 and 2.1.250 load the hooks file with it and run its hooks; whether a timed-out hook blocks there was not tested.
- Claude Code's ConfigChange hook could block settings edits during a session. IronTrellis does not use it yet.
- `"failOpen": true` in `irontrellis-hook.json` (off by default, and only you can set it) trades safety for availability: when the guard cannot check a tool call, the call goes to Claude Code's own permissions with a warning instead of being refused. A guard that cannot start at all still refuses.
- A script, or a `git config` textconv or filter, written earlier and run later is not seen by the shell rules.
- Extraction into a folder that holds no Claude Code configuration yet is allowed, even if that folder later becomes one.
- Archives other than tar and zip (7z, cpio, pax) are not recognised.

## The MCP gateway

The plugin does not start the IronTrellis MCP gateway. To route tools through it, register the gateway yourself with its own config (see the gateway's README).

## Licence

Apache-2.0. See LICENSE.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
