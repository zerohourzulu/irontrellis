# The resident guard (experimental, off by default)

This page belongs to the [hooks package](../../packages/hooks/README.md). Read its same-user limit first: everything there applies here too.

`irontrellis-hook daemon` keeps the history open in one long-running process of your own user, so a tool call no longer pays for a Node start and a verifying open of the history. The host then runs `irontrellis-hook-client <agent> <event>` in place of `irontrellis-hook <agent> <event>`: the same arguments, the same input, the same answers. The client never decides anything itself. Whenever the daemon can't answer (it isn't running, the socket isn't yours alone, a timeout, a reply it can't read), the client runs this package's `irontrellis-hook` and passes on its answer.

| One allowed tool call on a 10,000-event history, as a host runs it (an 8-core arm64 Linux VM, Node 24.19, 1 Nov 2026) | Median |
|---|---|
| today's hook (`irontrellis-hook`) | 493 ms |
| the daemon, with the Node client (`irontrellis-hook-client`) | 22 ms |
| the daemon, with the C client (`contrib/irontrellis-hook-client.c`, which you build yourself) | 3.2 ms |

On that machine the Node client is about 22 times faster than today's hook, but only the C client meets the 20 ms budget for a hook decision. An empty Node process alone took 15 ms there.

To try it:

1. Start it: `irontrellis-hook daemon` runs in the foreground until Ctrl-C or SIGTERM. The socket is `IRONTRELLISD_SOCKET` if set, else `$XDG_RUNTIME_DIR/irontrellis/irontrellisd.sock`, else `~/.irontrellis/run/irontrellisd.sock`. The socket's directory must be yours alone (mode 700), and every directory above it yours or root's and not writable by others (a sticky root directory such as `/tmp` is fine). On systems whose umask leaves your own directories group-writable, use `XDG_RUNTIME_DIR` or set `IRONTRELLISD_SOCKET` on both sides.
2. Point the host at the client: in `.claude/settings.json`, replace `irontrellis-hook` in the entries `install` wrote with `irontrellis-hook-client` (by absolute path, as `install` writes it). `irontrellis doctor` reports such an entry as unrecognized while the guard is experimental.
3. For the C client, build it from a checkout with `cc -O2 -o irontrellis-hook-client packages/hooks/contrib/irontrellis-hook-client.c`, and set `IRONTRELLISD_FALLBACK` to the absolute path of `irontrellis-hook`, so a stopped daemon costs speed, not the check. Without `IRONTRELLISD_FALLBACK`, the C client refuses a call the daemon can't answer.

What it keeps, and what it changes:

* **Every answer is the hook's.** The same code decides every event. A test plays allow, deny and ask, the protective rules, malformed input, changes made by the owner outside the guard and an unreadable anchor log through the hook and through each client, and compares every reply byte for byte. It is a release gate.
* **Fresh state.** The daemon reopens the history with the full verifying open whenever any file named like the history, or the witness policy file, changes, its own writes included.
* **Engine settings are the daemon's own.** `IRONTRELLIS_WITNESS_POLICY`, `IRONTRELLIS_CHALLENGE_PROFILE` and `SSH_AUTH_SOCK` come from the daemon's environment. A client with other values is answered by the hook instead. A client sends only the variables the hook reads.
* **Same user only, so no new boundary.** The daemon runs as you, so the hooks README's same-user limit applies in full, and it holds the owner key in memory for its whole life instead of for one call. Running it under a separate OS user, the real security gain, needs a peer-identity check that Node doesn't offer, so that mode is not in this release.
* Unix sockets only, so not on Windows.
