# Platforms

IronTrellis (formerly Continuity) keeps its history in ordinary files, so its promises lean on the machine underneath. The filesystem has to rename files atomically, create them exclusively, flush them to disk and make hard links. This page says where IronTrellis runs, how far each platform has been tested, and what behaves differently on Windows.

The short version: Linux and macOS are the documented development and CI targets. Windows has a CI job and its own tests, but no production experience. Wherever it runs, keep the history on a local filesystem.

## 1. Where it runs

| Platform | Status | CI jobs defined in `.github/workflows/ci.yml` |
|---|---|---|
| Linux | A documented development and CI target | `ubuntu-latest` with Node 24 and 22; the install check also on Node 22.18.0 |
| macOS | A documented development and CI target | `macos-latest` with Node 24 and 22; the install check also on Node 22.18.0 |
| Windows | A CI job and platform-specific tests exist. Count it as CI-tested only after that job's first green run, and even then it isn't production experience. | `windows-latest` with Node 24 and 22 |

The last column says which jobs exist, not that they have passed. Before you call a platform qualified for a release, check that release's CI results.

| You need | For |
|---|---|
| Node.js 22.18 or later | Every package (the `engines` field) |
| Python 3.11 or later | Only the frozen Python verifier |

The 1.0.0-rc.2 package set is larger than the older six-package deployment matrix. Treat each package's own manifest and installed-platform checks as authoritative.

**A stock Ubuntu 24.04 image needs one extra package for the install check.** The install check (`pnpm verify:install`, which runs `scripts/verify-install.mjs`) builds and installs the Python package in fresh virtual environments, and a stock Ubuntu 24.04 image lacks the module that creates them. Without it, the Python packaging step fails with "ensurepip is not available", and the steps that depend on it are skipped. Install the package first, as root or with `sudo`:

```sh
apt install python3.12-venv
```

## 2. The filesystem

Keep histories, key files and a witness's data directory on a local filesystem. IronTrellis relies on four behaviors there:

| Behavior | What relies on it |
|---|---|
| Atomic rename | A rewritten file, such as the pinned head `<history>.head`, is written beside the old one, flushed, and renamed over it. A reader sees the old file or the new one, never a mix. |
| Exclusive creation | Lock files, key files and temporary files are created only when no file of that name exists. |
| fsync | An append is flushed to disk before it counts (the store's default; its `fsync: false` option turns this off). |
| Hard links | A key file is linked into place from a finished temporary file. A stale writer lock is renamed aside, and linked back if it turns out to be another writer's. |

Network shares and cloud-synchronized folders don't provide the locking and rollback guarantees the history assumes. Keep the files an agent can write separate from authority and recovery state.

## 3. Windows: ACLs instead of modes, and full paths

On Linux and macOS, IronTrellis refuses a secret file, such as an owner key, that other users can read. On Windows, POSIX mode bits don't provide that check: `stat` reports synthetic modes, and the file's access control list (ACL) decides who can read it. So the check isn't applied there, and the protection is yours to set up.

| | Linux and macOS | Windows |
|---|---|---|
| A secret file other users can read | Refused by IronTrellis | Not detected; the directory's ACL must prevent it |

- **Set the ACLs first.** Configure each directory's ACL before any secret is created in it, so that files created later inherit it. Then check the inheritance under the real service identity. The [Windows reference](reference/operator-integrations-platforms.md#windows-specific-contracts) gives the exact `icacls` form.
- **Keep the agent's account out.** An ACL that gives the agent's own account access to an owner credential defeats the boundary.
- **Use full paths.** Windows paths must be unambiguous: `IRONTRELLIS_WITNESS_POLICY` and a gateway upstream's `command` and `cwd` must be drive-qualified (`C:\…`) or UNC (`\\server\share\…`).
- **Name programs, not wrappers.** A gateway upstream names an executable program, such as `node.exe` with the script in `args`, rather than a `.cmd` or `.bat` shell wrapper.

## 4. Processes, signals and locks

Shutdown and durability differ by platform. For the witness server (`irontrellis-witness serve`):

| | Linux and macOS | Windows |
|---|---|---|
| Graceful stop | SIGTERM or SIGINT | Ctrl+C, Ctrl+Break, or closing the console |
| Reload the admin token hashes | SIGHUP, or polling with `--reload-interval <seconds>` | Polling with `--reload-interval`, every 5 seconds by default |

On Windows, a service stop or `taskkill /F` ends the server outright, because Windows delivers no SIGTERM to a Node process. Such hard stops rely on the witness's recovery protocol.

**Locks.** A history's writer lock records its holder, and a lock held from another host is never reclaimed automatically. So:

- don't delete a lock merely because a process appears slow;
- don't assume that a reused process id identifies the original holder.

## 5. Files: line endings and byte order marks

Keep canonical history and witness files out of editors, and away from automatic line-ending conversion. If a conversion happens anyway:

| What happened to the file | Result |
|---|---|
| A history converted to CRLF line endings (by an editor, or by git's `core.autocrlf`) | It still replays to the same state, format 2 included: each record's hash covers its canonical encoding, not the line ending. |
| A UTF-8 byte order mark added at the start of a history | Refused, with a message that names it. |

This covers history files, not every transport. The repository's `.gitattributes` checks every text file out with LF line endings on every platform.

## 6. Unix socket paths

A Unix socket's path must fit in `sun_path`, which holds 104 bytes on macOS and 108 on Linux, including the terminating NUL. Two sockets therefore need a short directory:

- an ssh-agent socket (`SSH_AUTH_SOCK`);
- a protected-evidence `socketPath`, which is refused above 100 bytes.

The test helpers and `scripts/verify-install.mjs` create their sockets under `TMPDIR`, and fall back to `/tmp` when `TMPDIR` is too deep for a socket path to fit in 103 bytes. A sandbox that refuses `bind` on Unix sockets fails those tests whatever the path (`listen EPERM`, or "ssh-agent exited at start"); run them on a host that allows it.

## 7. What this page establishes, and what it doesn't

**Established:** the documented implementation paths, and finite platform tests.

**Not established:** containment on a hostile operating system, durability on every filesystem, every Windows deployment profile, or a live production qualification.

For the procedures of the profile you choose, use [OPERATOR](OPERATOR.md), [CUSTODY](CUSTODY.md), [WITNESS](WITNESS.md) and [SECURITY](SECURITY.md). To see how your own machine fares, run `pnpm -r test` and `pnpm verify:install` on it; the install check runs on Linux and macOS only.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
