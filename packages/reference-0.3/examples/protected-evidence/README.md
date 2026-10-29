# Restrict access, lose the reply, recover the case

For the next part of the story—finishing the investigation, reviewing a later report and recording a challenge—use the [investigation walkthrough](../../docs/INVESTIGATION-WALKTHROUGH.md). The command below preserves the original OPEN-duty demonstration.

An investigator sees an unexpected reader of an incident report. They ask the evidence service to close access. The service does it, but its reply gets lost. The investigator cannot tell whether the request worked. A replacement must recover the result without repeating it or inheriting extra permission.

This example uses a synthetic report. It makes real file-access decisions through a local service; it does not touch your documents, run an AI model, contact a chain, or need an API key.

From this source package, after `npm ci --ignore-scripts`:

```sh
node --experimental-strip-types examples/protected-evidence/scenario.mjs
```

Use Node 22.18+ or 24. The run takes several minutes because it writes and fully checks more than 256 events. Each printed stage includes the checks that passed. An assertion stops the run if a claim is false. The temporary case directory is printed at the end; its private `host/result.json` records the result. The example preserves the case for inspection and closes its child processes and listeners. Do not share the case directory: it contains newly generated local test credentials.

The story includes:

1. The reviewer can read the report through a private Unix socket.
2. Restriction commits, its network reply is deliberately dropped, and new reads are denied. An investigation duty stays open.
3. The original worker's one-use admission allowance is still reserved. A separate revoked restoration grant is still unusable. These checks happen while the worker is current.
4. 124 bounded metadata-review windows are granted and revoked in the same case. These are real administration records, not a regenerated history or new grants for the investigator.
5. A replacement is appointed and separately allowed to investigate. The old worker process remains alive and its new request is refused. The replacement still cannot restore access.
6. The destination restarts; a fresh coordinator process reopens the same history and retrieves the original result. Recording that result does not repeat the restriction or close the duty.
7. A separate permission allows one restoration, and the reviewer can read again.

The one-use limit counts the admitted unknown attempt. It is **not** a fabricated successful consumption or receipt. The service's signed result remains a report (`NOT_PROVEN` in Core's external-outcome vocabulary). The duty stays `OPEN`; this example does not decide that the investigation is complete.

## What protects the file?

Only the service reads the fixed bundle. Its two tools are `evidence.restrict` and `evidence.restore`, with a short reason. A worker cannot choose a file path, tool implementation, identity, credential or access level. The bundle's file names, sizes and hashes, its resource name and the reviewer credential hash determine the service identity. Restarting with a different configuration cannot silently reuse that identity. First creation requires `initialize:true` and an empty destination directory; reopen is the default and requires existing durable state. Missing restart state cannot silently reopen the bundle.

The ordered durable effect records determine access. An applied restriction and its result are committed together; there is no separate chmod or permission sidecar that could disagree. Every read checks the current durable state and immutable file bytes. A corrupt, missing or uncertain state refuses fresh reads. No writer transaction waits for a reader to finish receiving bytes.

A read authorized before closure can finish afterward. Copies already delivered cannot be recalled. This is a trusted local POSIX host profile: root, the service account, the coordinator, the kernel and filesystem remain trusted. It is not protection against a compromised host, a public HTTP service, a complete sandbox or a claim that every MCP/agent framework is contained.

## Linux account boundary

The ordinary command runs all processes as your user and **does not demonstrate OS isolation**. For the separate-account lab, an administrator provisions dedicated service, reviewer and two worker users, with the service and reviewer sharing a private socket group. Supply a JSON file mapping `service`, `reviewer`, `old` and `next` to numeric `uid` and `gid`, then run the same command as the trusted lab administrator with that file as its argument.

The launcher creates only a new `ct-h05-*` temporary directory. Bundle and destination directories are service-owned 0700; bundle files are 0400. The socket parent is service-owned 0710 and socket 0660. Reviewer config is reviewer-owned 0600 inside 0700. Coordinator history and keys are root-owned inside 0700. Workers get only a proposal IPC channel and no privileged keys or readable policy files. Both worker accounts must fail attempts to read the bundle, coordinator key, reviewer credential or history binding, fail socket access, and fail unsigned writes. Do not use production accounts or expose these listeners outside the lab.

The automated boundary tests are:

```sh
node --experimental-strip-types --test --test-concurrency=1 tests/core-0.3/protected-evidence.test.mjs
```

The injected sync failure is a deterministic fault test, not physical power-loss certification. Same-host rollback of all records is outside the profile. The finite continuation limits remain 1,024 events / 6 MiB; review-window generation is deliberately bounded.
