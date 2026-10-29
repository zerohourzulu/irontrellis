/**
 * Plain-language sentences for every error code the command can print.
 *
 * `CORE_MESSAGES` is typed against the core's `IronTrellisErrorCode` union, so
 * a code added to packages/core/src/input.ts without a sentence here fails the
 * build (`tsc`) instead of surfacing as a bare code at runtime. `CLI_MESSAGES`
 * covers the command's own codes and the engine-level codes that can reach the
 * command through the store, signer and witness layers.
 */
import type { IronTrellisErrorCode } from "@ramex-labs/irontrellis";

export const CORE_MESSAGES = {
  CAPACITY_RESERVED: "The history's capacity reserve refused this write.",
  CAPACITY_INCOMPATIBLE: "This history's capacity profile is not compatible with the requested operation.",
  CAPACITY_EVENT_LIMIT: "The event is larger than this history's per-event bound allows.",
  CAPACITY_BATCH_UNSUPPORTED: "This history does not admit batched writes.",
  CAPACITY_EXPECTED_HEAD_REQUIRED: "This write needs the expected head to be named.",
  INVALID_INPUT: "An argument is missing, malformed or refers to something the history does not know.",
  INVALID_HISTORY: "The history file is damaged, out of order or fails a signature or hash check.",
  // Kept for compatibility with Core 0.3 only: no release of the engine raises it (docs/API.md §8).
  HISTORY_LIMIT: "The history has reached a hard limit of the engine (a Core 0.3 code; this release does not raise it).",
  HISTORY_EXISTS: "A history already exists at that path; choose another path or remove it first.",
  PROFILE_MISMATCH: "The history was created under another owner, domain or policy than the one selected.",
  CLOCK_INVALID: "The host clock is behind the history's last event; nothing was written.",
  HISTORY_CONFLICT: "Another writer changed the history while this command was running; nothing was written. Run the command again.",
  POLICY_EVIDENCE_UNAVAILABLE: "The policy evidence needed for this decision is not available.",
  RUNTIME_NOT_CURRENT: "The session is not current for its agent (fenced, expired or superseded).",
  OPERATION_CONFLICT: "The same identifier was already recorded with different contents.",
  SIGNER_FAILED: "The signer did not produce a signature; nothing was written.",
  RECEIPT_UNAVAILABLE: "No usable receipt is recorded for that operation yet.",
  TRANSITION_REJECTED: "The history's rules refuse this event in the current state; nothing was written.",
  READ_UNAVAILABLE: "The history, its key file or its pinned head cannot be read.",
  WRITE_UNCONFIRMED: "The write did not complete; inspect the history file before retrying.",
  ROLLBACK_DETECTED: "The pinned head, an anchor log or a remote witness shows that events were removed or replaced after they were recorded.",
  CONTROL_AUTHORIZATION_INVALID: "A control event is unsigned or mis-signed for this history's owner keys.",
  KEY_UNAVAILABLE: "The owner key file for this history is missing or unreadable, so control events cannot be signed.",
  CAPACITY_CONTROL_ONLY: "The history is full: only revocations, terminations and lifecycle records are admitted.",
  HISTORY_FILE_LIMIT: "The history file has reached its size limit.",
  MIGRATION_UNSUPPORTED: "This history cannot be re-recorded under format 2 as it is.",
  KEY_EXISTS: "An owner key file already exists where the new history's key would go (left by an earlier or interrupted run, or planted); it is not adopted silently. Remove it, or pass --reuse-existing-key to make it the owner key.",
  ANCHOR_LOG_UNREADABLE: "An anchor log of this history exists but cannot be read, so a rollback cannot be ruled out. Repair or restore it (or archive it deliberately), then run the command again.",
  WITNESS_UNREADABLE: "The remote witness state file or the witness policy file of this history exists but cannot be read, so a rollback cannot be ruled out. Repair or restore it, then run the command again.",
  WITNESS_UNAVAILABLE: "A remote witness could not be reached, or does not hold the latest head yet. Events already recorded stay recorded; queued head statements wait in <history>.witness.json (irontrellis witness sync submits them).",
  WITNESS_SPLIT_VIEW: "A remote witness showed two versions of its log that it cannot prove consistent (a split view), so it can no longer vouch for this history. Investigate the witness, then remove it (irontrellis witness remove) or add it again deliberately.",
  WITNESS_REJECTED: "A witness refused this history or this request (a missing or wrong registration token, another verifier key, an answer that does not verify, or a statement it does not accept); nothing was recorded for it. Fix the witness policy (irontrellis witness add … --token, or witness remove), then run the command again.",
  // Format 2 (IronTrellis Core).
  FORMAT_READ_ONLY: "This history file is in an older format (or was migrated already) and opens read only; nothing was recorded. Migrate it to format 2 (irontrellis migrate) and run the command against the migrated file.",
  CHALLENGE_PROFILE_READ_ONLY: "This process runs the frozen-r2.3 challenge profile, which only verifies the frozen r2.3 conformance vectors; nothing was recorded. Unset IRONTRELLIS_CHALLENGE_PROFILE (the default is g3) and run the command again.",
  MIGRATION_MARKER_INVALID: "The migration marker beside this history names another file than the one on disk; nothing was recorded. Check which file was migrated before using either.",
  SNAPSHOT_STALE: "The engine's resume snapshot did not match the signed state root and was rebuilt by a full replay (informational).",
  CHECKPOINT_MISMATCH: "The engine refused to sign a checkpoint because the state root recomputed from its records differs from its own (a self-check that must never fire); nothing was recorded. Verify the history and report this.",
  DUTY_WRITER_REQUIRED: "A duty finding needs the two-signature writer (prepare, then attach); the one-signature route is refused.",
  CAPACITY_EXCEEDED: "The history reached a hard limit (state records or file size) or its declared record capacity; nothing was recorded. Migrate the history to continue.",
  EFFECT_LIMIT: "This intent already has the maximum number of effect records (64); nothing was recorded.",
  COUNTERPARTY_SIGNATURE_INVALID: "The counterparty's envelope signature does not verify under its registered key; nothing was recorded.",
  CLOCK_AHEAD_OF_READER: "The history's latest event is dated more than five minutes ahead of this computer's clock; enforcement denies until the clock or the history is checked.",
  SESSION_FENCED: "The runtime session belongs to an earlier control epoch of its agent; it can no longer sign.",
  OBSERVATION_DUPLICATE: "This provider event is already recorded with the same digest; nothing was written. The reconciler can advance its checkpoint.",
  TRANSITION_INVALID: "The history's replay rules refuse this event (a replay verdict); nothing was written.",
  REFUSAL_NOT_REPRODUCED: "The history's state does not decide this request the way the refusal says (it would be allowed, or refused with another code); nothing was recorded.",
  HISTORY_IDENTITY_MISMATCH: "This file is not the history this handle was configured for: its genesis line hashes to another history id.",
  ATTESTED_STATE_ROOT_MISMATCH: "An owner-signed attestation (pin or anchor log) names a state root this history does not have at that position: the owner key signed a state this history never reached. Treat it as evidence of key misuse.",
} as const satisfies Record<IronTrellisErrorCode, string>;

export const CLI_MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  USAGE: "The command line is not valid; run the command with --help.",
  UNKNOWN_COMMAND: "That command does not exist; run irontrellis --help for the list.",
  HISTORY_REQUIRED: "Name the history file with --history <file> or the IRONTRELLIS_HISTORY environment variable.",
  HISTORY_NOT_FOUND: "There is no history file at that path.",
  HISTORY_EMPTY: "The history file has no events.",
  ANCHORS_NOT_FOUND: "There is no anchor log at the path given with --anchors-file.",
  UNSUPPORTED_FORMAT: "This operation needs a format-2 history; migrate the file first (irontrellis migrate).",
  UNSUPPORTED_VERSION: "The history or witness uses a version this command does not support.",
  VERIFICATION_FAILED: "The history did not verify; see the report for the failing check.",
  HISTORY_ID_MISMATCH: "The history's id is not the one you gave: this is a different history (or a substitute), so nothing in it is established.",
  HISTORY_CHANGED: "The history file changed while it was being verified, so the identity checked first may not be the verified file's; verify a copy nothing else writes to.",
  OWNER_KEYS_MISMATCH: "The history's first owner keys are not the ones you gave: it may be a substitute signed with other keys, so nothing in it is established.",
  RECEIPT_INVALID: "The anchor target returned a receipt that cannot be recorded.",
  FILE_EXISTS: "A file already exists at that path; choose another path.",
  FILE_UNWRITABLE: "The file cannot be created at that path (a missing directory, no permission, or a name too long); nothing was recorded.",
  STORE_BUSY: "Another process holds the writer lock on this history.",
  WRITTEN_UNATTESTED: "The event IS recorded in the history (do not retry it), but the owner's signer did not attest the new head afterwards: the pin keeps the owner's attestation of an earlier head (verify notes PIN_ATTESTED_EARLIER). Run irontrellis repin once the signer answers.",
  ANCHOR_LOG_UNAVAILABLE: "The anchor target could not be reached or written; nothing was recorded.",
  ANCHOR_LOG_REJECTED: "The anchor target refused the head attestation; nothing was recorded.",
  STORE_CONFLICT: "The history head moved while this command was running; retry.",
  MIGRATED_INTENT: "This intent was admitted before the history was migrated; its recorded admission can only be re-evaluated on the legacy source archive.",
  DEMO_FAILED: "The demo scenario did not complete.",
  NO_WITNESS: "No remote witness is configured for this history or bound in it; add one with irontrellis witness add <url> --verifier-key <key>.",
  REPIN_REFUSED: "repin refused to attest the head: the pinned head or an anchor log shows that the file may have been cut back or replaced. Check the file, then run repin --accept-rollback to pin it as it is.",
});

/** How many times a write command retries after HISTORY_CONFLICT / STORE_BUSY (history.ts `withRetry`). */
export const WRITE_RETRIES = 5;

const recordOf = (value: unknown): Readonly<Record<string, unknown>> => (value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {});
/** The engine message when it says more than the bare code. */
const engineText = (code: string, message: string | undefined): string | undefined =>
  message !== undefined && message.length > 0 && message !== code ? message.replace(/\.$/, "") : undefined;

/**
 * What a pin, anchor-log or witness finding (`detail.reason` of ROLLBACK_DETECTED, ANCHOR_LOG_UNREADABLE or REPIN_REFUSED) says,
 * and how to recover from it, as two sentences.
 */
function rollbackFinding(c: Readonly<Record<string, unknown>>): { what: string; remedy: string } | undefined {
  const pin = typeof c.pinPath === "string" ? ` ${c.pinPath}` : "";
  const log = typeof c.anchorLogPath === "string" ? ` ${c.anchorLogPath}` : "";
  const position = (value: unknown): string => {
    const p = recordOf(value).position;
    return typeof p === "number" ? ` ${p}` : "";
  };
  const accept = "Check the history file, then run verify --accept-rollback (with the owner key beside the history) to re-pin it as it is.";
  switch (c.reason) {
    case "PIN_MALFORMED":
      return { what: `The pinned head file${pin} is malformed, so it cannot vouch for the history.`, remedy: accept };
    case "PIN_MISSING":
      return { what: `The history has events after genesis but its pinned head file${pin} is missing; a deleted pin hides a truncation, so the file is not trusted.`, remedy: accept };
    case "BEHIND_PIN":
      return { what: "The history file does not contain its pinned head: events were removed or replaced after they were pinned.", remedy: "Restore the latest copy, or run verify --accept-rollback to accept the file as it is." };
    case "PIN_UNATTESTED":
      return {
        what: `The pinned head file${pin} carries no owner attestation, so it cannot rule out a truncation: anyone who can write the history's directory can write such a pin for a cut-down file.`,
        remedy: "Compare the history with your latest copy and restore it if events are missing; if the file is right, run verify --accept-rollback (with the owner key beside the history) to re-pin it as it is.",
      };
    case "PIN_ATTESTATION_INVALID":
      return { what: `The pinned head file${pin} carries an attestation that is not a valid signature by this history's owner key, so it cannot vouch for the file.`, remedy: accept };
    case "PIN_ATTESTED_NOT_PREFIX":
      return {
        what: `The owner attested a head at position${position(c.attestedHead)} that this history file does not contain: events the owner vouched for were removed or replaced.`,
        remedy: "Restore the latest copy, or run verify --accept-rollback to accept the file as it is.",
      };
    case "ANCHOR_LOG_ROLLBACK":
      return {
        what: `The anchor log${log} holds an owner-attested head at position${position(c.anchoredHead)} that this history file does not contain: events were removed, or the file was replaced by an older copy.`,
        remedy: "Restore the latest copy. To accept the file as it is, run verify --accept-rollback, then archive the anchor log deliberately (readers refuse the file while the log holds heads it lacks).",
      };
    case "ANCHOR_LOG_UNREADABLE":
      return { what: `The anchor log${log} exists but cannot be read, so a rollback cannot be ruled out.`, remedy: "Repair or restore the log (or archive it deliberately), then run the command again." };
    case "WITNESS_AHEAD":
      return {
        what: `The remote witness ${typeof c.witness === "string" ? `${c.witness} ` : ""}holds an owner-signed head at position${position(c.witnessedHead)}, past the end of this history file (position${position(c.observedHead)}): events were removed, or the file was replaced by an older copy.`,
        remedy: "Restore the latest copy of the history. Nothing was written, and no statement was signed for this copy.",
      };
    case "WITNESS_FORK":
      if (typeof c.equivocationIndex === "number") {
        // docs/reference/witness-operations.md §6.1: the witness answered EQUIVOCATION to a statement signed for this copy; it recorded it as evidence and stays open.
        return {
          what: `The remote witness ${typeof c.witness === "string" ? `${c.witness} ` : ""}holds an owner-signed head at position${position(c.witnessedHead)} that differs from this history file there: the file was rewritten, replaced or rolled back while it was being written. The witness recorded the conflicting statement signed for this copy as evidence (leaf ${c.equivocationIndex}).`,
          remedy: "Restore a copy that is on the witness chain (a backup of the history and its pin), then write again: the witness keeps accepting heads that extend its latest one. This handle signs nothing more. If no copy was restored or rolled back on purpose, treat the owner key as compromised and rotate it (irontrellis owner rotate-key).",
        };
      }
      return {
        what: `The remote witness ${typeof c.witness === "string" ? `${c.witness} ` : ""}holds an owner-signed head at position${position(c.witnessedHead)} that differs from this history file there: the file was rewritten or replaced by another copy.`,
        remedy: "Restore the copy the witness holds. Nothing was written, and no statement was signed for this copy.",
      };
    default:
      return undefined;
  }
}

/** Sentences that depend on what the engine found (`context` is the error's machine-readable `detail`). */
function specific(code: string, message: string | undefined, context: unknown): string | undefined {
  const c = recordOf(context);
  const engine = engineText(code, message);
  switch (code) {
    case "INVALID_INPUT":
      if (c.reason === "POLICY_RESET") return "The owner keys in force have an owner approval policy, and this rotation would return it to the default (any one owner key signs). Nothing was written. Pass --owner-policy <file> with the policy the new keys should have (restate the current one to keep it), or --reset-policy to return to the default; irontrellis owner status shows the policy in force.";
      return engine === undefined ? undefined : `An argument is not valid: ${engine}.`;
    case "INVALID_HISTORY":
      return engine === undefined ? undefined : `The history file is damaged, out of order or fails a signature or hash check: ${engine}.`;
    case "TRANSITION_REJECTED":
      // A-172.2: the human-attestation writer pre-checks (A-109.1, A-119.4).
      if (c.reason === "ATTESTATION_EXPIRY") return `Under the human-attestation policy this write would pass an attestation's expiry (${String(c.expiresAt)}); a session may not move history time past it, so only the owner can. Nothing was written.`;
      if (c.reason === "ATTESTATION_HORIZON") return `Under the human-attestation policy this control event, with one human signer, would move history time past the attestation horizon (${String(c.horizon)}); it needs a second human signer or the head's time. Nothing was written.`;
      return engine === undefined ? undefined : `The history's rules refuse this event in the current state (${engine}); nothing was written.`;
    case "ROLLBACK_DETECTED": {
      const found = rollbackFinding(c);
      return found === undefined ? undefined : `${found.what} ${found.remedy}`;
    }
    case "WITNESS_UNAVAILABLE":
      if (c.reason === "MAX_UNWITNESSED") {
        return `${typeof c.unwitnessed === "number" ? c.unwitnessed : "Too many"} events are not yet held by the remote witnesses (the policy allows ${String(c.maxUnwitnessedEvents)}), so writes are refused until they accept the queued head statements; reads continue. Bring the witnesses back, then run irontrellis witness sync.`;
      }
      if (c.reason === "NOT_CHECKED") return "This history's witness policy requires a remote witness check before it is read (requireOnOpen), and the check could not be completed.";
      if (c.reason === "INVALID_ANSWER") {
        return `${engine ?? "A remote witness gave an answer that does not verify."} Nothing was written. An answer that does not verify (a missing or wrong signed latest note, a tampered receipt) may be an older genuine answer replayed to hide a rollback: check the network path to the witness (use https), then run the command again.`;
      }
      if (c.reason === "REGISTRATION_DENIED") {
        return `${engine ?? "A remote witness denies a registration it signed."} Owner writes and checks are refused until the witness knows the history again: ask its operator whether its data directory was restored or lost, and check the network path to it.`;
      }
      return engine === undefined ? undefined : `A remote witness could not be reached or does not hold the latest head yet: ${engine}.`;
    case "WITNESS_REJECTED":
      return engine === undefined ? undefined : `${engine}${/nothing was written|was not created/.test(engine) ? "" : "; nothing was recorded for it"}.`;
    case "ANCHOR_LOG_UNREADABLE": {
      const log = typeof c.anchorLogPath === "string" ? ` ${c.anchorLogPath}` : "";
      return `The anchor log${log} exists but cannot be read, so a rollback cannot be ruled out${engine === undefined ? "" : ` (${engine})`}. Repair or restore the log (or archive it deliberately), then run the command again.`;
    }
    case "WITNESS_UNREADABLE": {
      if (c.reason === "WITNESS_POLICY_UNREADABLE") {
        return `${engine ?? "The out-of-band witness policy file cannot be used"}. Fix the file (or the IRONTRELLIS_WITNESS_POLICY variable), then run the command again.`;
      }
      if (c.reason === "WITNESS_STATE_UNREADABLE") {
        return `The witness state file${typeof c.witnessPath === "string" ? ` ${c.witnessPath}` : ""} is malformed, so it cannot be used to rule out a rollback. Restore it, or move it aside deliberately: the remote witnesses are asked again and the history's bound witnesses stay in force.`;
      }
      return engine === undefined ? undefined : `${engine}.`;
    }
    case "REPIN_REFUSED": {
      const found = rollbackFinding(c);
      if (found === undefined) return undefined;
      if (c.reason === "ANCHOR_LOG_UNREADABLE") return `${found.what} repin attests nothing it cannot check: ${found.remedy}`;
      return `${found.what} repin did not attest this head, because that would vouch for a file that may have been cut back or replaced. Check the file against your latest copy; to pin it as it is, run repin --accept-rollback.`;
    }
    case "HISTORY_CONFLICT":
    case "STORE_BUSY": {
      if (typeof c.lockPath !== "string") return undefined;
      const holder = recordOf(c.holder);
      const who = typeof holder.pid === "number" ? ` (pid ${holder.pid}${typeof holder.hostname === "string" ? ` on ${holder.hostname}` : ""})` : "";
      const waited = code === "HISTORY_CONFLICT" ? `the command retried ${WRITE_RETRIES} times` : "the command waited for it";
      return `Another process holds the writer lock ${c.lockPath}${who}; ${waited}, and nothing was written. If no writer is running, the lock is stale: it is reclaimed once it is 60 s old and its process has exited, or remove the file.`;
    }
    case "SIGNER_FAILED":
      // A key held by a signer (ssh-agent, command): the engine's message says what the signer did and whether anything was written.
      return typeof c.signer === "string" || typeof c.reason === "string" ? engine : undefined;
    case "KEY_UNAVAILABLE":
      if (typeof c.signer === "string" || c.reason === "PUBLIC_KEY_ONLY" || c.reason === "REFERENCE_INVALID" || c.reason === "UNKNOWN_SIGNER") return engine;
      // Pre-rotation: the owner keys in force committed to a next key, and the rotation needs that key.
      if (Array.isArray(c.nextKeyDigests)) {
        if (typeof c.digest === "string") return `${engine ?? "The key given is not the committed next key"}. Nothing was written. Pass the next-key file that init, owner commit-next-key or the last rotation wrote (irontrellis owner status shows the committed digest).`;
        return `This history's owner keys committed to a next key (pre-rotation), and only that key can replace them${typeof c.nextKeyFile === "string" ? `; it is not at ${c.nextKeyFile}` : ""}. Bring the next-key file back from offline storage and run irontrellis owner rotate-key --next-key <file>. The current owner key alone cannot rotate; nothing was written.`;
      }
      return engine !== undefined && typeof c.nextKeyFile === "string" ? `${engine}. Nothing was written.` : undefined;
    case "KEY_EXISTS":
      if (c.reason === "REUSE_MISMATCH") return `${engine ?? "The existing owner key file is not a reference to the same key in the same signer"}. Nothing was written: with --reuse-existing-key and a signer, only a reference to that key in that signer is adopted.`;
      if (typeof c.keyPath === "string" && c.keyPath.endsWith(".owner-next-key.json") && /reuseExistingKey/.test(message ?? "")) {
        return `A next-key file already exists where the new history's next key would go (${c.keyPath}; left by an earlier or interrupted run, or planted); it is not adopted silently. Remove it, or pass --reuse-existing-key to commit the new history to it.`;
      }
      if (typeof c.keyPath === "string" && /(\.pending\.json|\.owner-next-key\.json)$/.test(c.keyPath)) return `${engine ?? `A key file is in the way: ${c.keyPath}`}. Nothing was written.`;
      return undefined;
    case "MIGRATION_UNSUPPORTED":
      if (c.reason === "SOURCE_UNPINNED") {
        return "The legacy source has no pinned head, so an edit or truncation of it cannot be ruled out, and migration would sign whatever it holds under the new owner key. Continuity-written histories never have a pin: check the source against a copy you trust, then pass --accept-unpinned-source.";
      }
      if (c.reason === "SOURCE_PIN_MISMATCH") {
        return `The legacy source does not match its pinned head (${String(c.pinnedHeadStatus)}); migration would sign an edited or truncated file under the new owner key. Restore the source, or pass --accept-unpinned-source to migrate it as it is.`;
      }
      return engine === undefined ? undefined : `This history cannot be re-recorded under format 2 as it is: ${engine}.`;
    default:
      return undefined;
  }
}

/**
 * The sentence for a code. `message` is the engine's message and `context` its
 * `detail`: some codes (INVALID_INPUT, INVALID_HISTORY, TRANSITION_REJECTED, ROLLBACK_DETECTED,
 * ANCHOR_LOG_UNREADABLE, WITNESS_UNREADABLE, REPIN_REFUSED, HISTORY_CONFLICT with a held lock, MIGRATION_UNSUPPORTED) get a sentence that
 * names what the engine found. Unknown codes get the engine's message, or a
 * generic sentence.
 */
export function describe(code: string, message?: string, context?: unknown): string {
  const found = specific(code, message, context);
  if (found !== undefined) return found;
  const known = (CORE_MESSAGES as Readonly<Record<string, string>>)[code] ?? CLI_MESSAGES[code];
  if (known !== undefined) return known;
  return message !== undefined && message.length > 0 && message !== code ? message : "The command failed.";
}
