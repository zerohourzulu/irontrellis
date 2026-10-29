/**
 * The local evidence-packet executor (port of Core 0.3 `adapters/packet-executor.mjs`):
 * copies a fixed, pre-selected set of files into a protected attempt directory
 * and retains an exact manifest + acknowledgment. Trusted local filesystem with
 * explicit path/link checks; not hostile-host isolation.
 */
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, mkdirSync, opendirSync, openSync, readSync, writeFileSync } from "node:fs";
import { dirname, join, parse, resolve, sep } from "node:path";
import { createHash } from "node:crypto";
import { canonicalEncode, captureValue } from "../canonical.ts";
import {
  LOCAL_EVIDENCE_PACKET_ADAPTER_ID, adapterAcknowledgmentEvidence, approvedAdapterProfile, createAdapterAcknowledgment, validateAdapterAcknowledgment,
  type AdapterAcknowledgment, type AdapterExternalEvidence,
} from "../adapter-editions.ts";
import type { AdapterIdentityResult } from "../admission.ts";
import { admittedSubmissionIdentity, type AdapterSubmissionResult, type AdmittedSubmissionFields, type AdmittedTransactionSubmission } from "../coordinators.ts";
import type { AdapterProfile, AuthorizationDomain, AuthorizationProof, ContentHash } from "../types.ts";

const VERSION = "0.2";
const ATTEMPT = `continuity-local-packet-attempt/${VERSION}`;
const MANIFEST = `continuity-local-packet-manifest/${VERSION}`;
const ACK = `continuity-local-packet-ack/${VERSION}`;
const NAME = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const HASH = /^0x[0-9a-f]{64}$/;
const FILE_BYTES = 65_536;
const TOTAL_BYTES = 262_144;
const RECORD_BYTES = 16_384;

export type EvidenceSelection = readonly Readonly<{ name: string; bytes: number; sha256: string }>[];
export type PacketExecutorOptions = Readonly<{
  inputDirectory: string; outputDirectory: string; selection: EvidenceSelection; termsCommitment: ContentHash; resource: string; domain: AuthorizationDomain; intentId: string;
}>;
export type PacketInspection =
  | Readonly<{ status: "PACKET_VERIFIED"; manifestSha256: string; manifest: Rec; files: EvidenceSelection; acknowledgment: AdapterAcknowledgment }>
  | Readonly<{ status: "OUTCOME_UNKNOWN"; reason: string }>;
type Rec = Record<string, unknown>;
type Unknown = Extract<AdapterSubmissionResult, { status: "OUTCOME_UNKNOWN" }> | Readonly<{ status: "OUTCOME_UNKNOWN"; reason: string }>;

function fail(message: string): never { throw new Error(message); }
const sha256 = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");
const equal = (a: unknown, b: unknown): boolean => canonicalEncode(a) === canonicalEncode(b);
const jsonBytes = (value: unknown): Buffer => Buffer.from(JSON.stringify(value) + "\n");
const isRecord = (v: unknown): v is Rec => v !== null && typeof v === "object" && !Array.isArray(v);
const exactKeys = (value: unknown, keys: readonly string[]): value is Rec =>
  isRecord(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));

function lexicalDirectory(path: string): string {
  // Windows accepts both separators, so both split a component there.
  if (typeof path !== "string" || path.length === 0 || path.includes("\0") || path.split(sep === "\\" ? /[\\/]/ : sep).includes("..")) fail("Invalid directory path");
  return resolve(path);
}
function directory(path: string): string {
  const absolute = lexicalDirectory(path), root = parse(absolute).root;
  let current = root;
  for (const component of absolute.slice(root.length).split(sep).filter(Boolean)) {
    current = join(current, component);
    const stat = lstatSync(current);
    if (stat.isSymbolicLink() || !stat.isDirectory()) fail("Directory path must not contain a symlink or non-directory");
  }
  return absolute;
}
function entries(path: string, maximum: number): string[] {
  directory(path);
  const handle = opendirSync(path), result: string[] = [];
  try {
    for (let entry = handle.readSync(); entry !== null; entry = handle.readSync()) {
      result.push(entry.name);
      if (result.length > maximum) fail("Too many directory entries");
    }
  } finally { handle.closeSync(); }
  return result.sort();
}
function readRegular(path: string, maximum: number): Buffer {
  directory(dirname(path));
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > maximum) fail("Expected bounded regular non-linked file");
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev || opened.ino !== before.ino || opened.size > maximum) fail("File identity changed");
    const buffer = Buffer.alloc(maximum + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = readSync(fd, buffer, length, buffer.length - length, null);
      if (count === 0) break;
      length += count;
    }
    const after = fstatSync(fd), named = lstatSync(path);
    if (length > maximum || length !== opened.size || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs ||
        after.nlink !== 1 || named.isSymbolicLink() || named.dev !== opened.dev || named.ino !== opened.ino) fail("File changed during bounded read");
    return buffer.subarray(0, length);
  } finally { closeSync(fd); }
}
function selectionValue(value: unknown): EvidenceSelection {
  const stable = captureValue(value);
  if (!Array.isArray(stable) || stable.length < 1 || stable.length > 8) fail("Select between one and eight files");
  let total = 0, previous: string | undefined;
  for (const item of stable as readonly unknown[]) {
    if (!exactKeys(item, ["name", "bytes", "sha256"]) || typeof item.name !== "string" || !NAME.test(item.name) || !Number.isSafeInteger(item.bytes) ||
        Object.is(item.bytes, -0) || (item.bytes as number) < 0 || (item.bytes as number) > FILE_BYTES || typeof item.sha256 !== "string" || !DIGEST.test(item.sha256) ||
        (previous !== undefined && previous >= item.name)) fail("Invalid ordered file selection");
    previous = item.name;
    total += item.bytes as number;
  }
  if (total > TOTAL_BYTES) fail("Selected files exceed aggregate byte limit");
  return stable as EvidenceSelection;
}

/** Enumerate and hash the (at most eight) files of an input directory in name order. */
export function selectInput(inputDirectory: string): EvidenceSelection {
  const root = directory(inputDirectory), names = entries(root, 8);
  return selectionValue(names.map((name) => {
    if (!NAME.test(name)) fail("Invalid selected basename");
    const bytes = readRegular(join(root, name), FILE_BYTES);
    return { name, bytes: bytes.length, sha256: sha256(bytes) };
  }));
}
function syncDirectory(path: string): void {
  directory(path);
  // Windows cannot open a directory for fsync (NTFS journals directory changes itself): skipped there (../platform.ts).
  if (process.platform === "win32") return;
  const fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}
function writeExclusive(path: string, bytes: Buffer): void {
  directory(dirname(path));
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeFileSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
  syncDirectory(dirname(path));
}
function readRecord(path: string): { value: unknown; bytes: Buffer } {
  const bytes = readRegular(path, RECORD_BYTES);
  const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  // Our retained JSON spelling is exact: duplicate keys/trailing material are invalid.
  if (!bytes.equals(jsonBytes(value))) fail("Non-exact retained record encoding");
  return { value, bytes };
}

export type PacketExecutor = Readonly<{
  adapterProfile: AdapterProfile;
  submit(submission: AdmittedTransactionSubmission): Promise<AdapterSubmissionResult>;
  reconcile(submission: AdmittedTransactionSubmission): AdapterSubmissionResult;
  inspect(): PacketInspection;
}>;

export function createPacketExecutor(options: PacketExecutorOptions): PacketExecutor {
  const { inputDirectory, outputDirectory, selection, termsCommitment, resource, domain, intentId: configuredIntentId } = options;
  const adapterProfile = approvedAdapterProfile(LOCAL_EVIDENCE_PACKET_ADAPTER_ID);
  const expectedDomain = captureValue(domain) as AuthorizationDomain;
  if (!isRecord(expectedDomain) || (expectedDomain.version !== VERSION && expectedDomain.version !== "1" && expectedDomain.version !== "2") || typeof configuredIntentId !== "string" || configuredIntentId.length === 0) fail("Missing fixed executor domain/intent");
  // Retained packet inspection must not depend on mutable original inputs; selectInput/first submit performs the actual input directory/link checks.
  const input = lexicalDirectory(inputDirectory), output = directory(outputDirectory);
  if (input === output || input.startsWith(output + sep) || output.startsWith(input + sep)) fail("Input and output directories must be disjoint");
  const selected = selectionValue(selection);
  if (typeof termsCommitment !== "string" || !HASH.test(termsCommitment) || typeof resource !== "string" || resource.length < 1 || resource.length > 256 ||
      Buffer.byteLength(resource) > 256 || /[\u0000-\u001f\u007f]/u.test(resource)) fail("Invalid executor terms or resource");
  const packet = join(output, "packet"), files = join(packet, "files");
  const record = (schemaVersion: string, identity: AdapterIdentityResult, intentId: string): Rec => ({
    schemaVersion, idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint, intentId, selection: selected, termsCommitment, resource, adapterIdentity: identity,
  });
  const acknowledgment = (identity: AdapterIdentityResult, digest: string): AdapterAcknowledgment => createAdapterAcknowledgment(identity, `0x${digest}`);
  const evidence = (identity: AdapterIdentityResult, ack: AdapterAcknowledgment): AdapterExternalEvidence => adapterAcknowledgmentEvidence(identity, ack);
  const unknown = (reason: string, identity?: AdapterIdentityResult): Unknown => Object.freeze(identity !== undefined
    ? { status: "OUTCOME_UNKNOWN" as const, idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint }
    : { status: "OUTCOME_UNKNOWN" as const, reason });

  function retainedAttempt(): Rec & { adapterIdentity: AdapterIdentityResult; intentId: string; idempotencyKey: string; submissionFingerprint: string } {
    const { value } = readRecord(join(output, "attempt.json"));
    if (!exactKeys(value, ["schemaVersion", "idempotencyKey", "submissionFingerprint", "intentId", "selection", "termsCommitment", "resource", "adapterIdentity"]) ||
        value.schemaVersion !== ATTEMPT || typeof value.idempotencyKey !== "string" || !HASH.test(value.idempotencyKey) ||
        typeof value.submissionFingerprint !== "string" || !HASH.test(value.submissionFingerprint) ||
        typeof value.intentId !== "string" || value.intentId.length < 1 || Buffer.byteLength(value.intentId) > 256 || !isRecord(value.adapterIdentity) ||
        !equal(value, record(ATTEMPT, value.adapterIdentity as AdapterIdentityResult, value.intentId)) ||
        value.intentId !== configuredIntentId || value.adapterIdentity.intentId !== configuredIntentId || !equal(value.adapterIdentity.domain, expectedDomain) ||
        !equal(value.adapterIdentity.adapterProfile, adapterProfile)) fail("Attempt identity/configuration mismatch");
    return value as Rec & { adapterIdentity: AdapterIdentityResult; intentId: string; idempotencyKey: string; submissionFingerprint: string };
  }

  function inspect(): PacketInspection {
    try {
      if (!equal(entries(output, 3), ["ack.json", "attempt.json", "packet"])) fail("Missing or unexpected output entries");
      const attempt = retainedAttempt();
      if (!equal(entries(packet, 2), ["files", "manifest.json"]) || !equal(entries(files, 8), selected.map((item) => item.name))) fail("Packet file membership mismatch");
      const { value: manifest, bytes: manifestBytes } = readRecord(join(packet, "manifest.json"));
      if (!equal(manifest, record(MANIFEST, attempt.adapterIdentity, attempt.intentId))) fail("Manifest does not bind the retained attempt");
      for (const item of selected) {
        const bytes = readRegular(join(files, item.name), FILE_BYTES);
        if (bytes.length !== item.bytes || sha256(bytes) !== item.sha256) fail("Packet file hash mismatch");
      }
      const manifestSha256 = sha256(manifestBytes);
      const { value: ack } = readRecord(join(output, "ack.json"));
      const typed = acknowledgment(attempt.adapterIdentity, manifestSha256);
      if (!validateAdapterAcknowledgment(typed, attempt.adapterIdentity) || !equal(ack, { schemaVersion: ACK, idempotencyKey: attempt.idempotencyKey,
        submissionFingerprint: attempt.submissionFingerprint, manifestSha256, acknowledgment: typed, evidence: evidence(attempt.adapterIdentity, typed) })) fail("Acknowledgment mismatch");
      return Object.freeze({ status: "PACKET_VERIFIED", manifestSha256, manifest: manifest as Rec, files: selected, acknowledgment: typed });
    } catch (error) { return unknown(error instanceof Error ? error.message : "Retained packet unavailable") as PacketInspection; }
  }

  /** The coordinator's submission carries the durable state: the identity is read from it, never by replaying `admittedHistory`. */
  function captureSubmission(submission: unknown): { stable: AdmittedSubmissionFields; identity: AdapterIdentityResult } {
    const { submission: stable, identity } = admittedSubmissionIdentity(submission);
    if (!equal(identity.adapterProfile, adapterProfile) || !equal(identity.domain, expectedDomain) || identity.intentId !== configuredIntentId) fail("Submission differs from fixed executor profile/domain/intent");
    const request = (stable.admissionEvent.data.authorizationProof as AuthorizationProof).request;
    if (request.action !== "collect-evidence-packet" || request.resource !== resource || request.termsCommitment !== termsCommitment) fail("Admitted request does not match the configured executor");
    return { stable, identity };
  }

  function retained(identity: AdapterIdentityResult, intentId: string): AdapterSubmissionResult {
    let attempt: ReturnType<typeof retainedAttempt>;
    try { attempt = retainedAttempt(); } catch { return unknown("Original attempt unavailable or inconsistent", identity) as AdapterSubmissionResult; }
    if (attempt.idempotencyKey !== identity.idempotencyKey) return unknown("Output belongs to a different original attempt", identity) as AdapterSubmissionResult;
    if (attempt.submissionFingerprint !== identity.submissionFingerprint) return Object.freeze({ status: "IDEMPOTENCY_FINGERPRINT_CONFLICT" as const,
      idempotencyKey: identity.idempotencyKey, retainedFingerprint: attempt.submissionFingerprint as ContentHash, suppliedFingerprint: identity.submissionFingerprint });
    if (attempt.intentId !== intentId) return unknown("Original intent mismatch", identity) as AdapterSubmissionResult;
    const result = inspect();
    return result.status === "PACKET_VERIFIED"
      ? Object.freeze({ status: "RETRY" as const, idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint, acknowledgment: result.acknowledgment, retainedEvidence: evidence(identity, result.acknowledgment) })
      : unknown(result.reason, identity) as AdapterSubmissionResult;
  }

  function reconcile(submission: AdmittedTransactionSubmission): AdapterSubmissionResult {
    const { stable, identity } = captureSubmission(submission);
    return retained(identity, stable.intentId);
  }

  // Deliberately not async: all bounded reads/writes finish before the Promise is returned, while the caller's synchronous serialized entry still holds.
  function submit(submission: AdmittedTransactionSubmission): Promise<AdapterSubmissionResult> {
    let identity: AdapterIdentityResult | undefined;
    try {
      const captured = captureSubmission(submission);
      identity = captured.identity;
      const { stable } = captured;
      if (entries(output, 3).length !== 0) return Promise.resolve(retained(identity, stable.intentId));
      if (!equal(selectInput(input), selected)) return Promise.resolve(unknown("Selected inputs changed before intake", identity) as AdapterSubmissionResult);
      writeExclusive(join(output, "attempt.json"), jsonBytes(record(ATTEMPT, identity, stable.intentId)));
      mkdirSync(packet, { mode: 0o700 }); syncDirectory(output);
      mkdirSync(files, { mode: 0o700 }); syncDirectory(packet);
      for (const item of selected) {
        const bytes = readRegular(join(input, item.name), FILE_BYTES);
        if (bytes.length !== item.bytes || sha256(bytes) !== item.sha256) fail("Selected input changed during intake");
        writeExclusive(join(files, item.name), bytes);
      }
      const manifest = record(MANIFEST, identity, stable.intentId), bytes = jsonBytes(manifest), manifestSha256 = sha256(bytes);
      writeExclusive(join(packet, "manifest.json"), bytes);
      const typed = acknowledgment(identity, manifestSha256);
      writeExclusive(join(output, "ack.json"), jsonBytes({ schemaVersion: ACK, idempotencyKey: identity.idempotencyKey,
        submissionFingerprint: identity.submissionFingerprint, manifestSha256, acknowledgment: typed, evidence: evidence(identity, typed) }));
      const verified = inspect();
      if (verified.status !== "PACKET_VERIFIED") return Promise.resolve(unknown(verified.reason, identity) as AdapterSubmissionResult);
      return Promise.resolve(Object.freeze({ status: "SUBMITTED" as const, idempotencyKey: identity.idempotencyKey,
        submissionFingerprint: identity.submissionFingerprint, acknowledgment: typed, evidence: evidence(identity, typed) }));
    } catch (error) { return Promise.resolve(unknown(error instanceof Error ? error.message : "Packet creation uncertain", identity) as AdapterSubmissionResult); }
  }

  return Object.freeze({ adapterProfile, submit, reconcile, inspect });
}
