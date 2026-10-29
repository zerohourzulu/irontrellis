/**
 * Migration transcription (SPEC-IRONTRELLIS-CORE-v2 §16.2 step 2 and its inversion, step 3).
 *
 * `AMOUNT_PATHS` is the ONE exhaustive list of the Amount field paths of a legacy or format-1 event (SPEC §16.2 step
 * 2(a)); it drives both directions: `toWire` (marker/bigint → §3.3 decimal string, the migration) and `toEngine`
 * (string → bigint, the reader's inversion for the shadow context). A bigint anywhere else in a source event is
 * `UNEXPECTED_AMOUNT_FIELD` (the closed schemas of HF1 §6 and spec 02 §6.3 admit no other Amount), so (a) is a
 * bijection on the listed paths. `invertTranscription` is the reader's inversion of steps 2(a), 2(c) and 2(d) (and of
 * the `credentialScheme` a legacy session gains, exactly as the format-1 migration added it, HF1 §11): applied to a
 * transcribed prefix event it yields the source event as the source engine held it, so the source's own per-position
 * hashes (`shadowHashes`) can be recomputed and the verbatim runtime signatures validate against the source's heads.
 */
import { EngineError } from "./errors.ts";
import { LEGACY_FORMAT, TRELLIS_FORMAT } from "./events.ts";
import { CONTROL_EVENT_TYPES, type CanonicalEvent, type EventType, type HistoryFormat } from "./types.ts";

type Rec = Record<string, unknown>;
const CONSTRAINT_AMOUNTS = ["maxAmount", "maxCumulativeAmount"] as const;
const constraintPaths = (prefix: string): readonly string[] => CONSTRAINT_AMOUNTS.map((key) => `${prefix}.constraints.${key}`);

/**
 * SPEC §16.2 step 2(a): every Amount field path of a source event, by type, exhaustively. `[]` stands for every member
 * of the list at that path. No other event type of formats 0.2 and 1 carries an Amount.
 */
export const AMOUNT_PATHS: Readonly<Partial<Record<EventType, readonly string[]>>> = Object.freeze({
  AUTHORITY_GRANTED: Object.freeze(constraintPaths("grant")),
  TRANSACTION_INTENT_DECLARED: Object.freeze(["amount"]),
  TRANSACTION_INTENT_ADMITTED: Object.freeze([
    "authorizationProof.request.amount",
    "authorizationProof.effectiveConstraints.maxAmount",
    "authorizationProof.effectiveConstraints.maxCumulativeAmount",
    ...constraintPaths("authorizationProof.permissionPath[]"),
    "authorizationProof.intersections[].effectiveConstraints.maxAmount",
    "authorizationProof.intersections[].effectiveConstraints.maxCumulativeAmount",
    ...constraintPaths("authorizationProof.intersections[].path[]"),
    "authorizationProof.usageSnapshot[].admittedCumulativeAmount",
  ]),
});

export type AmountDirection = "toWire" | "toEngine";
const unsupported = (reason: string, path: string): EngineError => new EngineError("MIGRATION_UNSUPPORTED", `${path}: ${reason}`, { reason: "UNEXPECTED_AMOUNT_FIELD", path });
const convert = (value: unknown, direction: AmountDirection, path: string): unknown => {
  if (direction === "toWire") {
    if (typeof value === "bigint") return value.toString();
    throw unsupported("expected an Amount marker at a listed Amount path", path);
  }
  if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) return BigInt(value);
  throw unsupported("expected an Amount string at a listed Amount path", path);
};
/** Converts the value at `segments` (if present) in a copy of `value`; untouched containers are shared. */
const convertAt = (value: unknown, segments: readonly string[], direction: AmountDirection, path: string): unknown => {
  if (segments.length === 0) return convert(value, direction, path);
  const [head, ...rest] = segments as [string, ...string[]];
  if (head.endsWith("[]")) {
    const key = head.slice(0, -2);
    if (value === null || typeof value !== "object" || Array.isArray(value)) return value;
    const list = (value as Rec)[key];
    if (list === undefined) return value;
    if (!Array.isArray(list)) throw unsupported("expected a list", `${path}.${key}`);
    return { ...(value as Rec), [key]: list.map((member, index) => convertAt(member, rest, direction, `${path}.${key}[${index}]`)) };
  }
  if (value === null || typeof value !== "object" || Array.isArray(value) || !Object.hasOwn(value, head)) return value;
  return { ...(value as Rec), [head]: convertAt((value as Rec)[head], rest, direction, `${path}.${head}`) };
};
/** The data of an event of `type` with every listed Amount path converted in `direction`; absent optional fields stay absent. */
export function convertAmounts(type: EventType, data: Readonly<Rec>, direction: AmountDirection): Readonly<Rec> {
  let out: unknown = data;
  for (const path of AMOUNT_PATHS[type] ?? []) out = convertAt(out, path.split("."), direction, "$.data");
  return out as Readonly<Rec>;
}
/** The path of the first bigint in `data` (a marker record of the source) outside the listed Amount paths, or `undefined`. */
export function markerOutsideAmountPaths(type: EventType, data: Readonly<Rec>): string | undefined {
  const listed = new Set((AMOUNT_PATHS[type] ?? []).map((path) => path.replaceAll("[]", "")));
  const visit = (value: unknown, logical: string, concrete: string): string | undefined => {
    if (typeof value === "bigint") return listed.has(logical) ? undefined : concrete;
    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index += 1) { const found = visit(value[index], logical, `${concrete}[${index}]`); if (found !== undefined) return found; }
      return undefined;
    }
    if (value !== null && typeof value === "object") {
      for (const key of Object.keys(value)) { const found = visit((value as Rec)[key], logical === "" ? key : `${logical}.${key}`, `${concrete}.${key}`); if (found !== undefined) return found; }
    }
    return undefined;
  };
  return visit(data, "", "$.data");
}

/**
 * SPEC §16.2 step 2, the data part (the new `/2` control signature is the caller's): (a) Amount markers → strings on
 * `AMOUNT_PATHS`, any other marker refused (`MIGRATION_UNSUPPORTED {reason: UNEXPECTED_AMOUNT_FIELD}`); (c) a
 * format-1 source's `/1` `controlAuthorization` kept as `sourceControlAuthorization` (legacy control events had none);
 * (d) prefix declarations carry `declarationAuthorization: null`; a legacy session gains `credentialScheme` (the source's
 * scheme, as the format-1 migration added it: the format-2 session schema requires it); (e) everything else verbatim.
 */
export function transcribeData(event: CanonicalEvent, sourceFormat: HistoryFormat, signatureScheme: string): Readonly<Rec> {
  const outside = markerOutsideAmountPaths(event.type, event.data);
  if (outside !== undefined) throw unsupported("an Amount marker outside the exhaustive Amount paths of SPEC §16.2 step 2(a)", outside);
  const data: Rec = { ...convertAmounts(event.type, event.data, "toWire") };
  if (CONTROL_EVENT_TYPES.has(event.type)) {
    const own = data.controlAuthorization;
    delete data.controlAuthorization;
    if (sourceFormat === TRELLIS_FORMAT && own !== undefined) data.sourceControlAuthorization = own;
  }
  if (event.type === "TRANSACTION_INTENT_DECLARED") data.declarationAuthorization = null;
  if (event.type === "RUNTIME_SESSION_ADMITTED" && sourceFormat === LEGACY_FORMAT) data.credentialScheme = signatureScheme;
  return data;
}

/**
 * SPEC §16.2 step 3: the source event a transcribed prefix event came from — undo (a) (strings → markers on
 * `AMOUNT_PATHS`), undo (c) (drop the `/2` `controlAuthorization`; for a format-1 source restore
 * `sourceControlAuthorization` as `controlAuthorization`), undo (d) (drop `declarationAuthorization: null`) and, for
 * a legacy source, drop the `credentialScheme` a session gained. Total on every transcribed event.
 */
export function invertTranscription(event: CanonicalEvent, sourceFormat: HistoryFormat): CanonicalEvent {
  const data: Rec = { ...convertAmounts(event.type, event.data, "toEngine") };
  if (CONTROL_EVENT_TYPES.has(event.type)) {
    delete data.controlAuthorization;
    if (sourceFormat === TRELLIS_FORMAT && Object.hasOwn(data, "sourceControlAuthorization")) data.controlAuthorization = data.sourceControlAuthorization;
    delete data.sourceControlAuthorization;
  }
  if (event.type === "TRANSACTION_INTENT_DECLARED" && data.declarationAuthorization === null) delete data.declarationAuthorization;
  if (event.type === "RUNTIME_SESSION_ADMITTED" && sourceFormat === LEGACY_FORMAT) delete data.credentialScheme;
  return Object.freeze({ id: event.id, type: event.type, timestamp: event.timestamp, data: Object.freeze(data) });
}
