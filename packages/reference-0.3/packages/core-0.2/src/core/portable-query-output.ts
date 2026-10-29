/** Package-owned projection accounting; no caller object is accepted here. */
import { canonicalEncode, compareProtocolStrings, immutableProtocolValue } from "./canonical.ts";
import type { PortableReplayEvidenceReference, PortableReplayState, PortableReceiptCommitmentRecord } from "./portable-replay.ts";
import { compareQueryEvidence, queryEventReference, queryReceiptReference } from "./portable-query-codec.ts";
import { createReferenceOutputBudget, isReferenceOutputOverflow, throwReferenceOutputOverflow, REFERENCE_OUTPUT_LIMITS } from "./reference-output-budget.ts";

type Evidence = PortableReplayEvidenceReference;
type Row = Record<string, unknown> & { evidence: Evidence[] };
export type PortableQueryDerivation<T> = Readonly<{
  answer?: T;
  includedFields: readonly string[];
  outputLimitExceeded: boolean;
}>;

export interface PortableQueryProjectionWriter {
  evidence(field: string, references: Iterable<Evidence>): void;
  row(field: string, key: string, fields: Readonly<Record<string, unknown>>, references: Iterable<Evidence>): void;
}

/** Package-owned nested row facts can themselves retain evidence references. */
const nestedEvidenceOccurrences = (value: unknown): number => {
  let count = 0;
  const visit = (current: unknown): void => {
    if (count > REFERENCE_OUTPUT_LIMITS.evidenceOccurrences) return;
    if (Array.isArray(current)) {
      for (const child of current) visit(child);
    } else if (current !== null && typeof current === "object") {
      const record = current as Record<string, unknown>;
      if (typeof record.kind === "string" && ["EVENT", "AUTHORITY", "RUNTIME_CREDENTIAL", "RECEIPT_COMMITMENT", "EXTERNAL"].includes(record.kind)) count += 1;
      for (const child of Object.values(record)) visit(child);
    }
  };
  visit(value);
  return count;
};

/** Repeated output occurrences may share a reference object, but are charged separately. */
export const createPortableQueryEvidenceCache = () => {
  const states = new WeakMap<PortableReplayState, Map<number, Evidence>>();
  const receipts = new WeakMap<PortableReceiptCommitmentRecord, Evidence>();
  return {
    event(state: PortableReplayState, position: number): Evidence {
      let cache = states.get(state);
      if (cache === undefined) { cache = new Map(); states.set(state, cache); }
      let reference = cache.get(position);
      if (reference === undefined) { reference = queryEventReference(state, position); cache.set(position, reference); }
      return reference;
    },
    receipt(record: PortableReceiptCommitmentRecord): Evidence {
      let reference = receipts.get(record);
      if (reference === undefined) { reference = queryReceiptReference(record); receipts.set(record, reference); }
      return reference;
    },
  };
};

/**
 * A group is one final evidence-list location. Merging a repeated fact charges
 * only new references in that group; the same reference in another group is a
 * separate occurrence. Once saturated, only the finite field vocabulary grows.
 */
export const createPortableQueryProjectionWriter = <T extends object>(skeleton: T) => {
  const value = skeleton as Record<string, unknown>;
  const budget = createReferenceOutputBudget(value);
  const fields = new Set<string>();
  const rows = new Map<string, Row>();
  const evidenceGroups = new Map<string, Set<string>>();
  let overflow = false;
  const observe = (path: string, current: unknown): void => {
    if (Array.isArray(current)) {
      for (const member of current) observe(path, member);
    } else if (current !== null && typeof current === "object") {
      for (const [key, member] of Object.entries(current)) {
        if (member === undefined) continue;
        const child = path === "" ? key : `${path}.${key}`;
        fields.add(child); observe(child, member);
      }
    }
  };
  observe("", value);
  const attempt = (reserve: () => void): boolean => {
    if (overflow) return false;
    try { reserve(); return true; }
    catch (error) {
      if (!isReferenceOutputOverflow(error)) throw error;
      overflow = true;
      // No incomplete normal result escapes, and no excess member is retained.
      for (const current of Object.values(value)) if (Array.isArray(current)) current.length = 0;
      rows.clear(); evidenceGroups.clear();
      return false;
    }
  };
  const appendEvidence = (groupKey: string, path: string, target: Evidence[] | undefined,
    references: Iterable<Evidence>, ancestorDepth: number): void => {
    for (const reference of references) {
      observe(path, reference);
      if (overflow || target === undefined) continue;
      let seen = evidenceGroups.get(groupKey);
      if (seen === undefined) { seen = new Set(); evidenceGroups.set(groupKey, seen); }
      const identity = canonicalEncode(reference);
      if (seen.has(identity)) continue;
      if (attempt(() => budget.append(reference, target.length, ancestorDepth, 1))) {
        seen.add(identity); target.push(reference);
      }
    }
  };
  return {
    evidence(field: string, references: Iterable<Evidence>): void {
      appendEvidence(field, field, overflow ? undefined : value[field] as Evidence[], references, 2);
    },
    row(field: string, key: string, members: Readonly<Record<string, unknown>>, references: Iterable<Evidence>): void {
      const identity = canonicalEncode([field, key]);
      observe(field, { ...members, evidence: [] });
      let row = rows.get(identity);
      if (!overflow && row === undefined) {
        const candidate: Row = { ...members, evidence: [] };
        const list = value[field] as Row[];
        // candidate.evidence is empty here; its later members are charged by
        // appendEvidence. Count only evidence already nested in row fields.
        if (attempt(() => budget.append(candidate, list.length, 2, nestedEvidenceOccurrences(candidate)))) {
          row = candidate; rows.set(identity, row); list.push(row);
        }
      }
      appendEvidence(identity, `${field}.evidence`, row?.evidence, references, 4);
    },
    finish(sortRows: (value: T) => void): PortableQueryDerivation<T> {
      if (!overflow) {
        for (const row of rows.values()) row.evidence.sort(compareQueryEvidence);
        for (const [key, current] of Object.entries(value)) {
          if (Array.isArray(current) && current.length !== 0 && evidenceGroups.has(key)) current.sort(compareQueryEvidence);
        }
        sortRows(skeleton);
      }
      return immutableProtocolValue({ ...(overflow ? {} : { answer: skeleton }),
        includedFields: [...fields].sort(compareProtocolStrings), outputLimitExceeded: overflow });
    },
  };
};

export const requirePortableQueryProjection = <T>(result: PortableQueryDerivation<T>): T => {
  if (result.outputLimitExceeded || result.answer === undefined) return throwReferenceOutputOverflow();
  return result.answer;
};

/**
 * Comparison-only plans store interned evidence identities, never an oversized
 * normal answer. Primary identities are unique in authoritative replay and the
 * normative array order is fixed by them, so equal row maps and evidence sets
 * are exactly equal canonical projections; no digest substitutes for equality.
 */
export const createPortableQueryComparisonPlan = (intern: Map<string, number>) => {
  const groups = new Map<string, { fields: string; evidence: Set<number> }>();
  const referenceIds = new WeakMap<object, number>();
  const identityFor = (reference: Evidence): number => {
    const cached = referenceIds.get(reference);
    if (cached !== undefined) return cached;
    const bytes = canonicalEncode(reference);
    let identity = intern.get(bytes);
    if (identity === undefined) { identity = intern.size; intern.set(bytes, identity); }
    referenceIds.set(reference, identity);
    return identity;
  };
  const add = (key: string, members: Readonly<Record<string, unknown>>, references: Iterable<Evidence>): void => {
    const fields = canonicalEncode(members);
    let group = groups.get(key);
    if (group === undefined) { group = { fields, evidence: new Set() }; groups.set(key, group); }
    else if (group.fields !== fields) throw new TypeError("Conflicting internal projection primary identity.");
    for (const reference of references) group.evidence.add(identityFor(reference));
  };
  return {
    groups,
    evidence(field: string, references: Iterable<Evidence>): void { add(field, {}, references); },
    row(field: string, key: string, members: Readonly<Record<string, unknown>>, references: Iterable<Evidence>): void {
      add(canonicalEncode([field, key]), members, references);
    },
  };
};

export const portableQueryComparisonPlansDiffer = (
  left: ReturnType<typeof createPortableQueryComparisonPlan>, right: ReturnType<typeof createPortableQueryComparisonPlan>,
): boolean => {
  if (left.groups.size !== right.groups.size) return true;
  for (const [key, a] of left.groups) {
    const b = right.groups.get(key);
    if (b === undefined || a.fields !== b.fields || a.evidence.size !== b.evidence.size) return true;
    for (const reference of a.evidence) if (!b.evidence.has(reference)) return true;
  }
  return false;
};
