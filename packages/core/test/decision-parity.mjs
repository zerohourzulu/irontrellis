/**
 * Decision parity between a migrated format-1 history T and its legacy source S
 * (DESIGN §8), shared by migrate.test.mjs and replay.test.mjs.
 *
 * Rule. Both sides are first compared after `strip` (the caller's function
 * dropping the fields that name the history itself: hashes, domain, version
 * literals, migration-only data). Every part of an answer must then be
 * deep-equal — ALLOW proofs included — except the DENY / INDETERMINATE
 * authorization results inside it, whose evidence is allowed to be narrower:
 * a format-1 state cites only the events relevant to the decision (genesis,
 * head, the actor's lifecycle, grants and revocations of the candidate paths,
 * their intersection partners and the prohibitions considered), where a legacy
 * state cites every authority event of the history (spec 02 §6.2). For such a
 * result we require:
 *   - `decision`, `code` and `scopeAssurance` equal;
 *   - the same number of failures and, per failure, `code`, `subjectId`,
 *     `rootAuthorityId`, `terminalAuthorityId`, `failingAuthorityId` and
 *     `authorityPathIds` equal;
 *   - the migrated failure's evidence is a subset of the source failure's
 *     evidence (by event id; each cited entry equal to the source's after
 *     `strip`) that still cites the failing authority's grant event and the
 *     head event.
 */
import assert from "node:assert/strict";

const FAILURE_FIELDS = ["code", "subjectId", "rootAuthorityId", "terminalAuthorityId", "failingAuthorityId", "authorityPathIds"];
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const isRefusal = (value) => isRecord(value) && (value.decision === "DENY" || value.decision === "INDETERMINATE") && Array.isArray(value.failures);
const keyOf = (reference) => reference.eventId ?? JSON.stringify(reference);

/**
 * Asserts `actual` (answers on the migrated history) against `expected`
 * (answers on the source) under the rule above. `state` is the migrated
 * replay state: it resolves the head event and each failing authority's grant
 * event (event ids are unchanged by migration).
 */
export function assertDecisionParity(actual, expected, { strip, state, message = "answers" }) {
  const head = state.events.at(-1).id;
  const refusal = (a, e, path) => {
    assert.ok(isRefusal(a), `${path}: expected a ${e.decision} result, got ${JSON.stringify(strip(a))?.slice(0, 200)}`);
    for (const key of ["decision", "code", "scopeAssurance"]) assert.deepEqual(a[key], e[key], `${path}.${key}`);
    assert.equal(a.failures.length, e.failures.length, `${path}.failures.length`);
    e.failures.forEach((sourceFailure, index) => {
      const failure = a.failures[index], at = `${path}.failures[${index}]`;
      for (const key of FAILURE_FIELDS) assert.deepEqual(strip(failure[key]), strip(sourceFailure[key]), `${at}.${key}`);
      const source = new Map(sourceFailure.evidence.map((reference) => [keyOf(reference), reference]));
      for (const reference of failure.evidence) {
        assert.ok(source.has(keyOf(reference)), `${at}: ${keyOf(reference)} is not cited by the source`);
        assert.deepEqual(strip(reference), strip(source.get(keyOf(reference))), `${at}: ${keyOf(reference)}`);
      }
      const cited = new Set(failure.evidence.map(keyOf));
      assert.ok(cited.has(head), `${at}: the head event ${head} is cited`);
      const failing = sourceFailure.failingAuthorityId === undefined ? undefined : state.authorities.get(sourceFailure.failingAuthorityId);
      if (failing !== undefined) assert.ok(cited.has(failing.grantEventId), `${at}: the failing authority's grant ${failing.grantEventId} is cited`);
    });
  };
  const walk = (a, e, path) => {
    if (isRefusal(e)) return refusal(a, e, path);
    if (Array.isArray(e) && Array.isArray(a)) {
      assert.equal(a.length, e.length, `${path}.length`);
      e.forEach((item, index) => walk(a[index], item, `${path}[${index}]`));
      return;
    }
    if (isRecord(e) && isRecord(a) && !isRefusal(a)) {
      const keys = Object.keys(strip(e)).sort();
      assert.deepEqual(Object.keys(strip(a)).sort(), keys, `${path}: fields`);
      for (const key of keys) walk(a[key], e[key], `${path}.${key}`);
      return;
    }
    assert.deepEqual(strip(a), strip(e), path);
  };
  walk(actual, expected, message);
}
