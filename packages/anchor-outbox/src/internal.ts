/**
 * Test fixtures only; not public; no semver promise (A-195.2). Not in the
 * package's exports map: the outbox's own tests import this file by path.
 */
export { openAnchorOutboxInternalForTests } from "./outbox.ts";
export { SYNTHETIC_TEST_PAIR } from "./profile.ts";
