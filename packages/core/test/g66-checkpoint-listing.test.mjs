import test from "node:test";
import assert from "node:assert/strict";
import { checkpointPolicyListings } from "../src/owner-policy.ts";
const key = (keyId, value) => ({ keyId, scheme: "eip191-personal-sign-keccak256", credential: `0x${value.repeat(40)}` });
const keys = [key("h1", "1"), key("h2", "a"), key("committee", "b")];
const policy = { threshold: 1, keyClasses: { committee: "AGENT" }, byType: { STATE_CHECKPOINT: 3 } };

test("A151 lists an explicit checkpoint threshold that needs the committee, across historical epochs", () => {
  const epochs = [{ fromPosition: 0, keys, policy }, { fromPosition: 8, keys, policy: { ...policy, byType: { STATE_CHECKPOINT: 2 } } }, { fromPosition: 19, keys, policy }];
  const before = JSON.stringify(epochs);
  assert.deepEqual(checkpointPolicyListings(epochs).map(({ fromPosition, checkpointThreshold, nonAgentCredentials }) => ({ fromPosition, checkpointThreshold, nonAgentCredentials })), [
    { fromPosition: 0, checkpointThreshold: 3, nonAgentCredentials: 2 }, { fromPosition: 19, checkpointThreshold: 3, nonAgentCredentials: 2 },
  ]);
  assert.equal(JSON.stringify(epochs), before);
  assert.deepEqual(checkpointPolicyListings([{ fromPosition: 0, keys }, { fromPosition: 1, keys, policy: { threshold: 1 } }]), []);
});

test("A151 counts credential aliases once and applies AGENT classification across aliases", () => {
  const aliases = [...keys, { ...key("alias", "a"), credential: `0x${"A".repeat(40)}` }];
  assert.equal(checkpointPolicyListings([{ fromPosition: 0, keys: aliases, policy }])[0].nonAgentCredentials, 2);
  const classified = { ...policy, keyClasses: { ...policy.keyClasses, alias: "AGENT" }, byType: { STATE_CHECKPOINT: 2 } };
  assert.equal(checkpointPolicyListings([{ fromPosition: 0, keys: aliases, policy: classified }])[0].nonAgentCredentials, 1);
});

test("A151 reports classification risk independently of PHL attestation time and never supplies a quorum verdict", () => {
  const result = checkpointPolicyListings([{ fromPosition: 0, keys, policy: { ...policy, humanFloor: "ATTESTED", attesters: [], attestations: [] } }]);
  assert.equal(result[0].nonAgentCredentials, 2);
  assert.deepEqual(Object.keys(result[0]).sort(), ["checkpointThreshold", "fromPosition", "nonAgentCredentials", "policy"]);
});
