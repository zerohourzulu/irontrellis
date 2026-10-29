/**
 * History-level mutation of wire event arrays: event drops, duplicates, swaps,
 * moves, truncation, splices from other histories, id and timestamp
 * collisions, signature swaps, structural mutation of single events
 * (including the genesis and its next-key commitment, rotations, commitment-only
 * rotations, witness binding events and anchors),
 * and generation of new owner-signed control events.
 *
 * Re-signing: a mutated format-1 control event can be re-signed with the owner
 * key in force (the seeds' private keys are known), and so can every later
 * control event (their signatures bind the head before them). Without it
 * almost every structural mutation stops at CONTROL_AUTHORIZATION_INVALID;
 * with it the fuzzer reaches the transition rules behind the signature. A
 * re-signed event carries a new signature, so the signed-content invariant
 * (which only follows seed signatures) is unaffected.
 */
import { core, plain, revive } from './env.mjs';
import { clone, mutateValue } from './mutate.mjs';

const credentialOf = (keys, keyId) => (Array.isArray(keys) ? keys.find((k) => k && k.keyId === keyId)?.credential : undefined);

/**
 * Re-signs, in place, every format-1 control event at index >= `from` whose key id names a key the registry holds
 * (the key in force for that id at that position, tracked through the genesis and every rotation before it). A
 * rotation's `nextKeyAuthorizations` are re-signed with the revealed keys when the registry holds them. Stops where
 * the prefix cannot be hashed.
 */
export async function resignFrom(events, from, registry) {
  if (core.detectFormat(events) !== core.TRELLIS_FORMAT) return events;
  const domain = events[0]?.data?.domain;
  const hasher = new core.HistoryHasher(core.TRELLIS_FORMAT);
  let keys = [];
  let previous = null;
  for (let i = 0; i < events.length; i += 1) {
    const event = events[i];
    if (event === null || typeof event !== 'object') return events;
    if (i === 0 && Array.isArray(event.data?.ownerKeys)) keys = event.data.ownerKeys;
    const authorization = event.data?.controlAuthorization;
    if (i >= from && i > 0 && event.data && typeof event.data === 'object' && authorization && typeof authorization === 'object' && typeof authorization.keyId === 'string') {
      const credential = credentialOf(keys, authorization.keyId);
      const signer = typeof credential === 'string' ? registry.get(credential.toLowerCase()) : undefined;
      if (signer !== undefined && signer.keyId === authorization.keyId) {
        try {
          const { controlAuthorization: _old, ...effect } = event.data;
          const signed = plain(await core.signControlEvent(signer, revive({ ...event, data: effect }), revive(domain), previous, 'sha256'));
          if (event.type === 'OWNER_KEYS_ROTATED' && Array.isArray(signed.data.nextKeyAuthorizations)) {
            const challenge = core.controlAuthorizationHash({
              domain: revive(domain), eventId: signed.id, eventType: signed.type, timestamp: signed.timestamp,
              previousHead: previous, effectHash: core.controlEffectHash(revive(signed), 'sha256'),
            }, 'sha256');
            signed.data.nextKeyAuthorizations = await Promise.all(signed.data.nextKeyAuthorizations.map(async (proof) => {
              const revealed = credentialOf(signed.data.ownerKeys, proof?.keyId);
              const proofSigner = typeof revealed === 'string' ? registry.get(revealed.toLowerCase()) : undefined;
              return proofSigner === undefined ? proof : { ...proof, signature: await proofSigner.signHash(challenge) };
            }));
          }
          events[i] = signed;
        } catch { /* unsignable (not canonical, bad domain): leave it for the engine to reject */ }
      }
    }
    try {
      previous = { hash: hasher.push(revive(events[i])), position: i };
    } catch {
      return events;
    }
    if (events[i]?.type === 'OWNER_KEYS_ROTATED' && Array.isArray(events[i].data?.ownerKeys)) keys = events[i].data.ownerKeys;
  }
  return events;
}

// Mutated events can be any JSON value; strict-mode assignment to a primitive's property throws.
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

/** The owner-signed control event templates of the seeds, by format, for the generation mutator. */
export function controlTemplates(histories) {
  const templates = [];
  for (const { events } of histories) {
    if (core.detectFormat(events) !== core.TRELLIS_FORMAT) continue;
    for (const event of events.slice(1)) if (event?.data?.controlAuthorization) templates.push(event);
  }
  return templates;
}

/**
 * One mutated history (a new array; the base is not touched). `donors`: other seed histories (same format preferred)
 * to splice from; `templates`: control events to generate from; `registry`: keys for re-signing.
 */
export async function mutateHistory(rng, base, { dict, donors, templates, registry }) {
  let events = clone(base);
  const n = events.length;
  let resignAt = Infinity;
  const touch = (i) => { resignAt = Math.min(resignAt, i); };
  const op = rng.weighted([
    [22, 'event'], [6, 'drop'], [5, 'dup'], [6, 'swap'], [4, 'move'], [4, 'truncate'], [6, 'splice'], [4, 'id'], [4, 'time'], [5, 'sigswap'],
    [8, 'generate'], [4, 'genesis'], [5, 'keys'], [4, 'anchor'], [3, 'empty'], [2, 'many'],
  ]);
  const i = rng.int(Math.max(1, n)), j = rng.int(Math.max(1, n));
  switch (op) {
    case 'event': events[i] = mutateValue(rng, events[i] ?? {}, dict, 2); touch(i); break;
    case 'drop': events.splice(i, 1 + (rng.chance(0.2) ? rng.int(3) : 0)); touch(i); break;
    case 'dup': events.splice(i, 0, clone(events[i])); touch(i); break;
    case 'swap': [events[i], events[j]] = [events[j], events[i]]; touch(Math.min(i, j)); break;
    case 'move': { const [event] = events.splice(i, 1); events.splice(j, 0, event); touch(Math.min(i, j)); break; }
    case 'truncate': events = events.slice(0, i); break;
    case 'splice': {
      const donor = rng.pick(donors).events;
      if (donor.length === 0) break;
      const k = rng.int(donor.length);
      if (rng.chance(0.5)) events.splice(i, 0, clone(donor[k])); else events[i] = clone(donor[k]);
      touch(i);
      break;
    }
    case 'id': if (n > 1 && isObject(events[i]) && events[j]) { events[i].id = events[j].id; touch(i); } break;
    case 'time': if (isObject(events[i])) { events[i].timestamp = rng.pick([0, (events[i - 1]?.timestamp ?? 1) - 1, events[i].timestamp + 1, 2 ** 53 - 1, events.at(-1)?.timestamp ?? 0]); touch(i); } break;
    case 'sigswap': {
      const donor = rng.chance(0.5) ? events : rng.pick(donors).events;
      const withSig = donor.filter((e) => e?.data?.controlAuthorization);
      if (withSig.length && events[i]?.data && typeof events[i].data === 'object') events[i].data.controlAuthorization = clone(rng.pick(withSig).data.controlAuthorization);
      return events; // never re-signed: the swap is the point
    }
    case 'generate': {
      if (templates.length === 0) break;
      const template = clone(rng.pick(templates));
      template.id = rng.chance(0.8) ? `fuzz:${rng.hex(6)}` : (events[j]?.id ?? template.id);
      template.timestamp = events[Math.min(i, n) - 1]?.timestamp ?? template.timestamp;
      const generated = rng.chance(0.6) ? mutateValue(rng, template, dict, 2) : template;
      const at = rng.chance(0.6) ? n : Math.max(1, i);
      events.splice(at, 0, generated);
      touch(at);
      break;
    }
    case 'genesis': if (events[0]) { events[0] = mutateValue(rng, events[0], dict, 2); touch(0); } break;
    case 'keys': { // rotations (commitment-only ones included) and the genesis key set and commitment
      const candidates = events.map((e, k) => [e, k]).filter(([e]) => ['OWNER_KEYS_ROTATED', 'DEPLOYMENT_INITIALIZED'].includes(e?.type));
      if (candidates.length === 0) break;
      const [event, k] = rng.pick(candidates);
      const field = rng.pick(['ownerKeys', 'nextKeyDigests', 'nextKeyAuthorizations', 'reason']);
      const data = isObject(event.data) ? event.data : {};
      if (Array.isArray(data[field]) && data[field].length && rng.chance(0.4)) data[field] = rng.chance(0.5) ? data[field].slice(1) : [...data[field], clone(data[field][0])];
      else if (data[field] !== undefined && rng.chance(0.3)) delete data[field];
      else data[field] = mutateValue(rng, data[field] ?? [], dict, 1);
      event.data = data;
      touch(k);
      break;
    }
    case 'anchor': { // anchors (point at other heads of this history) and witness binding events (structural mutation)
      const candidates = events.map((e, k) => [e, k]).filter(([e]) => ['ANCHOR_RECORDED', 'WITNESSES_BOUND', 'WITNESSES_UNBOUND'].includes(e?.type));
      if (candidates.length === 0) break;
      const [event, k] = rng.pick(candidates);
      try {
        const state = core.replay(revive(events.slice(0, k))).state;
        if (state && event.data?.anchoredHead && rng.chance(0.6)) {
          const p = rng.int(state.events.length + 1);
          event.data.anchoredHead = { hash: state.eventHistoryHashes[Math.min(p, state.events.length - 1)], position: p, canonicalTime: event.data.anchoredHead.canonicalTime };
        } else {
          events[k] = mutateValue(rng, event, dict, 2);
        }
      } catch { events[k] = mutateValue(rng, event, dict, 2); }
      touch(k);
      break;
    }
    case 'empty': events = rng.pick([[], [events[0]], [events[0], events[0]], events.slice(1)]).filter((e) => e !== undefined); break;
    default: for (let m = 0; m < 3; m += 1) { const k = rng.int(Math.max(1, events.length)); if (events[k]) events[k] = mutateValue(rng, events[k], dict, 1); touch(k); }
  }
  events = events.filter((e) => e !== undefined);
  if (resignAt !== Infinity && rng.chance(0.75)) {
    // Re-sign the mutated event (and usually everything after it, whose signatures bind the changed head).
    await resignFrom(events, resignAt, registry);
  }
  return events;
}
