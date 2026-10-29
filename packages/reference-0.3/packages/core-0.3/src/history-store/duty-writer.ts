/** Two independently authorized signatures; no lock is held across either callback. */
import {
  prepareHistoryDutyFinding, attachHistoryDutyFinding,
  prepareHistoryAdministrativeEvent, attachHistoryAdministrativeSignature,
} from '../../../core-0.2/src/administration/index.ts';
import { validatePortableDutyFreshEligibility } from '../../../core-0.2/src/core/duty-disposition.ts';
import { verifiedHistorySnapshot, historyDataFields, captureHistoryAncillary } from '../../../core-0.2/src/history/index.ts';
import type { ContentHash } from '../../../core-0.2/src/core/canonical.ts';
import { DirectoryHistoryStore, type Snapshot } from './store.ts';
import { hasAdministrativeRoom } from './capacity.ts';
import { integer, fail } from './codec.ts';

export async function commitHistoryDutyFinding(store: DirectoryHistoryStore, input: unknown, options: {
  signFinding: (hash: ContentHash) => Promise<unknown>;
  signTransition: (hash: ContentHash) => Promise<unknown>;
  now: () => number;
}) {
  const { signFinding, signTransition, now } = options;
  if (typeof signFinding !== 'function' || typeof signTransition !== 'function' || typeof now !== 'function') fail('CONFIGURATION_INVALID');
  const current = store.snapshot();
  const args = captureHistoryAncillary(historyDataFields(input, ['expectedDomain', 'transition', 'runtimeSessionId']));
  const preparedInput = { ...args, expectedHistoryHead: current.history.head };
  // This preparation checks both authorities and the complete maximum-signature
  // event shape before either callback. It never authenticates a placeholder.
  const finding = prepareHistoryDutyFinding(current.history, preparedInput);
  if (!hasAdministrativeRoom(current.history, args.transition, current.manifest.segments.length)) fail('CAPACITY_RESERVED');
  let lastTime = (args.transition as { timestamp: number }).timestamp;
  const checkRevision = (actual: Snapshot) => {
    if (actual.revision.instance !== current.revision.instance || actual.revision.generation !== current.revision.generation || actual.history.head.hash !== current.history.head.hash) fail('HISTORY_CONFLICT');
    const fresh = now();
    if (!integer(fresh, Number.MAX_SAFE_INTEGER) || fresh < lastTime) fail('CLOCK_INVALID');
    lastTime = fresh;
    return fresh;
  };
  const findingSignature = await signFinding(finding.signingHash);
  // Verify the first signature before offering anything to the second signer.
  const attached = attachHistoryDutyFinding(current.history, preparedInput, findingSignature);
  const afterFinding = store.snapshot(), firstTime = checkRevision(afterFinding);
  if (!validatePortableDutyFreshEligibility(verifiedHistorySnapshot(afterFinding.history).state,
    attached.transition, args.runtimeSessionId as string, firstTime)) fail("TRANSITION_REJECTED");
  const transition = prepareHistoryAdministrativeEvent(current.history, attached);
  const transitionSignature = await signTransition(transition.signingHash);
  const produced = attachHistoryAdministrativeSignature(current.history, attached, transitionSignature);
  return store.withWriter(writer => {
    const actual = writer.snapshot(), freshTime = checkRevision(actual);
    if (!validatePortableDutyFreshEligibility(verifiedHistorySnapshot(actual.history).state,
      attached.transition, args.runtimeSessionId as string, freshTime)) fail("TRANSITION_REJECTED");
    // The signatures keep their original time; fresh eligibility never changes
    // either signed challenge or substitutes a fresh proof into it.
    return writer.append(produced.event, current.revision);
  });
}
