// Application recovery over one exact canonical transition sequence.
// This does not add an event type or infer authority from a recovery marker.
const same = (a, b) => JSON.stringify(a, Object.keys(a).sort()) === JSON.stringify(b, Object.keys(b).sort());

export function handoverProgress(history, caseId, steps) {
  const positions = steps.map(step => history.flatMap((event, index) => event.id === `${caseId}:${step.suffix}` ? [index] : []));
  let completed = 0;
  for (let index = 0; index < steps.length; index++) {
    if (positions[index].length > 1) throw new Error('HANDOVER_DUPLICATE_STEP');
    if (!positions[index].length) continue;
    if (index !== completed) throw new Error('HANDOVER_NONPREFIX_STEPS');
    const position = positions[index][0], event = history[position], step = steps[index];
    const { administrativeAuthorization, ...data } = event.data;
    if (event.type !== step.type || !same(data, step.data) || (index < 4 && administrativeAuthorization !== undefined)) throw new Error('HANDOVER_STEP_MISMATCH');
    if (index === 0 && history[position - 1]?.id !== `${caseId}:obligation`) throw new Error('HANDOVER_UNEXPECTED_START');
    if (index > 0 && position !== positions[index - 1][0] + 1) throw new Error('HANDOVER_INTERLEAVED_HISTORY');
    completed++;
  }
  if (completed > 0 && completed < steps.length && positions[completed - 1][0] !== history.length - 1) throw new Error('HANDOVER_PARTIAL_HISTORY_CHANGED');
  return { completedSteps: completed, totalSteps: steps.length, nextStep: steps[completed]?.suffix ?? null, status: completed === steps.length ? 'COMPLETE' : completed ? 'IN_PROGRESS' : 'NOT_STARTED' };
}
