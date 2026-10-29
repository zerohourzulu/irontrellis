import { createCase, collectCase, handoverCase, attemptOldWorker, reviewCase, recordReviewProgress, inspectCase, exportCase, captureReviewSnapshot, attachReviewSupplement } from './application.mjs';
const help = `Continuity common Core 0.2 — two approved executor profiles, synthetic data

  node src/cli.mjs create CASE_ID INPUT_DIRECTORY [packet|simulated]
  node src/cli.mjs collect CASE_ID
  node src/cli.mjs note CASE_ID a|b FILE_NAME NOTE_ID "REVIEW_NOTE"
  node src/cli.mjs handover CASE_ID [--stop-after epoch|terminated|transfer|session-b]
  node src/cli.mjs attempt-old CASE_ID
  node src/cli.mjs review CASE_ID
  node src/cli.mjs status CASE_ID [--json]
  node src/cli.mjs export CASE_ID
  node src/cli.mjs snapshot CASE_ID SNAPSHOT_ID
  node src/cli.mjs attach-supplement CASE_ID INPUT_PATH SUPPLEMENT_ID FILE_NAME EXPECTED_SHA256 SOURCE_LABEL

A handover resumes the exact committed sequence; repeating a completed handover
adds no events. --stop-after exits normally after that newly committed step,
releasing the command lock. It does not simulate a power loss or kill during a write.
Notes are signed application records, not proof that an investigation is resolved.
One supplement may be explicitly imported by the operator as unverified synthetic
evidence. Import does not recollect the original packet or grant agent authority.
Cases live in cases/. Public development keys make this an operator prototype.
`;
function display(value) {
  if(value.schemaVersion?.startsWith('continuity-local-intake-summary/')) {
    const lines=[`Case: ${value.caseId}`,`Stage: ${value.stage}`,`Packet: ${value.packet.status}`,`History: ${value.head.position+1} events`,value.duty?`Duty: ${value.duty.status}; bearer ${value.duty.bearer}; performer ${value.duty.performer}`:'Duty: not created; intake must be acknowledged first.',`Old worker epoch: ${value.predecessorEpoch}`,`Review: ${value.review.reviewedCount}/${value.review.totalFiles} files have recorded work; ${value.review.recordCount} signed notes.`, `Remaining: ${value.review.remainingFiles.join(', ') || 'no files without a review note; incident resolution remains unproved'}`,`Scope: ${value.scope.execution}; synthetic data; common Core 0.2; investigation not proved.`];
    if(value.packet.status==='PACKET_VERIFIED') lines.splice(3,0,`Files: ${value.packet.files.length}; manifest SHA-256 ${value.packet.manifestSha256}`);
    if(value.reviewSupplement) lines.push(`Imported supplement: ${value.reviewSupplement.record.supplementId}; SHA-256 ${value.reviewSupplement.record.sha256}; source claim unverified.`);
    console.log(lines.join('\n'));
  } else console.log(JSON.stringify(value,null,2));
}
try {
  const [command,caseId,...args]=process.argv.slice(2);
  const requireArgs = condition => { if(!caseId || !condition) throw new Error('INVALID_ARGUMENTS — use --help'); };
  let result;
  if(!command || command==='--help') console.log(help);
  else if(command==='create') { requireArgs(args.length===1||args.length===2); result=await createCase(caseId,args[0],args[1]); }
  else if(command==='note') { requireArgs(args.length===4); result=await recordReviewProgress(caseId,...args); }
  else if(command==='snapshot') { requireArgs(args.length===1); result=await captureReviewSnapshot(caseId,args[0]); }
  else if(command==='attach-supplement') {
    requireArgs(args.length===5);
    result=await attachReviewSupplement(caseId, { supplementId:args[1], fileName:args[2], expectedSha256:args[3], sourceLabel:args[4] }, args[0]);
  }
  else if(command==='handover') { requireArgs(args.length===0 || args.length===2 && args[0]==='--stop-after'); result=await handoverCase(caseId,args.length?{stopAfter:args[1]}:{}); }
  else if(command==='status') { requireArgs(args.length===0 || args.length===1 && args[0]==='--json'); result=await inspectCase(caseId); }
  else {
    const commands={collect:collectCase,'attempt-old':attemptOldWorker,review:reviewCase,export:exportCase};
    requireArgs(args.length===0 && Object.hasOwn(commands,command)); result=await commands[command](caseId);
  }
  if(result!==undefined) {
    if(command==='status' && args[0]==='--json') console.log(JSON.stringify(result,null,2)); else display(result);
  }
} catch(error) { console.error(`Continuity: ${error.message}`); process.exitCode=1; }
