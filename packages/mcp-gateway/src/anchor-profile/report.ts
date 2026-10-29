// A161 structural codec only. Claims never become qualified evidence here.
import {canonical,digest,captureCodecBytes as bytes,parseCodecBytes,closed,protocol,identifier,contentHash as hash,u53,nullable,requireValue as need} from './common.ts';
import {validateTezosIdentifier} from './tezos-identifiers.ts';
import type {AnchorVerifyReport,AnchorReportConsistency,AnchorReportCodecResult,CodecBytes} from './types.ts';
export const ANCHOR_VERIFY_REPORT_VERSION='irontrellis-anchor-verify-report/1';
const VERSION=ANCHOR_VERIFY_REPORT_VERSION;
export const ANCHOR_FINALITY_LABELS=Object.freeze(['SUBMITTED','L2_INCLUDED','L1_POSTED','L1_FINAL','CEMENTED']);
export const ANCHOR_VERIFICATION_MODES=Object.freeze(['CONSENSUS_VERIFIED','TRUSTED_NODE','UNVERIFIED']);
const LABELS=ANCHOR_FINALITY_LABELS,MODES=ANCHOR_VERIFICATION_MODES;
export class ReportCodecError extends Error{readonly code='REPORT_CODEC_INVALID';constructor(reason:string){super(reason);this.name='ReportCodecError'}}
const bool=(v:unknown,p:string):void=>need(typeof v==='boolean',p+':BOOLEAN');
function node(v:unknown,path:string):void{closed(v,['chainId','protocol','softwareCommit','operator','headLevel'],path);for(const key of ['chainId','protocol','softwareCommit','operator'])protocol(v[key],path+'.'+key);u53(v.headLevel,path+'.headLevel')}
function shape(r: AnchorVerifyReport): AnchorVerifyReport {
  closed(r,['version','profileId','chainId','statement','tx','nodes','finality','sentence','observedAt','continuity'],'report');
  need(r.version===VERSION,'report.version');
  identifier(r.profileId,'report.profileId');protocol(r.chainId,'report.chainId');
  closed(r.statement,['digest','historyId','head'],'statement');
  hash(r.statement.digest,'statement.digest');hash(r.statement.historyId,'statement.historyId');
  closed(r.statement.head,['hash','position'],'statement.head');hash(r.statement.head.hash,'statement.head.hash');u53(r.statement.head.position,'statement.head.position');
  closed(r.tx,['hash','l2Block','l2BlockHash'],'tx');hash(r.tx.hash,'tx.hash');u53(r.tx.l2Block,'tx.l2Block');protocol(r.tx.l2BlockHash,'tx.l2BlockHash');
  closed(r.nodes,['evm','l1','ownRollup'],'nodes');node(r.nodes.evm,'nodes.evm');node(r.nodes.l1,'nodes.l1');nullable(r.nodes.ownRollup,node,'nodes.ownRollup');
  closed(r.finality,['label','mode','l1Level','l1BlockHash','l1BlockTime','operationHash','refutationResidual','cementedAt'],'finality');
  need(LABELS.includes(r.finality.label),'finality.label');need(MODES.includes(r.finality.mode),'finality.mode');
  u53(r.finality.l1Level,'finality.l1Level');
  // A-181.3: the L1 header time at l1Level (ms) as the validating L1 node returns it; chain evidence, never read in replay.
  if(r.finality.mode==='CONSENSUS_VERIFIED')u53(r.finality.l1BlockTime,'finality.l1BlockTime');else need(r.finality.l1BlockTime===null,'finality.l1BlockTime:NULL_UNLESS_CONSENSUS_VERIFIED');
  protocol(r.finality.l1BlockHash,'finality.l1BlockHash');protocol(r.finality.operationHash,'finality.operationHash');
  validateTezosIdentifier(r.finality.l1BlockHash,'block');validateTezosIdentifier(r.finality.operationHash,'operation');
  need(['OPEN','CLOSED'].includes(r.finality.refutationResidual),'finality.refutationResidual');nullable(r.finality.cementedAt,u53,'finality.cementedAt');
  protocol(r.sentence,'sentence');u53(r.observedAt,'observedAt');
  closed(r.continuity,['previousReportDigest','contradiction'],'continuity');nullable(r.continuity.previousReportDigest,hash,'continuity.previousReportDigest');bool(r.continuity.contradiction,'continuity.contradiction');
  return r;
}
function consistency(r: AnchorVerifyReport): AnchorReportConsistency {
  const codes:string[]=[], f=r.finality;
  if(r.continuity.contradiction)codes.push('DECLARED_CONTINUITY_CONTRADICTION');
  if(f.label==='L1_FINAL' && f.mode==='CONSENSUS_VERIFIED') {
    if(f.refutationResidual!=='OPEN' || f.cementedAt!==null)codes.push('L1_FINAL_REQUIRES_OPEN_AND_NULL');
    if(r.nodes.l1.headLevel<2 || f.l1Level>r.nodes.l1.headLevel-2)codes.push('DECLARED_L1_HEAD_HAS_FEWER_THAN_TWO_SUCCESSORS');
    if(r.nodes.evm.operator===r.nodes.l1.operator)codes.push('DECLARED_OPERATORS_EQUAL');
  }
  if(f.label==='CEMENTED' && (f.refutationResidual!=='CLOSED' || f.cementedAt===null))codes.push('CEMENTED_REQUIRES_CLOSED_AND_LEVEL');
  return Object.freeze({status:codes.length?'LISTED_CLAIM_CONTRADICTION':'NO_LISTED_CLAIM_CONTRADICTION',codes:Object.freeze(codes),
    sentenceSemanticsVerified:false,identityAuthenticityVerified:false,continuityRecomputed:false,evidenceVerified:false});
}
function encode(input: CodecBytes,exact: boolean): AnchorReportCodecResult {
  try {
    const inputBytes=bytes(input), report=shape(parseCodecBytes(inputBytes) as AnchorVerifyReport), canonicalText=canonical(report), canonicalBytes=Buffer.from(canonicalText,'utf8');
    if(exact)need(canonicalBytes.equals(inputBytes),'NONCANONICAL_REPORT_BYTES');
    return Object.freeze({format:'irontrellis-report-codec-result/1',validation:'STRUCTURAL_ONLY',claimedReport:report,canonicalText,
      canonicalByteLength:canonicalBytes.length,reportDigest:digest(report),
      claimConsistency:consistency(report),mode:'UNVERIFIED',qualifiedFinalityLabel:null,dispatchAllowed:false});
  } catch(error) {
    if(error instanceof ReportCodecError)throw error;
    throw new ReportCodecError(error instanceof Error ? error.message : 'INVALID_REPORT');
  }
}
// Normalizes only permitted key-order/whitespace/escape spellings after strict parsing.
export function encodeAnchorVerifyReport(input: CodecBytes) { return encode(input,false); }
// Intake for an already canonical persisted report: no whitespace/re-encoding tolerance.
export function decodeCanonicalAnchorVerifyReport(input: CodecBytes) { return encode(input,true); }
