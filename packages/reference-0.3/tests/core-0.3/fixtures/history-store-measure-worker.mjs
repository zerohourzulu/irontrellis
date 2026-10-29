import {performance} from 'node:perf_hooks';
import * as h from '../../../packages/core-0.3/src/history.ts';
import {readSnapshot,DirectoryHistoryStore,commitHistoryAdministration} from '../../../packages/core-0.3/src/history-store/index.ts';
import {authArgs,signHash} from './history-fixture.mjs';
const [path]=process.argv.slice(2),rows=[];
async function measure(name,fn){const start=performance.now();const result=await fn();rows.push({name,ms:Math.round((performance.now()-start)*100)/100,rssBytes:process.memoryUsage().rss});return result;}
const before=await measure('fresh_process_disk_read_and_full_replay',()=>readSnapshot(path));
const store=new DirectoryHistoryStore(path),events=h.exportContinuationEvents(before.history),domain=events[0].data.domain;
const after=await measure('signed_administrative_commit_with_post_sign_checks_and_fsync',()=>commitHistoryAdministration(store,{expectedDomain:domain,runtimeSessionId:'session',transition:{id:'measurement:review',type:'ATTEMPT_DUTY_REVIEW_CLOSED',timestamp:100,data:{dutyId:'duty',actorId:'worker',observationEventIds:[],summaryDigest:'0x'+'a'.repeat(64)}}},{signHash,now:()=>100}));
const reopened=await measure('reopen_after_commit_and_full_replay',()=>readSnapshot(path));
if(after.history.head.hash!==reopened.history.head.hash)throw Error('Reopen mismatch');
for(const action of ['inspect','export'])if(h.authorizeContinuation(reopened.history,authArgs(events,action)).result.decision!=='DENY')throw Error('Authority changed');
console.log(JSON.stringify({runtime:process.version,platform:process.platform,arch:process.arch,eventCountBefore:before.history.eventCount,eventCountAfter:after.history.eventCount,segmentCountBefore:before.manifest.segments.length,capacity:after.capacity,maxRssKiB:process.resourceUsage().maxRSS,rows,note:'Fresh process, no verified-state cache. OS page-cache coldness and power-loss durability are not claimed.'},null,2));
