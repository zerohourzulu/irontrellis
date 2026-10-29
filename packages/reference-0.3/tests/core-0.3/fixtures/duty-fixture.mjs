import {join,dirname} from 'node:path';
import {fixture,signHash} from './history-fixture.mjs';
import {openLocalOwner} from '../../../packages/core-0.3/src/local-owner.ts';
import {openLocalDutyPolicy} from '../../../packages/core-0.3/src/duties.ts';
import {prepareMigration,stageMigration,activateMigration,DirectoryHistoryStore} from '../../../packages/core-0.3/src/history-store/index.ts';
const digest={algorithm:'sha256',value:'0x'+'a'.repeat(64)};
const event=(id,type,data)=>({id,type,timestamp:100,data});
export async function dutyFixture(t,{policy='E5',sign=signHash}={}){
  const f=await fixture(t,{policy}),dir=dirname(f.config.historyFile),binding=join(dir,'binding.json'),path=join(dir,'store'),planFile=join(dir,'migration.json');
  prepareMigration({sourceFile:f.config.historyFile,targetDirectory:path,planFile,expectedHead:f.handle.head,configurationFiles:[binding],artifactFiles:[],quiesced:true});
  stageMigration(planFile,{quiesced:true});activateMigration(planFile,{quiesced:true});
  let clock=100,calls=0;
  const {historyFile,...rest}=f.options;
  const options={...rest,historyProfile:'continuity-segmented-local/1',historyBinding:binding,now:()=>clock,signHash:async h=>{calls++;return sign(h);}};
  const owner=openLocalOwner(options),store=new DirectoryHistoryStore(path),duties=openLocalDutyPolicy(options);
  const selection=duties.describe({duty:'duty',incidentSourceDigest:digest,attesterRole:'role'});
  const input={id:'activate',descriptor:selection.descriptor,activationAuthority:'activation'};
  const grant=(changes={})=>owner.grant({id:'activation',to:'worker',actions:[selection.activationAction],resources:[selection.activationResource],expiresAt:1000,...changes});
  const append=(id,type,data)=>store.append(event(id,type,data),store.snapshot().revision);
  return {...f,dir,options,owner,store,duties,selection,input,grant,append,get calls(){return calls},setTime:t=>clock=t};
}

