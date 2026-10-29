import {createPrivateKey,createPublicKey} from 'node:crypto';
import {createCooperativeDestination} from '../../../packages/remote-tools/destination.mjs';
import {createToolRegistry} from '../../../packages/remote-tools/validation.mjs';
import {migrateDestinationHistory} from '../../../packages/remote-tools/durable-store.mjs';
process.once('message',async input=>{
 try{
  const point=name=>{if(name===input.cut)process.kill(process.pid,'SIGKILL');};
  if(input.mode==='migrate'){await migrateDestinationHistory({...input.options,hooks:{point}});process.send({unexpectedCompletion:true});return;}
  const {options,registry}=input;
  const service=await createCooperativeDestination({...options,now:()=>100,coordinatorPublicKey:createPublicKey(options.coordinatorPublicKey),servicePrivateKey:createPrivateKey(options.servicePrivateKey),validateOperation:createToolRegistry(registry).validateOperation,checkpointHooks:{point}});
  process.send({url:service.url});
 }catch(e){process.send({error:e.code??e.message});process.exitCode=1;process.disconnect();}
});
