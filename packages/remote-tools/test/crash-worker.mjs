import {createPrivateKey,createPublicKey} from 'node:crypto';
import {createCooperativeDestination,createToolRegistry} from '../index.mjs';
process.once('message',async({options,registry,point})=>{
  try{
    const destination=await createCooperativeDestination({...options,coordinatorPublicKey:createPublicKey(options.coordinatorPublicKey),servicePrivateKey:createPrivateKey(options.servicePrivateKey),
      now:()=>100,validateOperation:createToolRegistry(registry).validateOperation,checkpointHooks:{point(name){if(name===point)process.exit(75)}}});
    process.send({url:destination.url});
  }catch(e){process.send({error:e.stack});process.exit(76)}
});
