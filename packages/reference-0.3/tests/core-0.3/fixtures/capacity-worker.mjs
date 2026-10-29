import {readFileSync} from 'node:fs';
import {privateKeyToAccount} from 'viem/accounts';
import {openLocalSimulation} from '../../../packages/core-0.3/src/simulation.ts';
const data=JSON.parse(readFileSync(process.argv[2]));
const account=privateKeyToAccount(data.key);
const runtime=openLocalSimulation({...data.config,now:()=>100,session:'session',signHash:async hash=>{
 if(process.argv[3]==='kill'){process.kill(process.pid,'SIGKILL');await new Promise(()=>{});}
 return account.signMessage({message:{raw:hash}});
}});
try{const result=await runtime.run({...data.op,id:process.argv[4]??data.op.id});console.log(JSON.stringify({status:result.status,admitted:result.admission?.status}));}
catch(error){console.log(JSON.stringify({refused:error.code??error.name}));}
