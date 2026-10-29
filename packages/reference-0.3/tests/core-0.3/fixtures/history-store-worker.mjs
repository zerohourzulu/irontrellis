import fs from 'node:fs';
import {DirectoryHistoryStore,activateMigration,stageMigration} from '../../../packages/core-0.3/src/history-store/index.ts';
const [mode,path,payloadFile,cut]=process.argv.slice(2);
const point=name=>{if(name===cut){fs.writeSync(1,'CUT '+name+'\n');process.kill(process.pid,'SIGKILL');}};
function run(){try{
 const payload=payloadFile==='-'?null:JSON.parse(fs.readFileSync(payloadFile,'utf8'));
 if(mode==='append')new DirectoryHistoryStore(path,{point}).append(payload.event,payload.revision);
 else if(mode==='activate')activateMigration(path,{quiesced:true},{point});
 else if(mode==='stage')stageMigration(path,{quiesced:true},{point});
 else throw Error('Unknown worker mode');
 process.send?.({status:'COMMITTED'});process.exitCode=0;
}catch(error){process.send?.({status:'REFUSED',code:error.code??error.name});fs.writeSync(2,String(error)+'\n');process.exitCode=2;}}
if(process.send){process.send({status:'READY'});process.once('message',()=>{run();process.disconnect();});}else run();
