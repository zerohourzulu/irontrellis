import {mkdtempSync,rmSync,realpathSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import {fixture,capture,padded} from './history-fixture.mjs';
import {initializeStore} from '../../../packages/core-0.3/src/history-store/store.ts';
import {DirectoryHistoryStore,historyCapacity} from '../../../packages/core-0.3/src/history-store/index.ts';
const f=await fixture(undefined,{policy:'E6'}),root=realpathSync(mkdtempSync(join(tmpdir(),'continuity-h03-measure-')));
try{
 const count=1024-historyCapacity(f.handle,1).reservedEvents,history=capture(padded(f.events,count));
 initializeStore(join(root,'store'),history); // Synthetic measurement fixture; not a public history-import API.
 const store=new DirectoryHistoryStore(join(root,'store'));
 const result=spawnSync(process.execPath,['--experimental-strip-types',new URL('./history-store-measure-worker.mjs',import.meta.url).pathname,store.path],{encoding:'utf8'});
 process.stdout.write(result.stdout);process.stderr.write(result.stderr);if(result.status!==0)process.exitCode=1;
}finally{f.cleanup();rmSync(root,{recursive:true,force:true});}
