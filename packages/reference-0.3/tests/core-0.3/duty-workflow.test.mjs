import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,writeFileSync,symlinkSync,linkSync,unlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {readDocumentDigest,investigateDuty} from '../../examples/protected-evidence/investigation.mjs';
import {dutyFixture} from './fixtures/duty-fixture.mjs';
import {signHash} from './fixtures/history-fixture.mjs';
import {canonicalEncode} from '../../packages/core-0.3/src/adapter.ts';

test('local incident/report commitments reject changed, absent, linked and oversized material',t=>{
 const dir=mkdtempSync(join(tmpdir(),'ct-d04-doc-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));const file=join(dir,'report');
 writeFileSync(file,'incident');const digest=readDocumentDigest(file);assert.equal(readDocumentDigest(file,digest).value,digest.value);
 writeFileSync(file,'different');assert.throws(()=>readDocumentDigest(file,digest),/DOCUMENT_DIGEST_MISMATCH/);
 symlinkSync(file,join(dir,'symlink'));assert.throws(()=>readDocumentDigest(join(dir,'symlink')));
 linkSync(file,join(dir,'hardlink'));assert.throws(()=>readDocumentDigest(file),/DOCUMENT_UNSUPPORTED/);unlinkSync(join(dir,'hardlink'));
 writeFileSync(file,'x'.repeat(65537));assert.throws(()=>readDocumentDigest(file),/DOCUMENT_UNSUPPORTED/);unlinkSync(file);assert.throws(()=>readDocumentDigest(file));
});
test('wrong incident bytes or missing observation configuration cannot grant or activate',async t=>{
 const x=await dutyFixture(t),file=join(x.dir,'incident');writeFileSync(file,'incident');const before=x.store.snapshot().revision;
 const args={local:x.options,dutyId:'duty',sourceFile:file,sourceDigest:{algorithm:'sha256',value:'0x'+'0'.repeat(64)},reportDirectory:x.dir,observeAgain:async()=>{}};
 await assert.rejects(investigateDuty(args),/DOCUMENT_DIGEST_MISMATCH/);
 await assert.rejects(investigateDuty({...args,observeAgain:undefined}),/observation callback/);
 assert.equal(canonicalEncode(x.store.snapshot().revision),canonicalEncode(before));assert.equal(x.calls,0);
});
test('incident changes while the finding signer yields cannot produce a completion',async t=>{
 const x=await dutyFixture(t),file=join(x.dir,'incident');writeFileSync(file,'incident');let calls=0;
 const local={...x.options,signHash:async hash=>{calls++;if(calls===2)writeFileSync(file,'changed during finding');return signHash(hash);}};
 await assert.rejects(investigateDuty({local,dutyId:'duty',sourceFile:file,sourceDigest:readDocumentDigest(file),reportDirectory:x.dir,observeAgain:async()=>{}}),/DOCUMENT_DIGEST_MISMATCH/);
 assert.equal(calls,2);assert.equal(x.owner.exportHistory().some(e=>e.type==='ATTEMPT_DUTY_DISPOSITION_RECORDED'),false);
 assert.equal(x.owner.exportHistory().filter(e=>e.type==='ATTEMPT_DUTY_POLICY_ACTIVATED').length,1);
});
