#!/usr/bin/env python3
"""Offline packed-artifact verification; synthetic fixtures and local listeners only."""
import argparse,json,os,shutil,subprocess,sys
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--node',required=True);p.add_argument('--pnpm',required=True)
p.add_argument('--output',required=True);p.add_argument('--store-dir',required=True)
p.add_argument('--tsc',required=True);p.add_argument('--type-roots',required=True)
p.add_argument('--checker')
a=p.parse_args();package=Path(__file__).resolve().parents[1];out=Path(a.output).resolve()
out.mkdir(parents=True,exist_ok=True);tarballs=out/'tarballs';tarballs.mkdir(exist_ok=True)
env=dict(os.environ);env['PATH']=str(Path(a.node).resolve().parent)+os.pathsep+env.get('PATH','')
def run(name,command,**kw):
 result=subprocess.run(command,env=env,capture_output=True,text=True,**kw)
 (out/(name+'.log')).write_text(result.stdout+result.stderr)
 if result.returncode:raise RuntimeError(name+' failed; see '+str(out/(name+'.log')))
 return result
for name,source in [('core',package.parent/'core'),('remote-tools',package)]:
 run('pack-'+name,[a.pnpm,'--dir',str(source),'pack','--pack-destination',str(tarballs)])
core=tarballs/'ramex-labs-irontrellis-1.0.0-rc.2.tgz';tools=tarballs/'ramex-labs-irontrellis-remote-tools-1.0.0-rc.2.tgz'
consumer=out/'consumer';consumer.mkdir(exist_ok=True)
(consumer/'package.json').write_text(json.dumps({'name':'irontrellis-remote-tools-packed-consumer','type':'module','private':True,'dependencies':{'@ramex-labs/irontrellis':'file:'+str(core),'@ramex-labs/irontrellis-remote-tools':'file:'+str(tools),'@langchain/core':'1.3.2','zod':'4.6.5'}},indent=2)+'\n')
(consumer/'pnpm-workspace.yaml').write_text(json.dumps({'overrides':{'@ramex-labs/irontrellis':'file:'+str(core),'langsmith':'0.11.5'},'autoInstallPeers':False},indent=2)+'\n')
run('install',[a.pnpm,'--dir',str(consumer),'install','--offline','--ignore-scripts','--store-dir',str(Path(a.store_dir).resolve())])
tests=consumer/'test';tests.mkdir(exist_ok=True)
for f in (package/'test').glob('*.mjs'):
 text=f.read_text().replace("'../index.mjs'","'@ramex-labs/irontrellis-remote-tools'")
 for subpath in ['wire','langchain','protected-evidence']:
  text=text.replace("'../"+subpath+".mjs'","'@ramex-labs/irontrellis-remote-tools/"+subpath+"'")
 (tests/f.name).write_text(text)
for fixture in (package/'test').glob('*.json'):
 shutil.copy2(fixture,tests/fixture.name)
histories=out/'histories';histories.mkdir(exist_ok=True);env['IRONTRELLIS_TEST_HISTORY_DIR']=str(histories)
run('tests',[a.node,'--test']+[str(f) for f in sorted(tests.glob('*.test.mjs'))])
(consumer/'consumer.mts').write_text("import * as r from '@ramex-labs/irontrellis-remote-tools';\nimport * as l from '@ramex-labs/irontrellis-remote-tools/langchain';\nconst p:r.HeadAuthenticationPolicy='REQUIRE_OWNER';void p;void r;void l;\n")
run('types',[a.node,a.tsc,'--noEmit','--strict','--skipLibCheck','false','--module','NodeNext','--moduleResolution','NodeNext','--target','ES2022','--lib','ESNext,DOM','--typeRoots',a.type_roots,str(consumer/'consumer.mts')])
if a.checker:
 results=[]
 for h in sorted(histories.glob('*.jsonl')):
  checked=run('checker-'+h.stem,[sys.executable,'-I',a.checker,'history',str(h)])
  value=json.loads(checked.stdout);results.append({'file':str(h),'result':value})
  if value.get('failures'):raise RuntimeError('checker failure: '+str(h))
 (out/'checker-results.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps({'status':'PASS','packedCore':str(core),'packedTools':str(tools),'consumer':str(consumer),'histories':str(histories)},indent=2))
