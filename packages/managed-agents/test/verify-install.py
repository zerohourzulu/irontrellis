#!/usr/bin/env python3
"""Pack both developer adapters with unchanged Core; offline clean consumer, real SDKs, strict types, the independent history checker."""
import argparse,json,os,shutil,subprocess,sys
from pathlib import Path
p=argparse.ArgumentParser()
for name in ['node','pnpm','output','store-dir','tsc','type-roots','checker']:p.add_argument('--'+name,required=True)
a=p.parse_args();package=Path(__file__).resolve().parents[1];out=Path(a.output).resolve();out.mkdir(parents=True,exist_ok=True)
env=dict(os.environ);env['PATH']=str(Path(a.node).resolve().parent)+os.pathsep+env.get('PATH','')
def run(name,args,**kw):
 r=subprocess.run(args,env=env,capture_output=True,text=True,**kw);(out/(name+'.log')).write_text(r.stdout+r.stderr)
 if r.returncode:raise RuntimeError(name+' failed: '+str(out/(name+'.log')))
 return r
balls=out/'tarballs';balls.mkdir(exist_ok=True)
for name in ['core','managed-agents','agent-shims']:run('pack-'+name,[a.pnpm,'--dir',str(package.parent/name),'pack','--pack-destination',str(balls)])
pins={name:'file:'+str(balls/('ramex-labs-'+name.split('/')[1]+'-1.0.0-rc.2.tgz')) for name in ['@ramex-labs/irontrellis','@ramex-labs/irontrellis-managed-agents','@ramex-labs/irontrellis-agent-shims']}
consumer=out/'consumer';consumer.mkdir(exist_ok=True)
(consumer/'package.json').write_text(json.dumps({'name':'adapters-packed-consumer','type':'module','private':True,'dependencies':{**pins,'@openai/agents':'0.20.0','@langchain/langgraph':'1.4.21','@langchain/core':'1.3.2','zod':'4.6.5'}},indent=2)+'\n')
(consumer/'pnpm-workspace.yaml').write_text(json.dumps({'overrides':{**pins,'langsmith':'0.11.5'},'autoInstallPeers':False},indent=2)+'\n')
run('install',[a.pnpm,'--dir',str(consumer),'install','--offline','--ignore-scripts','--store-dir',str(Path(a.store_dir).resolve())])
files=[]
for name in ['managed-agents','agent-shims']:
 target=consumer/name/'test';target.mkdir(parents=True,exist_ok=True)
 for source in (package.parent/name/'test').glob('*.mjs'):
  text=source.read_text().replace("../dist/index.js", "@ramex-labs/irontrellis-"+name);(target/source.name).write_text(text)
  if source.name.endswith('.test.mjs'):files.append(target/source.name)
shutil.copy2(package.parent/'agent-shims/test/consumer.mts',consumer/'consumer.mts')
run('types',[a.node,a.tsc,'--noEmit','--strict','--skipLibCheck','false','--module','NodeNext','--moduleResolution','NodeNext','--target','ES2023','--lib','ESNext,DOM','--typeRoots',a.type_roots,str(consumer/'consumer.mts')])
histories=out/'histories';histories.mkdir(exist_ok=True);env['IRONTRELLIS_TEST_HISTORY_DIR']=str(histories)
run('tests',[a.node,'--test']+[str(x) for x in files])
results=[]
for h in sorted(histories.glob('*.jsonl')):
 r=run('checker-'+h.stem,[sys.executable,'-I',a.checker,'history',str(h)]);value=json.loads(r.stdout);results.append({'file':str(h),'result':value})
 if value.get('failures'):raise RuntimeError('checker failed: '+str(h))
(out/'checker-results.json').write_text(json.dumps(results,indent=2)+'\n')
result={'status':'PASS','packages':pins,'consumer':str(consumer),'historyCount':len(results),'strictTypes':True,'testLog':str(out/'tests.log')};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
