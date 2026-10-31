"""Pack unchanged Core and three integrations; test a fresh isolated consumer.

Needs built Core and a prepared pnpm store (or registry access). The optional
OpenFGA binary must be independently verified version 1.21.0; no mock fallback.
"""
import argparse, hashlib, json, os, shutil, subprocess, tempfile
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--output',required=True,type=Path)
p.add_argument('--node',default='node')
p.add_argument('--pnpm',default='pnpm')
p.add_argument('--store-dir',type=Path)
p.add_argument('--offline',action='store_true')
p.add_argument('--openfga-binary',type=Path)
a=p.parse_args()
package=Path(__file__).resolve().parents[1]; workspace=package.parents[1]
output=a.output.resolve();output.mkdir(parents=True,exist_ok=True)
tarballs=output/'tarballs';tarballs.mkdir(exist_ok=True)
consumer=Path(tempfile.mkdtemp(prefix='irontrellis-integrations-consumer-'))
env=os.environ.copy();env.update({'LANGCHAIN_TRACING_V2':'false','LANGSMITH_TRACING':'false'})
if Path(a.node).is_absolute():env['PATH']=str(Path(a.node).parent)+os.pathsep+env.get('PATH','')
steps=[]
def run(name,args,cwd):
 result=subprocess.run([str(x) for x in args],cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 (output/(name+'.log')).write_text(result.stdout)
 steps.append({'step':name,'command':[str(x) for x in args],'cwd':str(cwd),'exit':result.returncode})
 (output/'steps.json').write_text(json.dumps(steps,indent=2)+'\n')
 if result.returncode:raise SystemExit(f'{name} failed; see {output/(name+".log")}')
 return result.stdout
names=['protected-evidence-mcp','policy-composition','langchain-evidence']
run('pack-core',[a.pnpm,'pack','--pack-destination',tarballs],workspace/'packages/core')
for name in names:run('pack-'+name,[a.pnpm,'pack','--pack-destination',tarballs],workspace/'integrations'/name)
dependencies={'@ramex-labs/irontrellis'+('-'+n if n else ''):'file:'+str(tarballs/('ramex-labs-irontrellis'+('-'+n if n else '')+'-1.0.0-rc.2.1.tgz')) for n in ['',*names]}
dependencies.update({'typescript':'5.9.3','@types/node':'24.6.0','@modelcontextprotocol/client':'2.2.0','@modelcontextprotocol/server':'2.2.0','langchain':'1.5.12','@langchain/core':'1.2.12','zod':'4.6.5','@cedar-policy/cedar-wasm':'4.13.0','@openfga/sdk':'0.9.7'})
(consumer/'package.json').write_text(json.dumps({'name':'irontrellis-integrations-packed-verification','private':True,'type':'module','dependencies':dependencies},indent=2)+'\n')
(consumer/'pnpm-workspace.yaml').write_text("packages:\n  - '.'\noverrides:\n  langsmith: 0.9.0\n  axios: 1.20.0\n"+''.join('  '+json.dumps(k)+': '+json.dumps(v)+'\n' for k,v in dependencies.items() if k.startswith('@ramex-labs/')))
install=[a.pnpm,'install','--ignore-scripts','--config.update-notifier=false','--config.fetch-retries=0']
if a.store_dir:install+=['--store-dir',a.store_dir.resolve()]
if a.offline:install+=['--offline']
run('install',install,consumer)
# Test fixtures are injected after installation; all runtime paths are the packed bytes.
for name in names:
 source=workspace/'integrations'/name;target=consumer/'node_modules/@ramex-labs'/('irontrellis-'+name)
 shutil.copytree(source/'tests',target/'tests',dirs_exist_ok=True)
 if name=='policy-composition':shutil.copy2(source/'fixture.mjs',target/'fixture.mjs')
shutil.copy2(package/'tests/consumer.mts',consumer/'consumer.mts')
histories=output/'histories';histories.mkdir(exist_ok=True);env['IRONTRELLIS_TEST_HISTORY_DIR']=str(histories)
for name in names:
 tests=sorted((consumer/'node_modules/@ramex-labs'/('irontrellis-'+name)/'tests').glob('*.test.mjs'))
 tests=[x for x in tests if x.name!='openfga.test.mjs']
 run('tests-'+name,[a.node,'--test',*tests],consumer)
if a.openfga_binary:
 env['OPENFGA_BINARY']=str(a.openfga_binary.resolve())
 run('tests-openfga',[a.node,consumer/'node_modules/@ramex-labs/irontrellis-policy-composition/run-openfga-tests.mjs'],consumer)
run('declarations',[a.node,'node_modules/typescript/bin/tsc','--noEmit','--strict','--skipLibCheck','false','--module','NodeNext','--moduleResolution','NodeNext','--target','ES2023','--lib','ESNext,DOM','consumer.mts'],consumer)
identities=[{'file':f.name,'bytes':f.stat().st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()} for f in sorted(tarballs.glob('*.tgz'))]
(output/'tarball-identities.json').write_text(json.dumps(identities,indent=2)+'\n')
print('PASS: four tarballs packed, clean install, protected/Cedar/LangChain tests and strict declarations; OpenFGA '+('passed' if a.openfga_binary else 'NOT RUN'))
