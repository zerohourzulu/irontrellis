"""Pack unchanged built Core, remote-tools and SDK, then test a clean install.

Run after Core is built. Supply --store-dir for a prepared pnpm store and
--offline to prohibit registry access. Output contains the exact commands/logs.
"""
import argparse, hashlib, json, os, shutil, subprocess, tempfile
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('--output',required=True,type=Path)
p.add_argument('--node',default='node')
p.add_argument('--pnpm',default='pnpm')
p.add_argument('--store-dir',type=Path)
p.add_argument('--offline',action='store_true')
a=p.parse_args()
package=Path(__file__).resolve().parents[1]
workspace=package.parents[1]
output=a.output.resolve();output.mkdir(parents=True,exist_ok=True)
tarballs=output/'tarballs';tarballs.mkdir(exist_ok=True)
consumer=Path(tempfile.mkdtemp(prefix='consumer-',dir=output))
env=os.environ.copy()
if Path(a.node).is_absolute():env['PATH']=str(Path(a.node).parent)+os.pathsep+env.get('PATH','')
steps=[]
def run(name,args,cwd):
    result=subprocess.run([str(x) for x in args],cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    (output/(name+'.log')).write_text(result.stdout)
    steps.append({'step':name,'command':[str(x) for x in args],'cwd':str(cwd),'exit':result.returncode})
    (output/'steps.json').write_text(json.dumps(steps,indent=2)+'\n')
    if result.returncode:raise SystemExit(f'{name} failed; see {output/(name+".log")}')
    return result.stdout

for directory in ['core','remote-tools','remote']:
    run('pack-'+directory,[a.pnpm,'pack','--pack-destination',tarballs],workspace/'packages'/directory)
dependencies={}
for directory,name in [('core','irontrellis'),('remote-tools','irontrellis-remote-tools'),('remote','irontrellis-remote')]:
    file=tarballs/f'ramex-labs-{name}-1.0.0-rc.2.1.tgz'
    assert file.is_file(),file
    dependencies['@ramex-labs/'+name]='file:'+str(file)
dependencies.update({'@langchain/core':'1.3.2','zod':'4.6.5','typescript':'5.9.3','@types/node':'24.6.0'})
(consumer/'package.json').write_text(json.dumps({'name':'irontrellis-remote-packed-verification','private':True,'type':'module','dependencies':dependencies},indent=2)+'\n')
# LangSmith is held at the workspace's override (pnpm-workspace.yaml): 0.11.5, within @langchain/core 1.3.2's
# >=0.11.0 <1.0.0 range (0.10.10/0.10.11 lacked a NullableHeaders declaration).
(consumer/'pnpm-workspace.yaml').write_text("packages:\n  - '.'\noverrides:\n  langsmith: 0.11.5\n"+"".join(f"  {json.dumps(k)}: {json.dumps(v)}\n" for k,v in dependencies.items() if k.startswith("@ramex-labs/")))
install=[a.pnpm,'install','--ignore-scripts','--config.update-notifier=false','--config.fetch-retries=0']
if a.store_dir:install+=['--store-dir',a.store_dir.resolve()]
if a.offline:install+=['--offline']
run('install',install,consumer)
for name in ['sdk.test.mjs','consumer.mts']:shutil.copy2(package/'test'/name,consumer/name)
histories=output/'histories';histories.mkdir(exist_ok=True)
env['IRONTRELLIS_TEST_HISTORY_DIR']=str(histories)
run('sdk-tests',[a.node,'--test','sdk.test.mjs'],consumer)
run('declarations',[a.node,'node_modules/typescript/bin/tsc','--noEmit','--strict','--skipLibCheck','false','--module','NodeNext','--moduleResolution','NodeNext','--target','ES2023','--lib','ESNext,DOM','consumer.mts'],consumer)
identities=[{'file':f.name,'bytes':f.stat().st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()} for f in sorted(tarballs.glob('*.tgz'))]
(output/'tarball-identities.json').write_text(json.dumps(identities,indent=2)+'\n')
print('PASS: three tarballs packed, isolated install, 3 SDK tests and strict all-five-subpath declarations')
