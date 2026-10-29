"""Reproduce A2 proposed-manifest tarball installation without editing builder-owned manifests.
Run after src/http-build.py. Supply --output DIR, optional --node/--pnpm,
--store-dir and --offline. Core must already be compiled and remote packages present.
"""
from pathlib import Path
import argparse,subprocess,shutil,json,os,hashlib,tempfile
p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=Path);p.add_argument('--node',default='node');p.add_argument('--pnpm',default='pnpm');p.add_argument('--store-dir',type=Path);p.add_argument('--offline',action='store_true');a=p.parse_args()
package=Path(__file__).resolve().parents[1];workspace=package.parents[1];out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
fixture=Path(tempfile.mkdtemp(prefix='package-fixture-',dir=out));env=os.environ.copy();steps=[]
if Path(a.node).is_absolute():env['PATH']=str(Path(a.node).parent)+os.pathsep+env.get('PATH','')
env['IRONTRELLIS_TEST_HISTORY_DIR']=str(out/'histories')
def run(name,args,cwd):
 r=subprocess.run([str(x)for x in args],cwd=cwd,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT);(out/(name+'.log')).write_text(r.stdout);steps.append({'name':name,'command':[str(x)for x in args],'cwd':str(cwd),'exit':r.returncode});(out/'steps.json').write_text(json.dumps(steps,indent=2)+'\n')
 if r.returncode:raise SystemExit(name+' failed; see '+str(out/(name+'.log')))
for name in ['dist','docs']:
 if(package/name).exists():shutil.copytree(package/name,fixture/name,ignore=shutil.ignore_patterns('*-test*'))
for name in ['README.md','LICENSE','NOTICE','server.json']:
 if(package/name).exists():shutil.copy2(package/name,fixture/name)
manifest=json.loads((package/'package.json').read_text());manifest['dependencies'].update({'@ramex-labs/irontrellis':'1.0.0-rc.2','@ramex-labs/irontrellis-remote':'1.0.0-rc.2','@modelcontextprotocol/client':'2.2.0','@modelcontextprotocol/server':'2.2.0','jose':'6.2.12'})
for name in ['http','cooperative','tasks','access-http']:manifest['exports']['./'+name]={'types':'./dist/'+name+'.d.mts','default':'./dist/'+name+'.mjs'}
(fixture/'package.json').write_text(json.dumps(manifest,indent=2)+'\n');(out/'proposed-package.json').write_text(json.dumps(manifest,indent=2)+'\n')
tarballs=out/'tarballs';tarballs.mkdir(exist_ok=True)
for directory in ['core','remote-tools','remote']:run('pack-'+directory,[a.pnpm,'pack','--pack-destination',tarballs],workspace/'packages'/directory)
run('pack-gateway',[a.pnpm,'pack','--pack-destination',tarballs],fixture)
consumer=Path(tempfile.mkdtemp(prefix='consumer-',dir=out))
deps={f'@ramex-labs/{name}':'file:'+str(tarballs/f'ramex-labs-{name}-1.0.0-rc.2.tgz')for name in ['irontrellis','irontrellis-remote-tools','irontrellis-remote','irontrellis-mcp-gateway']};deps.update({'@modelcontextprotocol/client':'2.2.0','jose':'6.2.12','typescript':'5.9.3','@types/node':'24.6.0'})
(consumer/'package.json').write_text(json.dumps({'name':'isolated-gateway-consumer','private':True,'type':'module','dependencies':deps},indent=2)+'\n')
(consumer/'pnpm-workspace.yaml').write_text("packages:\n - '.'\nautoInstallPeers: false\noverrides:\n"+''.join(' '+json.dumps(k)+': '+json.dumps(v)+'\n'for k,v in deps.items()if k.startswith('@ramex-labs/')))
install=[a.pnpm,'install','--ignore-scripts']
if a.store_dir:install+=['--store-dir',a.store_dir.resolve()]
if a.offline:install+=['--offline']
run('install',install,consumer)
for source in (package/'src').glob('*-test*.mjs'):
 s=source.read_text().replace("'../dist/","'./node_modules/@ramex-labs/irontrellis-mcp-gateway/dist/").replace("'../../remote-tools/test/helpers.mjs'","'./remote-testhelpers.mjs'");(consumer/source.name).write_text(s)
s=(workspace/'packages/remote-tools/test/helpers.mjs').read_text().replace("'../index.mjs'","'@ramex-labs/irontrellis-remote'");(consumer/'remote-testhelpers.mjs').write_text(s)
shutil.copy2(package/'src/http-test-consumer.mts',consumer/'consumer.mts')
run('declarations',[a.node,'node_modules/typescript/bin/tsc','--noEmit','--strict','--skipLibCheck','false','--module','NodeNext','--moduleResolution','NodeNext','--target','ES2023','--lib','ESNext,DOM','consumer.mts'],consumer)
run('gateway-tests',[a.node,'--test',*[x.name for x in sorted(consumer.glob('*-test.test.mjs'))]],consumer)
run('installed-dependencies',[a.pnpm,'list','--depth','2','--json'],consumer)
(out/'tarball-identities.json').write_text(json.dumps([{'file':x.name,'sha256':hashlib.sha256(x.read_bytes()).hexdigest(),'bytes':x.stat().st_size}for x in sorted(tarballs.glob('*.tgz'))],indent=2)+'\n')
print('PASS packed install, strict public declarations and all gateway tests')
