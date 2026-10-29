"""Build native gateway TS, then explicitly copy A2 runtime/declarations. No manifest edits."""
from pathlib import Path
import argparse,subprocess,shutil
p=argparse.ArgumentParser();p.add_argument('--node',default='node');p.add_argument('--tsc',type=Path);a=p.parse_args()
package=Path(__file__).resolve().parents[1];workspace=package.parents[1]
tsc=a.tsc or workspace/'node_modules/typescript/bin/tsc'
subprocess.run([a.node,str(tsc),'-p',str(package/'tsconfig.json')],check=True)
for name in ['access-http.mjs','access-http-guard.mjs','cooperative.mjs','tasks.mjs','http.mjs','http-common.mjs','http-private.mjs','http-router.mjs','http-server.mjs','access-http.d.mts','cooperative.d.mts','tasks.d.mts','http.d.mts','http-router.d.mts']:
 shutil.copy2(package/'src'/name,package/'dist'/name)
