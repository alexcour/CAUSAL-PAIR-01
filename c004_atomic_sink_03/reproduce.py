"""Deterministic finite-model capture and source-bound independent receipt."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
FILES=('produce.py','receive.py','reproduce.py','CONTRACT.md','CONFORMANCE.md')
def need(x,s):
    if not x:raise ValueError(s)
def run(a):
    out=a.out.resolve();raw=(json.dumps({n:hashlib.sha256((HERE/n).read_bytes()).hexdigest() for n in FILES},sort_keys=True,indent=2)+'\n').encode()
    if not a.read_only:
        subprocess.run([sys.executable,'-I','-B',str(HERE/'produce.py'),'--out',str(out)],check=True);(out/'SOURCE_MANIFEST.json').write_bytes(raw)
    need((out/'SOURCE_MANIFEST.json').read_bytes()==raw,'EXACT_SOURCE_CLOSURE')
    for opt,name in ((False,'normal'),(True,'optimized')):
        subprocess.run([sys.executable]+(['-O'] if opt else [])+['-I','-B',str(HERE/'receive.py'),'--out',str(out),'--result',str(out/('reader-'+name+'.json'))],check=True)
    need((out/'reader-normal.json').read_bytes()==(out/'reader-optimized.json').read_bytes(),'NORMAL_OPTIMIZED_IDENTICAL')
    result=json.loads((out/'reader-normal.json').read_bytes());result.update(source_manifest_sha256=hashlib.sha256(raw).hexdigest(),M1='HOLD',SR02='BLOCKED',independent_external_audit=False,real_platform_bound_proven=False)
    (out/'RESULTS.json').write_bytes((json.dumps(result,sort_keys=True,indent=2)+'\n').encode());print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--read-only',action='store_true');run(p.parse_args())
