"""Source-bound reproducible hook experiments and conditional arithmetic model."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
FILES=('hook.py','receive.py','model.py','model_receive.py','reproduce.py','CONTRACT.md')
def need(x,s):
    if not x:raise ValueError(s)
def run(a):
    out=a.out.resolve();manifest=(json.dumps({n:hashlib.sha256((HERE/n).read_bytes()).hexdigest() for n in FILES},sort_keys=True,indent=2)+'\n').encode()
    if not a.read_only:
        need(not out.exists(),'FRESH_OUTPUT_REQUIRED')
        subprocess.run([sys.executable,'-I','-B',str(HERE/'hook.py'),'--out',str(out)],check=True)
        (out/'SOURCE_MANIFEST.json').write_bytes(manifest)
        subprocess.run([sys.executable,'-I','-B',str(HERE/'model.py'),'--result',str(out/'MODEL.jsonl')],check=True)
    need((out/'SOURCE_MANIFEST.json').read_bytes()==manifest,'PINNED_SOURCE_CLOSURE')
    for opt,name in ((False,'normal'),(True,'optimized')):
        flags=[sys.executable]+(['-O'] if opt else [])+['-I','-B']
        subprocess.run(flags+[str(HERE/'receive.py'),'--out',str(out),'--result',str(out/('hook-reader-'+name+'.json'))],check=True)
        subprocess.run(flags+[str(HERE/'model_receive.py'),'--input',str(out/'MODEL.jsonl'),'--result',str(out/('model-reader-'+name+'.json'))],check=True)
    for kind in ('hook','model'):need((out/(kind+'-reader-normal.json')).read_bytes()==(out/(kind+'-reader-optimized.json')).read_bytes(),'READERS_AGREE:'+kind)
    hook=json.loads((out/'hook-reader-normal.json').read_bytes());model=json.loads((out/'model-reader-normal.json').read_bytes())
    r=dict(status='HOOK_COUNTEREXAMPLES_AND_CONDITIONAL_MARGIN_RECEIVED',C004_closed=False,M1='HOLD',SR02='BLOCKED',hook_cells=hook['cells'],hook_late_commits=hook['late_commit_counterexamples'],hook_mutants_per_mode=hook['mutations_rejected'],model=model,
        source_manifest_sha256=hashlib.sha256(manifest).hexdigest(),native_FCI_rerun=False,physical_bound_proven=False,independent_external_audit=False)
    (out/'RESULTS.json').write_bytes((json.dumps(r,sort_keys=True,indent=2)+'\n').encode());print(json.dumps(r))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--read-only',action='store_true');run(p.parse_args())
