"""Reproduce the C004 discriminator; PASS never means the deadline is closed."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
FILES=('bench.py','receive.py','native_witness.py','reproduce.py','CONTRACT.md')
def need(x,why):
    if not x:raise ValueError(why)
def source_manifest():
    return (json.dumps(dict(schema='C004-CONTRACT-DISCRIMINATOR/1',files={n:hashlib.sha256((HERE/n).read_bytes()).hexdigest() for n in FILES}),sort_keys=True,indent=2)+'\n').encode()
def run(a):
    out=a.out.resolve();raw=source_manifest()
    if a.verify_only:print(json.dumps(dict(status='C004_SOURCES_VERIFIED',files=len(FILES),source_manifest_sha256=hashlib.sha256(raw).hexdigest())));return
    need(bool(a.native_parent_zip or a.native_parent_dir),'PINNED_NATIVE_PARENT_REQUIRED')
    if not a.read_only:
        need(not out.exists(),'FRESH_OUTPUT_REQUIRED')
        subprocess.run([sys.executable,'-I','-B',str(HERE/'bench.py'),'--out',str(out)],check=True)
        (out/'SOURCE_MANIFEST.json').write_bytes(raw)
    need((out/'SOURCE_MANIFEST.json').read_bytes()==raw,'EXACT_C004_SOURCE_MANIFEST')
    for optimized,name in ((False,'normal'),(True,'optimized')):
        flags=[sys.executable]+(['-O'] if optimized else [])+['-I','-B']
        subprocess.run(flags+[str(HERE/'receive.py'),'--out',str(out),'--result',str(out/('fixture-reader-'+name+'.json'))],check=True)
        parent=['--parent-zip',str(a.native_parent_zip.resolve())] if a.native_parent_zip else ['--parent-dir',str(a.native_parent_dir.resolve())]
        subprocess.run(flags+[str(HERE/'native_witness.py')]+parent+['--result',str(out/('native-witness-'+name+'.json'))],check=True)
    for prefix in ('fixture-reader-','native-witness-'):
        need((out/(prefix+'normal.json')).read_bytes()==(out/(prefix+'optimized.json')).read_bytes(),'C004_READERS_IDENTICAL:'+prefix)
    fixture=json.loads((out/'fixture-reader-normal.json').read_text());native=json.loads((out/'native-witness-normal.json').read_text())
    need(fixture['C004_closed'] is native['C004_closed'] is False,'NEVER_CLOSE_C004_FROM_HARNESS_PASS')
    result=dict(status='C004_DISCRIMINATOR_AND_COUNTEREXAMPLES_RECEIVED',physical_COMMIT_deadline_contract='COUNTEREXAMPLES_RECEIVED',C004_closed=False,
        source_manifest_sha256=hashlib.sha256(raw).hexdigest(),fixture_cells=fixture['cells'],synthetic_late_commit_counterexamples=fixture['late_commit_counterexamples'],
        fixture_mutations_rejected_per_reader_mode=fixture['evidence_mutations_rejected'],pinned_native_late_commit_witnesses=native['native_late_commit_witnesses'],
        pinned_native_paired_kill_rollbacks=native['native_paired_kill_rollbacks'],native_witness_mutations_rejected_per_reader_mode=native['evidence_mutations_rejected'],
        readers_normal_optimized_byte_identical=True,native_new_execution=False,native_engines_modified=False,M1='HOLD',SR02='BLOCKED',
        independence='Distinct execution environments and separate readers; same author, not an external audit.')
    (out/'RESULTS.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n',encoding='utf-8');print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=Path('c004-results'));p.add_argument('--native-parent-zip',type=Path);p.add_argument('--native-parent-dir',type=Path)
    p.add_argument('--read-only',action='store_true');p.add_argument('--verify-only',action='store_true');run(p.parse_args())
