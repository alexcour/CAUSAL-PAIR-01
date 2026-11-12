"""Public native C execution campaign, frozen parent closure, explicit staging delta."""
import argparse,hashlib,importlib.util,itertools,json,os,pathlib,platform,subprocess,sys,tempfile
HERE=pathlib.Path(__file__).resolve().parent;PARENT=HERE.parent/'native_execution_01/reproduce.py'
PARENT_SHA='e52f01d4a111b5814749cd850aae8feb0f347d3e059d3135010c9362bb6f2b3c'
CASES=('success','before_commit','after_commit','expired_after_precheck','revoked_after_precheck','expired_before_commit','expired_before_commit_kill')
def need(x,why):
    if not x:raise ValueError(why)
def change(s,a,b):need(s.count(a)==1,'UNIQUE_TRANSFORM:'+a[:50]);return s.replace(a,b)
def stage_sources(stage):
    need(hashlib.sha256(PARENT.read_bytes()).hexdigest()==PARENT_SHA,'PINNED_ACTIVATION_PARENT')
    spec=importlib.util.spec_from_file_location('received_activation_launcher',PARENT);old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
    m=json.loads(old.stage_sources(stage))
    frozen={n:h for n,h in m['files'].items() if n.startswith('native/')}
    for source,target in [('execution.py','execution.py'),('native_finalization.py','native_finalization.py'),('owner.py','owner.py'),('phase.py','execution_phase.py'),('receive.py','receive.py'),('capability.py','capability.py')]:
        p=stage/'execution'/target
        if p.exists():p.chmod(0o644)
        p.write_bytes((HERE/source).read_bytes())
    m['execution_stage']='C_NATIVE_CAPABILITY/1';m['capability_parent_launcher_sha256']=PARENT_SHA
    m['changes']+=['explicit_SAMPLED_ADMISSION_only','COMMIT_DEADLINE_unqualified_refused_before_issue_or_execute','signed_v2_permit_RPC_and_policy3_capability_binding','seven_no_mutation_capability_probes_per_active_cell','fixture_temporal_TTL8s_for_added_probes']
    m['files']={p.relative_to(stage).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in stage.rglob('*') if p.is_file()}
    need(len(frozen)==37 and all(m['files'][n]==h for n,h in frozen.items()),'ALL_37_NATIVE_SOURCES_UNCHANGED')
    for p in stage.rglob('*'):p.chmod(0o755 if p.is_dir() else 0o444)
    return (json.dumps(m,sort_keys=True,indent=2)+'\n').encode()

def read(out,stage):
    h=hashlib.sha256((out/'cells/MANIFEST.json').read_bytes()).hexdigest()
    codes=[]
    for opt,name in [(False,'normal'),(True,'optimized')]:
        codes.append(subprocess.run([sys.executable]+(['-O'] if opt else [])+['-I','-B',str(stage/'execution/receive.py'),'--manifest',str(out/'cells/MANIFEST.json'),'--source-manifest',str(out/'source-manifest.json'),'--manifest-sha256',h,'--out',str(out/('execution-reader-'+name+'.json'))],check=False).returncode)
    need(codes==[0,0],'C_READERS_FAILED_HOLD:'+str(codes))
    need((out/'execution-reader-normal.json').read_bytes()==(out/'execution-reader-optimized.json').read_bytes(),'EXECUTION_READERS_IDENTICAL')
    return json.loads((out/'execution-reader-normal.json').read_bytes())
def main(a):
    if a.read_only or a.verify_only:
        with tempfile.TemporaryDirectory(prefix='C-execution-offline-') as temp:
            stage=pathlib.Path(temp);raw=stage_sources(stage)
            if a.verify_only:print(json.dumps(dict(status='C_EXECUTION_SOURCES_VERIFIED',files=len(json.loads(raw)['files']),manifest_sha256=hashlib.sha256(raw).hexdigest())));return
            need((a.out/'source-manifest.json').read_bytes()==raw,'EXACT_C_EXECUTION_SOURCE_MANIFEST');print(json.dumps(read(a.out.resolve(),stage)));return
    need(platform.system()=='Linux' and os.getuid()==0 and a.disposable_linux,'EXPLICIT_DISPOSABLE_LINUX_ROOT')
    import pwd,cryptography
    need(cryptography.__version__=='50.0.2' and hasattr(os,'pidfd_open'),'RUNTIME_PIN')
    for uid in range(62021,62027):
        try:pwd.getpwuid(uid)
        except KeyError:pass
        else:raise ValueError('FIXTURE_UID_IN_USE')
    out=a.out.resolve();need(not out.exists(),'FRESH_OUTPUT');out.mkdir(parents=True);out.chmod(0o755)
    stage=pathlib.Path(tempfile.mkdtemp(prefix='fci-execute-'));stage.chmod(0o755);raw=stage_sources(stage);(out/'source-manifest.json').write_bytes(raw)
    subprocess.run([sys.executable,'-I','-B',str(stage/'crash/collect.py'),'--stage',str(stage),'--manifest',str(out/'source-manifest.json'),'--manifest-sha256',hashlib.sha256(raw).hexdigest(),'--out',str(out/'cells'),'--launch-eight'],check=True)
    received=read(out,stage);(out/'EXECUTION_REPRODUCTION.json').write_text(json.dumps(dict(status='RECEIVED',source_manifest_sha256=hashlib.sha256(raw).hexdigest(),result=received),sort_keys=True,indent=2)+'\n')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=pathlib.Path,default=pathlib.Path('execution-results'));p.add_argument('--disposable-linux',action='store_true');p.add_argument('--verify-only',action='store_true');p.add_argument('--read-only',action='store_true');main(p.parse_args())
