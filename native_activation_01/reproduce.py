"""Standalone activation/permit campaign built on the frozen public admission lot."""
import argparse,hashlib,importlib.util,json,os,pathlib,platform,subprocess,sys,tempfile
HERE=pathlib.Path(__file__).resolve().parent;PARENT=HERE.parent/'native_admission_01/reproduce.py'
PARENT_SHA='234cd606321578f21d100aaf9df8ffe384bb01ff82fa72d8d4d2b5d3203b8f9b'
def need(x,why):
    if not x:raise ValueError(why)
def change(s,old,new):need(s.count(old)==1,'UNIQUE_TRANSFORM:'+old[:60]);return s.replace(old,new)
def stage_sources(stage):
    need(hashlib.sha256(PARENT.read_bytes()).hexdigest()==PARENT_SHA,'PINNED_PARENT_LAUNCHER')
    spec=importlib.util.spec_from_file_location('received_admission_launcher',PARENT);p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
    origin=p.verify_sources();manifest=json.loads(p.stage_sources(stage,origin))
    path=stage/'task/attribution.py';s=path.read_text();s=change(s,'            admission.provision(Path(self.path))',
        '            admission.provision(Path(self.path))\n            import activation\n            activation.provision(Path(self.path))');path.write_bytes(s.encode())
    path=stage/'task/actors.py';s=path.read_text();s=change(s,'    from attribution import augment',"    sys.path.insert(0,str(args.native_root.parent/'activation'))\n    from attribution import augment");path.write_bytes(s.encode())
    path=stage/'crash/collect.py';s=path.read_text();s=change(s,'import select,signal,uuid',"sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'activation'))\nfrom activation_phase import phase as activation_phase\nimport select,signal,uuid")
    s=change(s,"            row['status']='CAPTURED'","            activation_phase(a,runtime,work,sd,evidence,row,flags,client,answer,root_snapshot,context_path,supervisor_key)\n            need(immutable=={n:sha(runtime/n) for n in immutable},'ACTIVATION_INSTALLED_KEYS_UNCHANGED')\n            row['status']='CAPTURED'")
    compile(s,'activation_collect.py','exec');path.write_bytes(s.encode())
    for n,target in [('activation.py','activation.py'),('owner.py','owner.py'),('phase.py','activation_phase.py'),('receive.py','receive.py')]:
        path=stage/'activation'/target;path.parent.mkdir(exist_ok=True);path.write_bytes((HERE/n).read_bytes())
    manifest['activation_stage']='C_ACTIVATION_PERMIT/1';manifest['activation_parent_launcher_sha256']=PARENT_SHA
    manifest['changes']+=['empty_activation_permit_schema_before_B','fresh_root_activation_grant_after_admission_owner_wait','new_activation_permit_phase_without_C_execution']
    manifest['files']={p.relative_to(stage).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in stage.rglob('*') if p.is_file()}
    for p in stage.rglob('*'):p.chmod(0o755 if p.is_dir() else 0o444)
    return (json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
def read(out,stage):
    sha=hashlib.sha256((out/'cells/MANIFEST.json').read_bytes()).hexdigest()
    for opt,name in [(False,'normal'),(True,'optimized')]:
        subprocess.run([sys.executable]+(['-O'] if opt else [])+['-I','-B',str(stage/'activation/receive.py'),'--manifest',str(out/'cells/MANIFEST.json'),
            '--source-manifest',str(out/'source-manifest.json'),'--manifest-sha256',sha,'--out',str(out/('activation-reader-'+name+'.json'))],check=True)
    need((out/'activation-reader-normal.json').read_bytes()==(out/'activation-reader-optimized.json').read_bytes(),'ACTIVATION_READERS_IDENTICAL')
    return json.loads((out/'activation-reader-normal.json').read_bytes())
def main(a):
    if a.read_only or a.verify_only:
        with tempfile.TemporaryDirectory(prefix='activation-offline-') as temp:
            stage=pathlib.Path(temp);raw=stage_sources(stage)
            if a.verify_only:print(json.dumps(dict(status='ACTIVATION_SOURCES_VERIFIED',files=len(json.loads(raw)['files']),manifest_sha256=hashlib.sha256(raw).hexdigest())));return
            need((a.out/'source-manifest.json').read_bytes()==raw,'EXACT_ACTIVATION_SOURCE_MANIFEST');print(json.dumps(read(a.out.resolve(),stage)));return
    need(platform.system()=='Linux' and os.getuid()==0 and a.disposable_linux,'EXPLICIT_DISPOSABLE_LINUX_ROOT')
    import pwd,cryptography
    need(cryptography.__version__=='50.0.2' and hasattr(os,'pidfd_open'),'RUNTIME_PIN')
    for uid in range(62021,62027):
        try:pwd.getpwuid(uid)
        except KeyError:pass
        else:raise ValueError('FIXTURE_UID_IN_USE')
    out=a.out.resolve();need(not out.exists(),'FRESH_OUTPUT');out.mkdir(parents=True);out.chmod(0o755)
    stage=pathlib.Path(tempfile.mkdtemp(prefix='fci-activate-'));stage.chmod(0o755);raw=stage_sources(stage);(out/'source-manifest.json').write_bytes(raw)
    subprocess.run([sys.executable,'-I','-B',str(stage/'crash/collect.py'),'--stage',str(stage),'--manifest',str(out/'source-manifest.json'),
        '--manifest-sha256',hashlib.sha256(raw).hexdigest(),'--out',str(out/'cells'),'--launch-eight'],check=True)
    received=read(out,stage);(out/'ACTIVATION_REPRODUCTION.json').write_text(json.dumps(dict(status='RECEIVED',source_manifest_sha256=hashlib.sha256(raw).hexdigest(),
        scope='Activation/native-permit issuance and dry gate only; no business execute, normal native constructor or rearm',result=received),sort_keys=True,indent=2)+'\n')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=pathlib.Path,default=pathlib.Path('activation-results'));p.add_argument('--disposable-linux',action='store_true')
    p.add_argument('--verify-only',action='store_true');p.add_argument('--read-only',action='store_true');main(p.parse_args())
