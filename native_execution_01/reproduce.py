"""Public native C execution campaign, frozen parent closure, explicit staging delta."""
import argparse,hashlib,importlib.util,itertools,json,os,pathlib,platform,subprocess,sys,tempfile
HERE=pathlib.Path(__file__).resolve().parent;PARENT=HERE.parent/'native_activation_01/reproduce.py'
PARENT_SHA='1d269301df8b322892cc20c93c58b4465a9ea223e7a0acdb89f998cba7fe62d1'
CASES=('success','before_commit','after_commit','expired_after_precheck','revoked_after_precheck','expired_before_commit','expired_before_commit_kill')
def need(x,why):
    if not x:raise ValueError(why)
def change(s,a,b):need(s.count(a)==1,'UNIQUE_TRANSFORM:'+a[:50]);return s.replace(a,b)
def stage_sources(stage):
    need(hashlib.sha256(PARENT.read_bytes()).hexdigest()==PARENT_SHA,'PINNED_ACTIVATION_PARENT')
    spec=importlib.util.spec_from_file_location('received_activation_launcher',PARENT);old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
    m=json.loads(old.stage_sources(stage))
    p=stage/'task/attribution.py';p.chmod(0o644);s=p.read_text();s=change(s,'            activation.provision(Path(self.path))','            activation.provision(Path(self.path))\n            import execution\n            execution.provision(Path(self.path))');p.write_bytes(s.encode())
    p=stage/'task/actors.py';p.chmod(0o644);s=p.read_text();s=change(s,"    from attribution import augment","    sys.path.insert(0,str(args.native_root.parent/'execution'))\n    from attribution import augment");p.write_bytes(s.encode())
    p=stage/'crash/collect.py';p.chmod(0o644);s=p.read_text();s=change(s,'from activation_phase import phase as activation_phase',"sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'execution'))\nfrom execution_phase import phase as activation_phase\nimport itertools")
    s=change(s,"      for cut in ('before_commit','after_commit'):","      for cut,execution_case in itertools.product(('before_commit','after_commit'),('success','before_commit','after_commit','expired_after_precheck','revoked_after_precheck','expired_before_commit','expired_before_commit_kill')):")
    s=change(s,"evidence=a.out/(profile+'-'+cut+('-O' if opt else '-normal'))","evidence=a.out/(profile+'-'+cut+('-O' if opt else '-normal')+'-'+execution_case)")
    s=change(s,"row=dict(profile=profile,cut=cut,optimized=opt,status='INCONCLUSIVE',waits=[])","row=dict(profile=profile,cut=cut,optimized=opt,execution_case=execution_case,status='INCONCLUSIVE',waits=[])")
    s=change(s,"optimized=opt))","optimized=opt,execution_case=execution_case))")
    s=change(s,"need(len(reports)==8,'EXACT_EIGHT')","need(len(reports)==56,'EXACT_FIFTY_SIX')")
    p.write_bytes(s.encode())
    for source,target in [('execution.py','execution.py'),('native_finalization.py','native_finalization.py'),('owner.py','owner.py'),('phase.py','execution_phase.py'),('receive.py','receive.py')]:
        p=stage/'execution'/target;p.parent.mkdir(exist_ok=True);p.write_bytes((HERE/source).read_bytes())
    m['execution_stage']='C_NATIVE_CONSUMPTION/2';m['execution_parent_launcher_sha256']=PARENT_SHA
    m['changes']+=['versioned_FCI_application_staging_after_all_native_finalizers','typed_policy_stop_before_vendor_COMMIT','separate_readonly_rollback_verification_and_durable_signed_abort']
    m['changes']+=['empty_consumption_schema_before_B','normal_native_constructor_and_fixture_supervised_rearm','fresh_root_transition_grants_native_epoch_bound','one_consumption_in_real_C_effect_transaction','seven_cases_each_parent_cell','exact_signature_error_mapping','isolated_negative_probes','late_commit_limit_observation']
    m['files']={p.relative_to(stage).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in stage.rglob('*') if p.is_file()}
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
