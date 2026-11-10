"""Standalone launcher for the exact71 received sources, in disposable Linux only."""
import argparse,hashlib,json,os,pathlib,platform,shutil,subprocess,sys,tempfile
HERE=pathlib.Path(__file__).resolve().parent
MANIFEST_SHA='fb7f6b88d5cdfe4b903cf1ab6ac4753c8a64a9b37694461f9b200adff8e36cf8'
def need(x,why):
    if not x:raise ValueError(why)
def verify_sources():
    raw=(HERE/'source-manifest.json').read_bytes();need(hashlib.sha256(raw).hexdigest()==MANIFEST_SHA,'MANIFEST_PIN')
    manifest=json.loads(raw);need(len(manifest['files'])==71,'EXACT71')
    for name,digest in manifest['files'].items():
        p=pathlib.PurePosixPath(name);need(not p.is_absolute() and '..' not in p.parts,'CONFINED_SOURCE')
        need(hashlib.sha256((HERE/'sources'/name).read_bytes()).hexdigest()==digest,'SOURCE:'+name)
    return manifest
def stage_sources(stage,manifest):
    shutil.copytree(HERE/'sources',stage,dirs_exist_ok=True)
    original=(HERE/'sources/admission/receive.py').read_bytes()
    needle=b"lambda x:x['admission_pair'][1]['response']['result']['result'].update(new_allocation=True)"
    replacement=b"lambda x:x['admission_pair'][1]['response']['result']['result'].update(new_allocation=not x['admission_pair'][1]['response']['result']['result']['new_allocation'])"
    need(original.count(needle)==1,'ONE_VERSIONED_MUTATION_FIX')
    revised=original.replace(needle,replacement)
    need(revised==(HERE/'receive_v11.py').read_bytes(),'EXACT_READER_V11_DELTA')
    (stage/'admission/receive.py').write_bytes(revised)
    effective=json.loads(json.dumps(manifest));effective['files']['admission/receive.py']=hashlib.sha256(revised).hexdigest()
    effective['origin_manifest_sha256']=MANIFEST_SHA;effective['public_receiver_version']='1.1'
    effective['changes'].append('public_reader_v11_inverts_either_client_result_instead_of_possible_noop')
    return (json.dumps(effective,sort_keys=True,indent=2)+'\n').encode()
def readers(out,sources):
    manifest=out/'cells/MANIFEST.json';sha=hashlib.sha256(manifest.read_bytes()).hexdigest()
    for optimized,name in ((False,'normal'),(True,'optimized')):
        cmd=[sys.executable]+(['-O'] if optimized else [])+['-I','-B',str(sources/'admission/receive.py'),
            '--manifest',str(manifest),'--source-manifest',str(out/'source-manifest.json'),'--manifest-sha256',sha,'--out',str(out/('reader-'+name+'.json'))]
        subprocess.run(cmd,check=True)
    need((out/'reader-normal.json').read_bytes()==(out/'reader-optimized.json').read_bytes(),'READERS_IDENTICAL')
    return json.loads((out/'reader-normal.json').read_bytes())
def main(a):
    manifest=verify_sources();out=a.out.resolve()
    if a.verify_only:
        print(json.dumps(dict(status='SOURCE71_VERIFIED',manifest_sha256=MANIFEST_SHA)));return
    if a.read_only:
        with tempfile.TemporaryDirectory(prefix='fci-public-offline-') as temp:
            stage=pathlib.Path(temp);effective=stage_sources(stage,manifest)
            need((out/'source-manifest.json').read_bytes()==effective,'READBACK_SOURCE_PIN')
            print(json.dumps(readers(out,stage),sort_keys=True));return
    need(platform.system()=='Linux' and hasattr(os,'getuid') and os.getuid()==0,'DISPOSABLE_LINUX_ROOT_REQUIRED')
    need(a.disposable_linux and not out.exists(),'EXPLICIT_DISPOSABLE_LINUX_AND_FRESH_OUTPUT')
    import pwd
    for uid in range(62021,62027):
        try:pwd.getpwuid(uid)
        except KeyError:pass
        else:raise ValueError('FIXTURE_UID_ALREADY_ASSIGNED:'+str(uid))
    need(hasattr(os,'pidfd_open'),'PIDFD_REQUIRED')
    import cryptography
    need(cryptography.__version__=='50.0.2','PINNED_CRYPTOGRAPHY_50_0_2')
    out.mkdir(parents=True);out.chmod(0o755)
    stage=pathlib.Path(tempfile.mkdtemp(prefix='fci-public-admission-'));stage.chmod(0o755)
    effective=stage_sources(stage,manifest)
    for p in stage.rglob('*'):
        p.chmod(0o755 if p.is_dir() else 0o444)
    (out/'source-manifest.json').write_bytes(effective);effective_sha=hashlib.sha256(effective).hexdigest()
    subprocess.run([sys.executable,'-I','-B',str(stage/'crash/collect.py'),'--stage',str(stage),
        '--manifest',str(out/'source-manifest.json'),'--manifest-sha256',effective_sha,'--out',str(out/'cells'),'--launch-eight'],check=True)
    received=readers(out,stage)
    record=dict(schema='PUBLIC-NATIVE-ADMISSION-REPRODUCTION/1.1',status='RECEIVED',origin_manifest_sha256=MANIFEST_SHA,manifest_sha256=effective_sha,
        source_files=len(manifest['files']),python=sys.version,platform=platform.platform(),cryptography=cryptography.__version__,
        stage=str(stage),scope='Fresh fixtures; exact frozen sources; trusted root/OS/owner; no independent audit',result=received)
    (out/'REPRODUCTION.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
    print(json.dumps(record,sort_keys=True))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=pathlib.Path,default=pathlib.Path('public-admission-results'))
    p.add_argument('--disposable-linux',action='store_true');p.add_argument('--verify-only',action='store_true');p.add_argument('--read-only',action='store_true')
    main(p.parse_args())
