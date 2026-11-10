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
        need((out/'source-manifest.json').read_bytes()==(HERE/'source-manifest.json').read_bytes(),'READBACK_SOURCE_PIN')
        print(json.dumps(readers(out,HERE/'sources'),sort_keys=True));return
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
    shutil.copytree(HERE/'sources',stage,dirs_exist_ok=True)
    for p in stage.rglob('*'):
        p.chmod(0o755 if p.is_dir() else 0o444)
    (out/'source-manifest.json').write_bytes((HERE/'source-manifest.json').read_bytes())
    subprocess.run([sys.executable,'-I','-B',str(stage/'crash/collect.py'),'--stage',str(stage),
        '--manifest',str(out/'source-manifest.json'),'--manifest-sha256',MANIFEST_SHA,'--out',str(out/'cells'),'--launch-eight'],check=True)
    received=readers(out,stage)
    record=dict(schema='PUBLIC-NATIVE-ADMISSION-REPRODUCTION/1',status='RECEIVED',manifest_sha256=MANIFEST_SHA,
        source_files=len(manifest['files']),python=sys.version,platform=platform.platform(),cryptography=cryptography.__version__,
        stage=str(stage),scope='Fresh fixtures; exact frozen sources; trusted root/OS/owner; no independent audit',result=received)
    (out/'REPRODUCTION.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
    print(json.dumps(record,sort_keys=True))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=pathlib.Path,default=pathlib.Path('public-admission-results'))
    p.add_argument('--disposable-linux',action='store_true');p.add_argument('--verify-only',action='store_true');p.add_argument('--read-only',action='store_true')
    main(p.parse_args())
