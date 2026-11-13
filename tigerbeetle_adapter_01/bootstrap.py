"""Pinned official TigerBeetle development runtime; no credentials or real accounts."""
import argparse,hashlib,json,os,platform,subprocess,urllib.request,zipfile
from pathlib import Path
VERSION='0.17.9'
WHEEL=('https://files.pythonhosted.org/packages/98/ba/1819cb0023531fd8e45b89c1d223a937c837aac9b6c0d4ae6f9ce1565a50/tigerbeetle-0.17.9-py3-none-any.whl',1680410,'405910bfdf74f169a27a282abfd6a124bee57ac2ef8cc50d247bb753e9a119ec')
SERVERS={'Windows':('tigerbeetle-x86_64-windows.zip',8101136,'aaac96a69380b33a0e63f981635c24924d610f28c3f41637f9e57b8caa0e5e77'),
         'Linux':('tigerbeetle-x86_64-linux.zip',7338512,'af71f2c0057e3b409bf79940fa94894b738187b0d4f1e711097bca15df5d8cd4')}
def need(x,s):
    if not x:raise ValueError(s)
def sha(b):return hashlib.sha256(b).hexdigest()
def download(url,path,size,digest):
    if not path.exists():
        with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'Codex-research-fixture'}),timeout=90) as f:raw=f.read()
        need(len(raw)==size and sha(raw)==digest,'OFFICIAL_DOWNLOAD_IDENTITY');path.write_bytes(raw)
    need(path.stat().st_size==size and sha(path.read_bytes())==digest,'PINNED_LOCAL_DOWNLOAD')
def extract(path,target):
    with zipfile.ZipFile(path) as z:
        need(z.testzip() is None,'ZIP_CRC');inventory={}
        for e in z.infolist():
            p=Path(e.filename);need(not p.is_absolute() and '..' not in p.parts and '\\' not in e.filename and ':' not in e.filename,'CONFINED_ZIP')
            if e.is_dir():continue
            data=z.read(e);dest=target/p;dest.parent.mkdir(parents=True,exist_ok=True)
            if dest.exists():need(dest.read_bytes()==data,'UNCHANGED_EXTRACTED_RUNTIME')
            else:dest.write_bytes(data)
            inventory[e.filename]=sha(data)
    return inventory
def run(root):
    system=platform.system();need(system in SERVERS and platform.machine().lower() in ('amd64','x86_64'),'SUPPORTED_X86_64_DEV_HOST');root.mkdir(parents=True,exist_ok=True)
    name,size,digest=SERVERS[system];download('https://github.com/tigerbeetle/tigerbeetle/releases/download/'+VERSION+'/'+name,root/'server.zip',size,digest)
    server=extract(root/'server.zip',root/'server');url,size,wheel_hash=WHEEL;download(url,root/'client.whl',size,wheel_hash);client=extract(root/'client.whl',root/'vendor')
    candidates=list((root/'server').rglob('tigerbeetle.exe' if system=='Windows' else 'tigerbeetle'));need(len(candidates)==1,'ONE_SERVER_BINARY');binary=candidates[0].resolve()
    if system=='Linux':binary.chmod(0o755)
    flags=dict(creationflags=subprocess.CREATE_NO_WINDOW) if os.name=='nt' else {}
    v=subprocess.run([str(binary),'version'],capture_output=True,text=True,timeout=20,check=True,**flags);version=(v.stdout+v.stderr).strip();need(VERSION in version,'PINNED_SERVER_VERSION')
    result=dict(version=VERSION,platform=system,binary=str(binary),binary_sha256=sha(binary.read_bytes()),server_zip_sha256=digest,wheel_sha256=wheel_hash,server_files=server,client_files=client,version_output=version,scope='Disposable synthetic development ledger; not production or physical COMMIT deadline qualification.')
    (root/'RUNTIME.json').write_bytes((json.dumps(result,sort_keys=True,indent=2)+'\n').encode());print(json.dumps({k:v for k,v in result.items() if k not in ('server_files','client_files')}))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',type=Path,required=True);run(p.parse_args().runtime.resolve())
