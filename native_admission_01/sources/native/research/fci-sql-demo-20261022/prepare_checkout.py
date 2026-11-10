"""Copy only this experiment and verified frozen sources into a readable /tmp tree."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--path-file",type=Path,required=True);args=ap.parse_args()
    m=json.loads((HERE/"SOURCE_FREEZE.json").read_text())
    dst=Path(tempfile.mkdtemp(prefix="fci-d0-checkout-",dir="/tmp"));os.chmod(dst,0o755)
    files=[(ROOT/f["path"],f) for f in m["files"]]
    for p in HERE.iterdir():
        if p.is_file():files.append((p,None))
    for src,entry in files:
        data=src.read_bytes()
        if entry:
            actual=hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
            if actual!=entry["git_blob_sha"]:raise ValueError("frozen Git blob mismatch: "+entry["path"])
        dest=dst/src.relative_to(ROOT);dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes(data);os.chmod(dest,0o644)
    for path in dst.rglob("*"):
        if path.is_dir():os.chmod(path,0o755)
    args.path_file.write_text(str(dst)+"\n")
    print("Verified",len(m["files"]),"frozen blobs; readable experiment copy:",dst)

if __name__=="__main__":main()
