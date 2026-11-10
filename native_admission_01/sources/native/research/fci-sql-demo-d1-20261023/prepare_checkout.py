"""Copy D1 and its byte-frozen dependencies into a readable disposable tree."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path-file", type=Path, required=True)
    args = ap.parse_args()
    manifest = json.loads((HERE / "SOURCE_FREEZE.json").read_text())
    destination = Path(tempfile.mkdtemp(prefix="fci-d1-checkout-", dir="/tmp"))
    os.chmod(destination, 0o755)
    files = [(ROOT / f["path"], f) for f in manifest["files"]]
    files.extend((p, None) for p in HERE.iterdir() if p.is_file())
    for source, entry in files:
        data = source.read_bytes()
        if entry:
            digest = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            if digest != entry["git_blob_sha"]:
                raise ValueError("frozen Git blob mismatch: " + entry["path"])
        target = destination / source.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        os.chmod(target, 0o644)
    for path in destination.rglob("*"):
        if path.is_dir():
            os.chmod(path, 0o755)
    args.path_file.write_text(str(destination) + "\n")
    print("Verified", len(manifest["files"]), "frozen dependencies; readable experiment:", destination)


if __name__ == "__main__":
    main()
