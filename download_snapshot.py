"""
download_snapshot.py  --  get and PIN the OSV PyPI snapshot (Week 3: reproducible)

OSV republishes all.zip every day, so "download the snapshot" gives different
data on different days. This script records the exact file the team uses
(size + SHA-256) in snapshot_manifest.json, which IS committed to GitHub.
The big zip itself (data/raw/) is NOT committed.

  python download_snapshot.py                  # download if missing, pin it
  python download_snapshot.py --from-file X.zip   # OFFLINE: use a zip a teammate shared
  python download_snapshot.py --verify         # check data/raw/PyPI.zip against the manifest
  python download_snapshot.py --repin          # deliberately replace the pinned snapshot

Everything except the first download works with NO internet.
"""
import argparse
import hashlib
import json
import shutil
import sys
import urllib.request
import zipfile
from datetime import date
from pathlib import Path

URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
DEST = Path("data/raw/PyPI.zip")
MANIFEST = Path(__file__).with_name("snapshot_manifest.json")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def describe(path, url):
    with zipfile.ZipFile(path) as z:
        n = sum(1 for name in z.namelist() if name.endswith(".json"))
    return {"source_url": url, "pinned_on": date.today().isoformat(),
            "size_bytes": Path(path).stat().st_size, "sha256": sha256_file(path),
            "json_records": n}


def load_manifest():
    try:
        return json.loads(MANIFEST.read_text())
    except Exception:
        return None


def compare(info, pinned):
    if info["sha256"] == pinned.get("sha256"):
        print(f"OK  - identical to the pinned snapshot ({pinned['json_records']:,} records, "
              f"pinned {pinned['pinned_on']}).")
        return True
    print("MISMATCH - this zip is NOT the pinned snapshot.")
    print(f"  pinned : {pinned['sha256'][:16]}... ({pinned['json_records']:,} records)")
    print(f"  yours  : {info['sha256'][:16]}... ({info['json_records']:,} records)")
    print("  OSV changes daily. Ask the teammate who pinned it to share their zip, then run:")
    print("      python download_snapshot.py --from-file <their PyPI.zip>")
    print("  (or run with --repin if the whole team agrees to move to a newer snapshot)")
    return False


def main():
    ap = argparse.ArgumentParser(description="Download / pin / verify the OSV PyPI snapshot")
    ap.add_argument("--from-file", help="use this local zip instead of downloading (offline)")
    ap.add_argument("--verify", action="store_true", help="only check data/raw/PyPI.zip")
    ap.add_argument("--repin", action="store_true", help="overwrite snapshot_manifest.json")
    ap.add_argument("--url", default=URL)
    a = ap.parse_args()
    pinned = load_manifest()

    if a.verify:
        if not DEST.exists():
            sys.exit(f"{DEST} not found.")
        if not pinned:
            sys.exit("No snapshot_manifest.json yet - run without --verify first.")
        sys.exit(0 if compare(describe(DEST, a.url), pinned) else 1)

    DEST.parent.mkdir(parents=True, exist_ok=True)
    if a.from_file:
        src = Path(a.from_file)
        if not src.exists():
            sys.exit(f"{src} not found.")
        if src.resolve() != DEST.resolve():
            shutil.copyfile(src, DEST)
        print(f"Using local file {src} -> {DEST}")
    elif DEST.exists():
        print(f"Already have {DEST} ({DEST.stat().st_size / 1e6:.1f} MB) - not downloading again.")
    else:
        print(f"Downloading {a.url} ...")
        tmp = DEST.with_suffix(".part")
        urllib.request.urlretrieve(a.url, tmp)
        tmp.replace(DEST)
        print(f"Saved to {DEST} ({DEST.stat().st_size / 1e6:.1f} MB)")

    info = describe(DEST, a.url if not a.from_file else f"file:{Path(a.from_file).name}")
    if pinned is None or a.repin:
        MANIFEST.write_text(json.dumps(info, indent=2) + "\n")
        print(f"Pinned this snapshot in {MANIFEST.name}: {info['json_records']:,} records, "
              f"sha256 {info['sha256'][:16]}...")
        print("Commit snapshot_manifest.json so the whole team uses the same data.")
    else:
        sys.exit(0 if compare(info, pinned) else 1)


if __name__ == "__main__":
    main()
