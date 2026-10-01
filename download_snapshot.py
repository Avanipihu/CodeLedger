"""
Download the static OSV PyPI snapshot into data/raw/  (this folder is gitignored!)
Run from the project root:  python scripts/download_snapshot.py
"""
import urllib.request
from pathlib import Path

URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
DEST = Path("data/raw/PyPI.zip")

DEST.parent.mkdir(parents=True, exist_ok=True)
if DEST.exists():
    print(f"Already downloaded: {DEST} ({DEST.stat().st_size/1e6:.1f} MB)")
else:
    print(f"Downloading {URL} ...")
    urllib.request.urlretrieve(URL, DEST)
    print(f"Saved to {DEST} ({DEST.stat().st_size/1e6:.1f} MB)")
