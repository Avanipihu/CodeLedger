"""
Builds a ~10MB fake OSV folder (with deliberately BROKEN records) to prove
the parser never throws a KeyError. Output goes to data/test_10mb/ (gitignored).
Run: python scripts/make_test_chunk.py && python osv_parser.py data/test_10mb --out output
"""
import json
from pathlib import Path

out = Path("data/test_10mb"); out.mkdir(parents=True, exist_ok=True)

def good(i):
    return {"id": f"PYSEC-2026-{i}", "summary": f"Bug {i} in pkg{i}", "details": "x" * 1500,
            "aliases": [f"CVE-2026-{i}"], "published": "2026-01-01T00:00:00Z",
            "modified": "2026-02-01T00:00:00Z",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [{"package": {"name": f"pkg{i}", "ecosystem": "PyPI"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
                          "versions": ["1.0", "1.1"]}],
            "references": [{"type": "WEB", "url": f"https://example.com/{i}"}]}

def broken(i):
    kind = i % 6
    r = good(i)
    if kind == 0: del r["affected"]
    elif kind == 1: r["affected"] = [{"package": None}]
    elif kind == 2: r["severity"] = "high"
    elif kind == 3: r["affected"][0]["ranges"] = [{"events": [{"weird": 1}]}]
    elif kind == 4: del r["id"]
    else: r["aliases"] = None
    return r

size, i = 0, 0
while size < 10 * 1024 * 1024:
    rec = broken(i) if i % 10 == 0 else good(i)
    text = json.dumps(rec)
    if i % 97 == 0:
        text = text[:-20]  # truncated -> invalid JSON
    (out / f"rec_{i}.json").write_text(text)
    size += len(text); i += 1
print(f"Wrote {i} files, {size/1e6:.1f} MB")
