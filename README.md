# OSV Vulnerability Project

## Member A - Pipeline Pioneer (Week 1 deliverables)
- `osv_parser.py`  - parses OSV JSON -> Python dict -> CSV rows / SQL INSERT strings
- `scripts/download_snapshot.py` - downloads the raw PyPI snapshot to `data/raw/` (gitignored)
- `scripts/make_test_chunk.py` - builds a ~10MB messy test set to prove no `KeyError`
- `sample_data/sample_osv.json` - ONE tiny sample record (safe to commit)
- `output/*.csv`, `output/sample_inserts.sql` - dummy CSVs + sample SQL

## Quick run
```
python scripts/download_snapshot.py                # ~ raw data, NOT committed
python osv_parser.py data/raw/PyPI.zip --max-mb 10 # the "10MB chunk" checklist test
python osv_parser.py sample_data/sample_osv.json   # tiny demo
```
Check `output/import_summary.json` and `output/import_log.csv` afterwards.
