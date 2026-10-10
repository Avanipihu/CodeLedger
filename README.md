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

## Week 2 - Integration (Member A)
- `ingest.py` - loads OSV records into MySQL (Member B's `codeledger` schema) and MongoDB (original document).
  Safe to re-run: upserts, no duplicates.
- `osv_parser.py` - now also has `parse_osv_for_schema()` + a CVSS v3 base-score calculator.
- `schema.sql` - Member B's schema, copied here ONLY for local testing. Do not commit over theirs.
- `requirements.txt` - `pip install -r requirements.txt`
- Output: `output/failed_records.csv`, `output/warnings.csv`, `output/ingest_summary.json`

```
python ingest.py data/raw/PyPI.zip --dry-run --limit 25000          # parse only, no DB
python ingest.py data/raw/PyPI.zip --init-schema --limit 25000      # creates tables, loads 25k
python ingest.py data/raw/PyPI.zip                                   # full ingestion
```
Settings via env vars: MYSQL_HOST MYSQL_PORT MYSQL_USER MYSQL_PASSWORD MYSQL_DB MONGO_URI MONGO_DB
(MYSQL_DB defaults to `codeledger`.)
