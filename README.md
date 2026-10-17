# OSV Vulnerability Project

## Member A - Pipeline Pioneer

### Week 1 - Foundation
- `osv_parser.py` - parses OSV JSON -> Python dict -> CSV rows / SQL INSERT strings
- `download_snapshot.py` - gets the raw PyPI snapshot into `data/raw/` (never committed)
- `make_test_chunk.py` - builds a ~10MB messy test set to prove no `KeyError`
- `sample_osv.json`, `vulnerabilities.csv`, `affected_packages.csv`, `sample_inserts.sql` - dummy data

### Week 2 - Integration
- `ingest.py` - loads OSV records into MySQL (Member B's `codeledger` schema) and the ORIGINAL
  JSON into MongoDB (for Member C). Safe to re-run: upserts, no duplicates.
- `requirements.txt` - pinned versions: `pip install -r requirements.txt`

### Week 3 - Hardening
**Speed.** `ingest.py` now writes each batch with a handful of multi-row statements instead of one
statement per row. If a batch contains a bad record, the batch is rolled back and replayed one record
at a time, so the bad record is logged and everything else still loads.
Measured against a local MySQL-compatible server on synthetic OSV-shaped data: about 3-4x faster
than the Week 2 version (e.g. ~2,600 vs ~820 records/s on 40,000 records), producing byte-identical
tables. Real numbers depend on your machine; the log tells you yours. `--slow` forces the old path.

**Metadata logs** (written to `output/` on every run):
| File | What it holds |
|---|---|
| `import_history.log` | One line per run, appended: `Imported 24,774 records on 2026-10-17 | read=... failed=... | source sha256 | seconds | fingerprint` |
| `ingest_summary.json` | Full details of the latest run: counts, failure reasons grouped, speed, snapshot hash |
| `failed_records.csv` | Every record that failed, with the reason |
| `warnings.csv` | Parts skipped inside otherwise-good records (e.g. an affected entry with no package name) |

**Offline reproducibility.** `ingest.py` never touches the internet (only your MySQL/MongoDB).
OSV republishes its snapshot daily, so the team pins ONE snapshot:
- `snapshot_manifest.json` (committed) records the pinned zip's size, record count and SHA-256.
- `ingest.py` hashes its input and warns if it is not the pinned snapshot.
- `input_fingerprint` in the summary is a hash of every record loaded: two runs on the same
  snapshot must print the same fingerprint, and produce identical database content.

```
python download_snapshot.py                    # first time only: download + pin
python download_snapshot.py --verify           # does my data/raw/PyPI.zip match the pin?
python download_snapshot.py --from-file X.zip  # OFFLINE: use the zip a teammate shared
```

Running with no internet:
```
# once, while online:
pip download -r requirements.txt -d wheels      # (do NOT commit the wheels folder)
# (wheels are OS/Python-specific: download them on the same kind of machine you'll install on)
# on the offline machine:
pip install --no-index --find-links wheels -r requirements.txt
python download_snapshot.py --from-file /path/to/shared/PyPI.zip
python ingest.py data/raw/PyPI.zip --init-schema --limit 25000
```

### Running the ingestion
```
python ingest.py data/raw/PyPI.zip --dry-run --limit 25000          # parse only, no DB
python ingest.py data/raw/PyPI.zip --init-schema --limit 25000      # creates tables, loads 25k
python ingest.py data/raw/PyPI.zip                                   # full ingestion
```
`--init-schema` runs Member B's `schema.sql` (looked up next to `ingest.py`; use
`--schema-file path/to/schema.sql` if it lives elsewhere).
Settings via env vars: MYSQL_HOST MYSQL_PORT MYSQL_USER MYSQL_PASSWORD MYSQL_DB MONGO_URI MONGO_DB
(`MYSQL_DB` / `MONGO_DB` default to `codeledger`).
