"""
ingest.py  --  Pipeline Pioneer (Member A), Week 2

Reads OSV records (osv_parser.py) and loads them into
  * MySQL   -> Member B's normalized tables (schema.sql, database `codeledger`)
  * MongoDB -> the ORIGINAL untouched OSV document (Member C needs this)

Safe to re-run: records are upserted, so there are no duplicates.
Records that fail to parse or insert go to output/failed_records.csv and
never stop the run. Skipped sub-parts (e.g. an affected entry with no
package name) go to output/warnings.csv.

Examples:
    python ingest.py data/raw/PyPI.zip --dry-run --limit 25000
    python ingest.py data/raw/PyPI.zip --init-schema --limit 25000
    python ingest.py data/raw/PyPI.zip                    # full ingestion
Connection settings (env vars or flags):
    MYSQL_HOST MYSQL_PORT MYSQL_USER MYSQL_PASSWORD MYSQL_DB  MONGO_URI MONGO_DB
"""
import argparse
import csv
import json
import os
import re
import time
from datetime import date
from pathlib import Path

from osv_parser import iter_raw_records, parse_osv_for_schema

VULN_SQL = (
    "INSERT INTO vulnerabilities (vulnerability_id, schema_version, summary, details, "
    "published_at, modified_at, withdrawn_at) VALUES (%s,%s,%s,%s,%s,%s,%s) "
    "ON DUPLICATE KEY UPDATE schema_version=VALUES(schema_version), "
    "summary=VALUES(summary), details=VALUES(details), "
    "published_at=VALUES(published_at), modified_at=VALUES(modified_at), "
    "withdrawn_at=VALUES(withdrawn_at)"
)


def parse_args():
    e = os.environ.get
    ap = argparse.ArgumentParser(description="Ingest OSV data into MySQL + MongoDB")
    ap.add_argument("source", help=".zip, folder of .json, or single .json")
    ap.add_argument("--limit", type=int, default=None, help="stop after N records")
    ap.add_argument("--batch-size", type=int, default=500, help="records per commit")
    ap.add_argument("--out", default="output")
    ap.add_argument("--init-schema", action="store_true",
                    help="run --schema-file first (creates the tables)")
    ap.add_argument("--schema-file", default=str(Path(__file__).with_name("schema.sql")))
    ap.add_argument("--dry-run", action="store_true", help="parse only, touch no database")
    ap.add_argument("--skip-mysql", action="store_true")
    ap.add_argument("--skip-mongo", action="store_true")
    ap.add_argument("--mysql-host", default=e("MYSQL_HOST", "localhost"))
    ap.add_argument("--mysql-port", type=int, default=int(e("MYSQL_PORT", "3306")))
    ap.add_argument("--mysql-user", default=e("MYSQL_USER", "root"))
    ap.add_argument("--mysql-password", default=e("MYSQL_PASSWORD", ""))
    ap.add_argument("--mysql-db", default=e("MYSQL_DB", "codeledger"))
    ap.add_argument("--mongo-uri", default=e("MONGO_URI", "mongodb://localhost:27017"))
    ap.add_argument("--mongo-db", default=e("MONGO_DB", "codeledger"))
    return ap.parse_args()


# ---------------- connections ----------------
def connect_mysql(a):
    import pymysql
    kw = dict(host=a.mysql_host, port=a.mysql_port, user=a.mysql_user,
              password=a.mysql_password, charset="utf8mb4", autocommit=False)
    if a.init_schema:
        conn = pymysql.connect(**kw)  # DB may not exist yet; schema.sql creates it
        text = Path(a.schema_file).read_text(encoding="utf-8")
        text = re.sub(r"^\s*--.*$", "", text, flags=re.M)  # drop comment lines
        with conn.cursor() as cur:
            for stmt in [s.strip() for s in text.split(";") if s.strip()]:
                cur.execute(stmt)
        conn.commit()
        conn.select_db(a.mysql_db)
        return conn
    return pymysql.connect(database=a.mysql_db, **kw)


def connect_mongo(a):
    import pymongo
    client = pymongo.MongoClient(a.mongo_uri, serverSelectionTimeoutMS=5000)
    client.admin.command("ping")  # fail fast if Mongo isn't running
    coll = client[a.mongo_db]["vulnerabilities"]
    coll.create_index("affected.package.name")
    return coll


# ---------------- MySQL writing (one record) ----------------
def get_package_id(cur, caches, a):
    eco = a["ecosystem"]
    if eco not in caches["eco"]:
        cur.execute("INSERT IGNORE INTO ecosystems (name) VALUES (%s)", (eco,))
        cur.execute("SELECT ecosystem_id FROM ecosystems WHERE name=%s", (eco,))
        caches["eco"][eco] = cur.fetchone()[0]
    eco_id = caches["eco"][eco]
    key = (eco_id, a["name"])
    if key not in caches["pkg"]:
        cur.execute("INSERT IGNORE INTO packages (ecosystem_id, name, purl) "
                    "VALUES (%s,%s,%s)", (eco_id, a["name"], a["purl"]))
        cur.execute("SELECT package_id FROM packages WHERE ecosystem_id=%s AND name=%s",
                    key)
        caches["pkg"][key] = cur.fetchone()[0]
    return caches["pkg"][key]


def write_record(cur, p, caches):
    v = p["vulnerability"]
    vid = v["id"]
    cur.execute(VULN_SQL, (vid, v["schema_version"], v["summary"], v["details"],
                           v["published_at"], v["modified_at"], v["withdrawn_at"]))
    # wipe old children so re-runs replace instead of duplicate
    for table in ("vulnerability_alias", "vulnerability_severity",
                  "vulnerability_reference", "affected_package"):
        cur.execute(f"DELETE FROM {table} WHERE vulnerability_id=%s", (vid,))

    if p["aliases"]:
        cur.executemany("INSERT IGNORE INTO vulnerability_alias "
                        "(vulnerability_id, alias_value) VALUES (%s,%s)",
                        [(vid, x) for x in p["aliases"]])
    if p["severities"]:
        cur.executemany("INSERT INTO vulnerability_severity (vulnerability_id, "
                        "severity_type, score_value, base_score, source) "
                        "VALUES (%s,%s,%s,%s,%s)",
                        [(vid, *s) for s in p["severities"]])
    if p["references"]:
        cur.executemany("INSERT INTO vulnerability_reference (vulnerability_id, "
                        "reference_type, url) VALUES (%s,%s,%s)",
                        [(vid, *r) for r in p["references"]])

    for a in p["affected"]:
        pkg_id = get_package_id(cur, caches, a)
        cur.execute("INSERT INTO affected_package (vulnerability_id, package_id) "
                    "VALUES (%s,%s)", (vid, pkg_id))
        ap_id = cur.lastrowid
        if a["severities"]:
            cur.executemany("INSERT INTO affected_package_severity (affected_package_id, "
                            "severity_type, score_value, base_score, source) "
                            "VALUES (%s,%s,%s,%s,%s)",
                            [(ap_id, *s) for s in a["severities"]])
        if a["versions"]:
            cur.executemany("INSERT IGNORE INTO affected_version "
                            "(affected_package_id, version) VALUES (%s,%s)",
                            [(ap_id, x) for x in a["versions"]])
        for r in a["ranges"]:
            cur.execute("INSERT INTO affected_range (affected_package_id, range_ordinal, "
                        "range_type, repo) VALUES (%s,%s,%s,%s)",
                        (ap_id, r["ordinal"], r["type"], r["repo"]))
            rid = cur.lastrowid
            cur.executemany("INSERT INTO range_event (range_id, event_order, "
                            "event_type, event_value) VALUES (%s,%s,%s,%s)",
                            [(rid, *ev) for ev in r["events"]])


# ---------------- MongoDB writing ----------------
def mongo_write(coll, pairs):
    import pymongo
    ops = [pymongo.ReplaceOne({"_id": i}, {**r, "_id": i}, upsert=True)
           for i, r in pairs]
    coll.bulk_write(ops, ordered=False)


def mongo_flush(coll, pending, counts, log_fail):
    """pending = [(osv_id, raw, source_name)] already safe in MySQL."""
    if not pending:
        return
    if coll is None:
        counts["loaded"] += len(pending)
        return
    try:
        mongo_write(coll, [(i, r) for i, r, _ in pending])
        counts["loaded"] += len(pending)
    except Exception:  # find the culprit one by one
        for i, r, n in pending:
            try:
                mongo_write(coll, [(i, r)])
                counts["loaded"] += 1
            except Exception as e:
                counts["failed"] += 1
                log_fail(n, i, f"MongoDB insert failed: {e}")


# ---------------- main ----------------
def main():
    a = parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    conn = coll = cur = None
    if not a.dry_run:
        if not a.skip_mysql:
            conn = connect_mysql(a)
            cur = conn.cursor()
            print("Connected to MySQL")
        if not a.skip_mongo:
            coll = connect_mongo(a)
            print("Connected to MongoDB")

    counts = {"read": 0, "loaded": 0, "failed": 0, "warnings": 0}
    caches = {"eco": {}, "pkg": {}}
    start = time.time()

    with open(out / "failed_records.csv", "w", newline="", encoding="utf-8") as ff, \
         open(out / "warnings.csv", "w", newline="", encoding="utf-8") as fwn:
        fw, ww = csv.writer(ff), csv.writer(fwn)
        fw.writerow(["source", "osv_id", "error"])
        ww.writerow(["source", "osv_id", "warning"])

        def log_fail(source, osv_id, error):
            fw.writerow([source, osv_id, error])

        pending = []

        def finish_batch():
            nonlocal pending
            if conn:
                conn.commit()
            mongo_flush(coll, pending, counts, log_fail)
            pending = []
            print(f"  ...{counts['read']} read, {counts['loaded']} loaded, "
                  f"{counts['failed']} failed", flush=True)

        for name, raw in iter_raw_records(a.source):
            if a.limit and counts["read"] >= a.limit:
                break
            counts["read"] += 1
            try:
                if isinstance(raw, Exception):
                    raise ValueError(f"bad JSON: {raw}")
                p = parse_osv_for_schema(raw)
            except Exception as e:
                counts["failed"] += 1
                log_fail(name, "", str(e))
                continue

            vid = p["vulnerability"]["id"]
            for w in p["warnings"]:
                counts["warnings"] += 1
                ww.writerow([name, vid, w])

            if a.dry_run:
                counts["loaded"] += 1
                continue

            if conn:
                try:
                    cur.execute("SAVEPOINT rec")
                    write_record(cur, p, caches)
                    cur.execute("RELEASE SAVEPOINT rec")
                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT rec")
                    caches["eco"].clear()   # cached ids may belong to rolled-back rows
                    caches["pkg"].clear()
                    counts["failed"] += 1
                    log_fail(name, vid, f"MySQL insert failed: {e}")
                    continue
            pending.append((vid, raw, name))
            if len(pending) >= a.batch_size:
                finish_batch()
        if not a.dry_run:
            finish_batch()

    summary = {
        "imported_at": date.today().isoformat(),
        "records_read": counts["read"],
        "records_loaded": counts["loaded"],
        "records_failed": counts["failed"],
        "warnings": counts["warnings"],
        "seconds": round(time.time() - start, 1),
        "dry_run": a.dry_run,
        "message": f"Imported {counts['loaded']} records on {date.today().isoformat()}",
    }
    (out / "ingest_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    if conn:
        conn.close()


if __name__ == "__main__":
    main()
