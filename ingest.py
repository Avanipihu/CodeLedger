"""
ingest.py  --  Pipeline Pioneer (Member A), Week 3 (hardened + fast)

Reads OSV records (osv_parser.py) and loads them into
  * MySQL   -> Member B's normalized tables (schema.sql, database `codeledger`)
  * MongoDB -> the ORIGINAL untouched OSV document (Member C needs this)

What's new in Week 3
  * FAST: each batch is written with a handful of multi-row statements
    instead of one statement per row. If a batch hits a bad record, it is
    rolled back and replayed one record at a time, so a single bad record
    can never block the rest (and gets logged).
  * METADATA LOGS: every run writes output/ingest_summary.json and appends a
    human-readable line to output/import_history.log, e.g.
        "Imported 24,774 records on 2026-10-17"
  * OFFLINE / REPRODUCIBLE: no network access is used here; the run records
    the SHA-256 of the input snapshot and compares it with
    snapshot_manifest.json; an `input_fingerprint` proves two runs saw the
    same data.

Safe to re-run: records are upserted, so there are no duplicates.

Examples:
    python ingest.py data/raw/PyPI.zip --dry-run --limit 25000
    python ingest.py data/raw/PyPI.zip --init-schema --limit 25000
    python ingest.py data/raw/PyPI.zip                    # full ingestion
Connection settings (env vars or flags):
    MYSQL_HOST MYSQL_PORT MYSQL_USER MYSQL_PASSWORD MYSQL_DB  MONGO_URI MONGO_DB
"""
import argparse
import csv
import hashlib
import json
import os
import re
import time
from collections import Counter
from datetime import date, datetime
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
ALIAS_SQL = ("INSERT IGNORE INTO vulnerability_alias (vulnerability_id, alias_value) "
             "VALUES (%s,%s)")
VSEV_SQL = ("INSERT INTO vulnerability_severity (vulnerability_id, severity_type, "
            "score_value, base_score, source) VALUES (%s,%s,%s,%s,%s)")
REF_SQL = ("INSERT INTO vulnerability_reference (vulnerability_id, reference_type, url) "
           "VALUES (%s,%s,%s)")
AP_SQL = "INSERT INTO affected_package (vulnerability_id, package_id) VALUES (%s,%s)"
APSEV_SQL = ("INSERT INTO affected_package_severity (affected_package_id, severity_type, "
             "score_value, base_score, source) VALUES (%s,%s,%s,%s,%s)")
AVER_SQL = ("INSERT IGNORE INTO affected_version (affected_package_id, version) "
            "VALUES (%s,%s)")
RANGE_SQL = ("INSERT INTO affected_range (affected_package_id, range_ordinal, "
             "range_type, repo) VALUES (%s,%s,%s,%s)")
EVENT_SQL = ("INSERT INTO range_event (range_id, event_order, event_type, event_value) "
             "VALUES (%s,%s,%s,%s)")
CHILD_TABLES = ("vulnerability_alias", "vulnerability_severity",
                "vulnerability_reference", "affected_package")  # last one cascades

MANIFEST = Path(__file__).with_name("snapshot_manifest.json")


def parse_args():
    e = os.environ.get
    ap = argparse.ArgumentParser(description="Ingest OSV data into MySQL + MongoDB")
    ap.add_argument("source", help=".zip, folder of .json, or single .json")
    ap.add_argument("--limit", type=int, default=None, help="stop after N records")
    ap.add_argument("--batch-size", type=int, default=1000, help="records per commit")
    ap.add_argument("--out", default="output")
    ap.add_argument("--init-schema", action="store_true",
                    help="run --schema-file first (creates the tables)")
    ap.add_argument("--schema-file", default=str(Path(__file__).with_name("schema.sql")))
    ap.add_argument("--dry-run", action="store_true", help="parse only, touch no database")
    ap.add_argument("--skip-mysql", action="store_true")
    ap.add_argument("--skip-mongo", action="store_true")
    ap.add_argument("--slow", action="store_true",
                    help="force the old one-record-at-a-time path (for comparison)")
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


# ---------------- helpers ----------------
def chunks(seq, n=500):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def _in(n):
    return ",".join(["%s"] * n)


def vuln_tuple(p):
    v = p["vulnerability"]
    return (v["id"], v["schema_version"], v["summary"], v["details"],
            v["published_at"], v["modified_at"], v["withdrawn_at"])


# ---------------- SLOW PATH: one record at a time (fallback) ----------------
def get_package_id(cur, caches, a):
    ekey = a["ecosystem"].casefold()
    if ekey not in caches["eco"]:
        cur.execute("INSERT IGNORE INTO ecosystems (name) VALUES (%s)", (a["ecosystem"],))
        cur.execute("SELECT ecosystem_id FROM ecosystems WHERE name=%s", (a["ecosystem"],))
        caches["eco"][ekey] = cur.fetchone()[0]
    eco_id = caches["eco"][ekey]
    pkey = (eco_id, a["name"].casefold())
    if pkey not in caches["pkg"]:
        cur.execute("INSERT IGNORE INTO packages (ecosystem_id, name, purl) "
                    "VALUES (%s,%s,%s)", (eco_id, a["name"], a["purl"]))
        cur.execute("SELECT package_id FROM packages WHERE ecosystem_id=%s AND name=%s",
                    (eco_id, a["name"]))
        caches["pkg"][pkey] = cur.fetchone()[0]
    return caches["pkg"][pkey]


def write_record(cur, p, caches):
    vid = p["vulnerability"]["id"]
    cur.execute(VULN_SQL, vuln_tuple(p))
    for table in CHILD_TABLES:  # wipe old children so re-runs replace, not duplicate
        cur.execute(f"DELETE FROM {table} WHERE vulnerability_id=%s", (vid,))
    if p["aliases"]:
        cur.executemany(ALIAS_SQL, [(vid, x) for x in p["aliases"]])
    if p["severities"]:
        cur.executemany(VSEV_SQL, [(vid, *s) for s in p["severities"]])
    if p["references"]:
        cur.executemany(REF_SQL, [(vid, *r) for r in p["references"]])
    for a in p["affected"]:
        pkg_id = get_package_id(cur, caches, a)
        cur.execute(AP_SQL, (vid, pkg_id))
        ap_id = cur.lastrowid
        if a["severities"]:
            cur.executemany(APSEV_SQL, [(ap_id, *s) for s in a["severities"]])
        if a["versions"]:
            cur.executemany(AVER_SQL, [(ap_id, x) for x in a["versions"]])
        for r in a["ranges"]:
            cur.execute(RANGE_SQL, (ap_id, r["ordinal"], r["type"], r["repo"]))
            rid = cur.lastrowid
            cur.executemany(EVENT_SQL, [(rid, *ev) for ev in r["events"]])


# ---------------- FAST PATH: whole batch, few statements ----------------
def resolve_packages(cur, recs, caches):
    """Make sure every ecosystem/package in the batch exists; fill caches."""
    need_eco = {}
    for p in recs:
        for a in p["affected"]:
            k = a["ecosystem"].casefold()
            if k not in caches["eco"]:
                need_eco[k] = a["ecosystem"]
    if need_eco:
        names = list(need_eco.values())
        cur.executemany("INSERT IGNORE INTO ecosystems (name) VALUES (%s)",
                        [(n,) for n in names])
        for ch in chunks(names):
            cur.execute(f"SELECT ecosystem_id, name FROM ecosystems "
                        f"WHERE name IN ({_in(len(ch))})", ch)
            for eid, n in cur.fetchall():
                caches["eco"][n.casefold()] = eid

    need = {}
    for p in recs:
        for a in p["affected"]:
            eid = caches["eco"][a["ecosystem"].casefold()]
            k = (eid, a["name"].casefold())
            if k not in caches["pkg"] and k not in need:
                need[k] = (eid, a["name"], a["purl"])
    if need:
        cur.executemany("INSERT IGNORE INTO packages (ecosystem_id, name, purl) "
                        "VALUES (%s,%s,%s)", list(need.values()))
        for ch in chunks(list(need), 300):
            flat = [x for k in ch for x in (k[0], need[k][1])]
            cur.execute("SELECT package_id, ecosystem_id, name FROM packages WHERE "
                        "(ecosystem_id, name) IN (" + ",".join(["(%s,%s)"] * len(ch)) + ")",
                        flat)
            for pid, eid, n in cur.fetchall():
                caches["pkg"][(eid, n.casefold())] = pid


def write_batch(cur, items, caches):
    by_id = {p["vulnerability"]["id"]: p for p in items}  # same id twice: last wins
    recs = list(by_id.values())
    vids = list(by_id)

    cur.executemany(VULN_SQL, [vuln_tuple(p) for p in recs])
    for table in CHILD_TABLES:
        for ch in chunks(vids):
            cur.execute(f"DELETE FROM {table} WHERE vulnerability_id IN ({_in(len(ch))})", ch)

    rows = [(p["vulnerability"]["id"], x) for p in recs for x in p["aliases"]]
    if rows:
        cur.executemany(ALIAS_SQL, rows)
    rows = [(p["vulnerability"]["id"], *s) for p in recs for s in p["severities"]]
    if rows:
        cur.executemany(VSEV_SQL, rows)
    rows = [(p["vulnerability"]["id"], *r) for p in recs for r in p["references"]]
    if rows:
        cur.executemany(REF_SQL, rows)

    resolve_packages(cur, recs, caches)
    plan = []  # (vid, affected_dict, package_id)
    for p in recs:
        vid = p["vulnerability"]["id"]
        for a in p["affected"]:
            pid = caches["pkg"][(caches["eco"][a["ecosystem"].casefold()],
                                 a["name"].casefold())]
            plan.append((vid, a, pid))
    if not plan:
        return

    cur.executemany(AP_SQL, [(v, pid) for v, _, pid in plan])
    ap_ids = {}
    for ch in chunks(vids):
        cur.execute("SELECT affected_package_id, vulnerability_id, package_id FROM "
                    f"affected_package WHERE vulnerability_id IN ({_in(len(ch))})", ch)
        for apid, v, pid in cur.fetchall():
            ap_ids[(v, pid)] = apid

    sev_rows, ver_rows, rng_rows = [], [], []
    for v, a, pid in plan:
        apid = ap_ids[(v, pid)]
        sev_rows += [(apid, *s) for s in a["severities"]]
        ver_rows += [(apid, x) for x in a["versions"]]
        rng_rows += [(apid, r["ordinal"], r["type"], r["repo"]) for r in a["ranges"]]
    if sev_rows:
        cur.executemany(APSEV_SQL, sev_rows)
    if ver_rows:
        cur.executemany(AVER_SQL, ver_rows)
    if not rng_rows:
        return
    cur.executemany(RANGE_SQL, rng_rows)

    range_ids = {}
    ap_list = list({apid for apid, *_ in rng_rows})
    for ch in chunks(ap_list):
        cur.execute("SELECT range_id, affected_package_id, range_ordinal FROM "
                    f"affected_range WHERE affected_package_id IN ({_in(len(ch))})", ch)
        for rid, apid, ordn in cur.fetchall():
            range_ids[(apid, ordn)] = rid
    ev_rows = []
    for v, a, pid in plan:
        apid = ap_ids[(v, pid)]
        for r in a["ranges"]:
            rid = range_ids[(apid, r["ordinal"])]
            ev_rows += [(rid, *ev) for ev in r["events"]]
    if ev_rows:
        cur.executemany(EVENT_SQL, ev_rows)


def load_batch(conn, cur, batch, caches, counts, log_fail, force_slow=False):
    """batch = [(parsed, raw, source_name)]. Returns the ones now safe in MySQL."""
    if not force_slow:
        try:
            write_batch(cur, [p for p, _, _ in batch], caches)
            return batch
        except Exception:
            conn.rollback()  # earlier batches are already committed; this undoes only this one
            caches["eco"].clear()
            caches["pkg"].clear()
            counts["slow_batches"] += 1
    ok = []
    for item in batch:  # replay one by one to find the culprit(s)
        p, _, name = item
        try:
            cur.execute("SAVEPOINT rec")
            write_record(cur, p, caches)
            cur.execute("RELEASE SAVEPOINT rec")
            ok.append(item)
        except Exception as e:
            cur.execute("ROLLBACK TO SAVEPOINT rec")
            caches["eco"].clear()   # cached ids may belong to rolled-back rows
            caches["pkg"].clear()
            counts["failed"] += 1
            log_fail(name, p["vulnerability"]["id"], f"MySQL insert failed: {e}")
    return ok


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


# ---------------- reproducibility + metadata ----------------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def check_snapshot(source):
    """-> (sha256 or None, matches_manifest True/False/None)"""
    p = Path(source)
    if not p.is_file():
        return None, None
    digest = sha256_file(p)
    if MANIFEST.exists():
        try:
            pinned = json.loads(MANIFEST.read_text()).get("sha256")
        except Exception:
            pinned = None
        if pinned:
            match = digest == pinned
            if not match:
                print("WARNING: this snapshot is NOT the one pinned in "
                      "snapshot_manifest.json - results may differ from the team's.")
            return digest, match
    return digest, None


def reason_key(msg):
    if msg.startswith("bad JSON"):
        return "bad JSON"
    return re.sub(r"\d+", "N", msg)[:70]


def fmt_history(s):
    when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sha = (s["source_sha256"] or "n/a")[:12]
    return (f"[{when}] {s['message']} | read={s['records_read']:,} "
            f"failed={s['records_failed']:,} warnings={s['warnings']:,} | "
            f"source={s['source']} sha256={sha} | {s['seconds']}s "
            f"({s['records_per_second']:,.0f} rec/s) | "
            f"fingerprint={s['input_fingerprint'][:12]} | dry_run={s['dry_run']}")


# ---------------- main ----------------
def main():
    a = parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    src_sha, pinned_ok = check_snapshot(a.source)
    conn = coll = cur = None
    if not a.dry_run:
        if not a.skip_mysql:
            conn = connect_mysql(a)
            cur = conn.cursor()
            print("Connected to MySQL")
        if not a.skip_mongo:
            coll = connect_mongo(a)
            print("Connected to MongoDB")

    counts = {"read": 0, "loaded": 0, "failed": 0, "warnings": 0, "slow_batches": 0}
    caches = {"eco": {}, "pkg": {}}
    fingerprint_items = []
    reasons = Counter()
    start = time.time()

    with open(out / "failed_records.csv", "w", newline="", encoding="utf-8") as ff, \
         open(out / "warnings.csv", "w", newline="", encoding="utf-8") as fwn:
        fw, ww = csv.writer(ff), csv.writer(fwn)
        fw.writerow(["source", "osv_id", "error"])
        ww.writerow(["source", "osv_id", "warning"])

        def log_fail(source, osv_id, error):
            reasons[reason_key(error)] += 1
            fw.writerow([source, osv_id, error])

        batch = []

        def finish_batch():
            nonlocal batch
            if batch:
                ok = load_batch(conn, cur, batch, caches, counts, log_fail, a.slow) \
                    if conn else batch
                if conn:
                    conn.commit()
                pending = [(p["vulnerability"]["id"], raw, name) for p, raw, name in ok]
                fingerprint_items.extend(
                    f"{i}|{raw.get('modified', '')}" for i, raw, _ in pending)
                mongo_flush(coll, pending, counts, log_fail)
            batch = []
            print(f"  ...{counts['read']:,} read, {counts['loaded']:,} loaded, "
                  f"{counts['failed']:,} failed", flush=True)

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
                fingerprint_items.append(f"{vid}|{raw.get('modified', '')}")
                continue

            batch.append((p, raw, name))
            if len(batch) >= a.batch_size:
                finish_batch()
        if not a.dry_run:
            finish_batch()

    secs = round(time.time() - start, 2)
    today = date.today().isoformat()
    fp = hashlib.sha256("\n".join(sorted(fingerprint_items)).encode()).hexdigest()
    summary = {
        "imported_at": today,
        "run_finished_at": datetime.now().isoformat(timespec="seconds"),
        "message": f"Imported {counts['loaded']:,} records on {today}",
        "source": Path(a.source).name,
        "source_sha256": src_sha,
        "matches_pinned_snapshot": pinned_ok,
        "records_read": counts["read"],
        "records_loaded": counts["loaded"],
        "records_failed": counts["failed"],
        "warnings": counts["warnings"],
        "failure_reasons": dict(reasons.most_common()),
        "seconds": secs,
        "records_per_second": round(counts["read"] / secs, 1) if secs else 0,
        "batch_size": a.batch_size,
        "slow_path_batches": counts["slow_batches"],
        "input_fingerprint": fp,
        "dry_run": a.dry_run,
    }
    (out / "ingest_summary.json").write_text(json.dumps(summary, indent=2))
    with open(out / "import_history.log", "a", encoding="utf-8") as h:
        h.write(fmt_history(summary) + "\n")
    print(json.dumps(summary, indent=2))
    if conn:
        conn.close()


if __name__ == "__main__":
    main()
