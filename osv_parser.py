"""
osv_parser.py  --  Pipeline Pioneer (Member A), Week 1

Parses OSV (Open Source Vulnerability) JSON records into plain Python
dictionaries, then into CSV rows and SQL INSERT strings.

Design rule: NEVER index a dict with raw["key"]. OSV records are messy
(missing fields, wrong types, nulls), so everything uses .get() plus
type checks. A bad record is logged and skipped - it must never crash
the whole run (no KeyError!).

Usage:
    python osv_parser.py sample_data/sample_osv.json
    python osv_parser.py data/raw/PyPI.zip --max-mb 10
    python osv_parser.py data/raw/PyPI/ --out output
"""
import argparse
import csv
import json
import logging
import time
import zipfile
from pathlib import Path

log = logging.getLogger("osv_parser")


# ---------- tiny safe-access helpers ----------
def _s(v):
    """Return stripped string or '' (never None, never crashes)."""
    return v.strip() if isinstance(v, str) else ""


def _list(v):
    return v if isinstance(v, list) else []


def _dict(v):
    return v if isinstance(v, dict) else {}


# ---------- core: JSON -> Python dictionary ----------
def parse_osv_record(raw):
    """
    Turn ONE raw OSV JSON object into a clean dictionary:
    {
      "id", "summary", "details", "published", "modified", "severity",
      "aliases": [...], "references": [...],
      "affected": [ {"package_name","ecosystem","introduced","fixed","versions"} ... ]
    }
    Raises ValueError only if the record is unusable (no id).
    """
    if not isinstance(raw, dict):
        raise ValueError("record is not a JSON object")

    osv_id = _s(raw.get("id"))
    if not osv_id:
        raise ValueError("missing 'id'")

    severity = ""
    for sev in _list(raw.get("severity")):
        score = _s(_dict(sev).get("score"))
        if score:
            severity = score  # e.g. a CVSS vector string
            break

    affected = []
    for entry in _list(raw.get("affected")):
        entry = _dict(entry)
        pkg = _dict(entry.get("package"))
        name = _s(pkg.get("name"))
        ecosystem = _s(pkg.get("ecosystem"))
        versions = ";".join(str(v) for v in _list(entry.get("versions")))

        # Turn the event list into (introduced, fixed) pairs
        pairs = []
        for rng in _list(entry.get("ranges")):
            introduced = None
            for ev in _list(_dict(rng).get("events")):
                ev = _dict(ev)
                if "introduced" in ev:
                    if introduced is not None:
                        pairs.append((introduced, ""))
                    introduced = str(ev["introduced"])
                elif "fixed" in ev:
                    pairs.append((introduced or "", str(ev["fixed"])))
                    introduced = None
                elif "last_affected" in ev:
                    pairs.append((introduced or "", ""))
                    introduced = None
            if introduced is not None:
                pairs.append((introduced, ""))
        if not pairs:
            pairs = [("", "")]

        for introduced, fixed in pairs:
            affected.append({
                "package_name": name,
                "ecosystem": ecosystem,
                "introduced": introduced,
                "fixed": fixed,
                "versions": versions,
            })

    references = [_s(_dict(r).get("url")) for r in _list(raw.get("references"))
                  if _s(_dict(r).get("url"))]

    return {
        "id": osv_id,
        "summary": _s(raw.get("summary")),
        "details": _s(raw.get("details")),
        "published": _s(raw.get("published")),
        "modified": _s(raw.get("modified")),
        "severity": severity,
        "aliases": [str(a) for a in _list(raw.get("aliases"))],
        "references": references,
        "affected": affected,
    }


# ---------- dictionary -> CSV rows ----------
VULN_COLUMNS = ["osv_id", "summary", "details", "published", "modified",
                "severity", "aliases"]
AFFECTED_COLUMNS = ["osv_id", "package_name", "ecosystem", "introduced",
                    "fixed", "affected_versions"]


def to_vuln_row(rec):
    return [rec["id"], rec["summary"], rec["details"], rec["published"],
            rec["modified"], rec["severity"], ";".join(rec["aliases"])]


def to_affected_rows(rec):
    return [[rec["id"], a["package_name"], a["ecosystem"], a["introduced"],
             a["fixed"], a["versions"]] for a in rec["affected"]]


# ---------- dictionary -> SQL INSERT strings (MySQL-safe escaping) ----------
def _q(value):
    """Quote a value for a SQL string literal ('' if empty -> NULL)."""
    if value == "" or value is None:
        return "NULL"
    v = str(value).replace("\\", "\\\\").replace("'", "''")
    return f"'{v}'"


def to_sql_inserts(rec):
    stmts = [
        "INSERT INTO vulnerabilities (osv_id, summary, details, published, "
        "modified, severity, aliases) VALUES ("
        + ", ".join(_q(x) for x in to_vuln_row(rec)) + ");"
    ]
    for row in to_affected_rows(rec):
        stmts.append(
            "INSERT INTO affected_packages (osv_id, package_name, ecosystem, "
            "introduced, fixed, affected_versions) VALUES ("
            + ", ".join(_q(x) for x in row) + ");"
        )
    return stmts


# ---------- reading sources: .json file, folder of .json, or .zip ----------
def iter_raw_records(source, max_bytes=None):
    """
    Yields (source_name, parsed_json_or_Exception).
    Stops after max_bytes of input if given (e.g. 10MB test chunk).
    """
    source = Path(source)
    total = 0

    def budget_hit():
        return max_bytes is not None and total >= max_bytes

    if source.is_dir():
        for p in sorted(source.rglob("*.json")):
            if budget_hit():
                return
            data = p.read_bytes()
            total += len(data)
            yield p.name, _load(data)
    elif source.suffix == ".zip":
        with zipfile.ZipFile(source) as z:
            for name in z.namelist():
                if not name.endswith(".json"):
                    continue
                if budget_hit():
                    return
                data = z.read(name)
                total += len(data)
                yield name, _load(data)
    else:  # single file: one object OR a list of objects
        data = source.read_bytes()
        loaded = _load(data)
        if isinstance(loaded, list):
            for i, item in enumerate(loaded):
                yield f"{source.name}[{i}]", item
        else:
            yield source.name, loaded


def _load(data):
    try:
        return json.loads(data)
    except Exception as e:  # malformed JSON -> return the error, don't crash
        return e


# ---------- main pipeline ----------
def run(source, out_dir="output", max_bytes=None, sql_limit=50):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    start = time.time()
    ok = failed = 0
    sql_lines = []

    with open(out / "vulnerabilities.csv", "w", newline="", encoding="utf-8") as fv, \
         open(out / "affected_packages.csv", "w", newline="", encoding="utf-8") as fa, \
         open(out / "import_log.csv", "w", newline="", encoding="utf-8") as fl:
        wv, wa, wl = csv.writer(fv), csv.writer(fa), csv.writer(fl)
        wv.writerow(VULN_COLUMNS)
        wa.writerow(AFFECTED_COLUMNS)
        wl.writerow(["source", "status", "osv_id", "error"])

        for name, raw in iter_raw_records(source, max_bytes):
            try:
                if isinstance(raw, Exception):
                    raise ValueError(f"bad JSON: {raw}")
                rec = parse_osv_record(raw)
                wv.writerow(to_vuln_row(rec))
                wa.writerows(to_affected_rows(rec))
                if len(sql_lines) < sql_limit:
                    sql_lines.extend(to_sql_inserts(rec))
                wl.writerow([name, "OK", rec["id"], ""])
                ok += 1
            except Exception as e:  # one bad record never stops the run
                wl.writerow([name, "FAILED", "", str(e)])
                failed += 1

    (out / "sample_inserts.sql").write_text("\n".join(sql_lines) + "\n", encoding="utf-8")
    summary = {"succeeded": ok, "failed": failed,
               "seconds": round(time.time() - start, 2)}
    (out / "import_summary.json").write_text(json.dumps(summary, indent=2))
    log.info("Done: %s", summary)
    return summary


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    ap = argparse.ArgumentParser(description="Parse OSV JSON into CSV/SQL")
    ap.add_argument("source", help=".json file, folder of .json, or .zip")
    ap.add_argument("--out", default="output")
    ap.add_argument("--max-mb", type=float, default=None,
                    help="only read this many MB of input (e.g. 10)")
    ap.add_argument("--sql-limit", type=int, default=50,
                    help="max number of SQL insert lines to write")
    a = ap.parse_args()
    run(a.source, a.out, int(a.max_mb * 1024 * 1024) if a.max_mb else None, a.sql_limit)
