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
import math
import re
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


# ---------- Week 2: richer parse that matches Member B's schema.sql ----------
from datetime import datetime

_DT_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})(?:[T ](\d{2}:\d{2}:\d{2}))?")


def _dt(v):
    """OSV timestamp -> 'YYYY-MM-DD HH:MM:SS' (MySQL DATETIME) or None."""
    m = _DT_RE.match(_s(v))
    if not m:
        return None
    text = f"{m.group(1)} {m.group(2) or '00:00:00'}"
    try:
        datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return text


def _roundup(x):
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector):
    """CVSS v3.x base score (0-10) from a vector string, or None if unusable."""
    try:
        m = dict(p.split(":", 1) for p in vector.split("/")[1:])
        changed = m["S"] == "C"
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62,
              "H": 0.5 if changed else 0.27}[m["PR"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        iss = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
        impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if changed \
            else 6.42 * iss
        expl = 8.22 * av * ac * pr * ui
        if impact <= 0:
            return 0.0
        total = 1.08 * (impact + expl) if changed else impact + expl
        return _roundup(min(total, 10))
    except Exception:
        return None


def _severities(items):
    out = []
    for sev in _list(items):
        sev = _dict(sev)
        stype, score = _s(sev.get("type")), _s(sev.get("score"))
        if not stype or not score:
            continue
        base = cvss3_base_score(score) if stype == "CVSS_V3" else None
        out.append((stype[:30], score[:255], base, None))
    return out


def parse_osv_for_schema(raw):
    """
    Parse ONE OSV record into the shape Member B's tables need.
    Returns dict with: vulnerability, aliases, severities, references,
    affected (merged per package), warnings.  Raises ValueError if unusable.
    """
    if not isinstance(raw, dict):
        raise ValueError("record is not a JSON object")
    vid = _s(raw.get("id"))
    if not vid:
        raise ValueError("missing 'id'")
    if len(vid) > 100:
        raise ValueError("id longer than 100 characters")
    warnings = []

    vuln = {
        "id": vid,
        "schema_version": _s(raw.get("schema_version"))[:30] or None,
        "summary": _s(raw.get("summary")) or None,
        "details": _s(raw.get("details")) or None,
        "published_at": _dt(raw.get("published")),
        "modified_at": _dt(raw.get("modified")),
        "withdrawn_at": _dt(raw.get("withdrawn")),
    }

    aliases = list(dict.fromkeys(
        str(a).strip()[:100] for a in _list(raw.get("aliases"))
        if isinstance(a, (str, int)) and str(a).strip()))

    references = []
    for ref in _list(raw.get("references")):
        ref = _dict(ref)
        url = _s(ref.get("url"))
        if url:
            references.append((_s(ref.get("type"))[:40] or "WEB", url[:2048]))

    merged = {}
    for entry in _list(raw.get("affected")):
        entry = _dict(entry)
        pkg = _dict(entry.get("package"))
        name, eco = _s(pkg.get("name")), _s(pkg.get("ecosystem"))
        if not name or not eco:
            warnings.append("affected entry skipped: missing package name/ecosystem")
            continue
        a = merged.setdefault((eco, name), {
            "ecosystem": eco[:100], "name": name[:255],
            "purl": _s(pkg.get("purl"))[:512] or None,
            "severities": [], "versions": [], "ranges": []})
        a["severities"].extend(_severities(entry.get("severity")))
        for v in _list(entry.get("versions")):
            if isinstance(v, (str, int, float)) and str(v).strip():
                a["versions"].append(str(v).strip()[:255])
        for rng in _list(entry.get("ranges")):
            rng = _dict(rng)
            events = []
            for ev in _list(rng.get("events")):
                for etype, val in _dict(ev).items():
                    if etype in ("introduced", "fixed", "last_affected", "limit") \
                            and isinstance(val, (str, int, float)) and str(val).strip():
                        events.append((len(events) + 1, etype, str(val).strip()[:255]))
            if events:
                a["ranges"].append({
                    "ordinal": len(a["ranges"]) + 1,
                    "type": _s(rng.get("type"))[:30] or "UNKNOWN",
                    "repo": _s(rng.get("repo"))[:512] or None,
                    "events": events})
    for a in merged.values():
        a["versions"] = list(dict.fromkeys(a["versions"]))

    return {"vulnerability": vuln, "aliases": aliases,
            "severities": _severities(raw.get("severity")),
            "references": references, "affected": list(merged.values()),
            "warnings": warnings}


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
