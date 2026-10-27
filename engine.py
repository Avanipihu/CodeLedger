"""
Core matching and persistence engine for CodeLedger.
Resolves OSV boundaries, enriches from MongoDB, and persists scan records in MySQL.

Run `python matching_engine.py` directly to test both database connections.
"""
from __future__ import annotations

import logging
import os
import re
import ssl
from datetime import datetime
from urllib.parse import unquote, urlparse

import pymongo
import pymysql
from dotenv import load_dotenv

from matcher import is_vulnerable

load_dotenv()
log = logging.getLogger("codeledger.engine")

ECOSYSTEM = "PyPI"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def normalize_name(name: str) -> str:
    """PEP 503 normalization: Flask_Cors, flask.cors, flask-cors -> flask-cors."""
    return re.sub(r"[-_.]+", "-", (name or "").strip()).lower()


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes")


# --------------------------------------------------------------------------
# Connections
# --------------------------------------------------------------------------
def _mysql_settings() -> dict:
    cfg = {
        "host": os.getenv("MYSQL_HOST", "localhost"),
        "port": int(os.getenv("MYSQL_PORT", "3306")),
        "user": os.getenv("MYSQL_USER", "root"),
        "password": os.getenv("MYSQL_PASSWORD", os.getenv("DB_PASSWORD", "")),
        "database": os.getenv("MYSQL_DB", "codeledger"),
    }
    uri = os.getenv("MYSQL_URI") or os.getenv("DATABASE_URL")
    if uri:
        u = urlparse(uri)
        cfg.update(
            host=u.hostname or cfg["host"],
            port=u.port or cfg["port"],
            user=unquote(u.username) if u.username else cfg["user"],
            password=unquote(u.password) if u.password else cfg["password"],
            database=(u.path or "/").lstrip("/") or cfg["database"],
        )
    return cfg


def _ssl_option(host: str):
    """
    - MYSQL_SSL_CA set          -> verify the server against that CA (recommended).
    - SSL requested, no CA      -> verify against system CAs.
    - MYSQL_SSL_INSECURE=true   -> skip verification (local dev only).
    """
    ca = os.getenv("MYSQL_SSL_CA")
    if ca:
        if not os.path.exists(ca):
            raise FileNotFoundError(f"MYSQL_SSL_CA points to a missing file: {ca}")
        return ssl.create_default_context(cafile=ca)

    wants_ssl = (
        _truthy(os.getenv("MYSQL_SSL"))
        or "aivencloud.com" in (host or "")
        or "aiven.io" in (host or "")
        or bool(os.getenv("MYSQL_URI") or os.getenv("DATABASE_URL"))
    )
    if not wants_ssl:
        return None

    ctx = ssl.create_default_context()
    if _truthy(os.getenv("MYSQL_SSL_INSECURE")):
        log.warning("MySQL TLS verification is DISABLED (MYSQL_SSL_INSECURE).")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def get_mysql_connection():
    cfg = _mysql_settings()
    kwargs = dict(
        host=cfg["host"], port=cfg["port"], user=cfg["user"],
        password=cfg["password"], database=cfg["database"],
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=5,
    )
    ssl_opt = _ssl_option(cfg["host"])
    if ssl_opt is not None:
        kwargs["ssl"] = ssl_opt
    return pymysql.connect(**kwargs)


_mongo_client: pymongo.MongoClient | None = None


def get_mongo_collection():
    """Shared MongoClient (created once, reused)."""
    global _mongo_client
    if _mongo_client is None:
        _mongo_client = pymongo.MongoClient(
            os.getenv("MONGO_URI", "mongodb://localhost:27017/"),
            serverSelectionTimeoutMS=3000,
        )
    return _mongo_client[os.getenv("MONGO_DB", "codeledger")]["vulnerabilities"]


def check_connections() -> dict:
    """Returns {'mysql': 'ok' | error text, 'mongo': 'ok' | error text}."""
    result = {}
    try:
        conn = get_mysql_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
        conn.close()
        result["mysql"] = "ok"
    except Exception as e:
        result["mysql"] = f"{type(e).__name__}: {e}"
    try:
        get_mongo_collection().database.client.admin.command("ping")
        result["mongo"] = "ok"
    except Exception as e:
        result["mongo"] = f"{type(e).__name__}: {e}"
    return result


# --------------------------------------------------------------------------
# Vulnerability lookup & matching
# --------------------------------------------------------------------------
def fetch_package_vulnerabilities(cursor, package_name: str) -> dict:
    """
    Returns {vulnerability_id: {range_id: [event rows in order]}}.
    Restricted to the PyPI ecosystem and matched on a normalized name.
    """
    query = """
        SELECT
            v.vulnerability_id,
            ar.range_id,
            re.event_id,
            re.event_type,
            re.event_value
        FROM packages p
        JOIN ecosystems e ON p.ecosystem_id = e.ecosystem_id
        JOIN affected_package ap ON p.package_id = ap.package_id
        JOIN vulnerabilities v ON ap.vulnerability_id = v.vulnerability_id
        LEFT JOIN affected_range ar ON ap.affected_package_id = ar.affected_package_id
        LEFT JOIN range_event re ON ar.range_id = re.range_id
        WHERE e.name = %s
          AND LOWER(REPLACE(REPLACE(p.name, '_', '-'), '.', '-')) = %s
        ORDER BY v.vulnerability_id, ar.range_id, re.event_id ASC;
    """
    cursor.execute(query, (ECOSYSTEM, normalize_name(package_name)))

    vulns: dict = {}
    for row in cursor.fetchall():
        vulns.setdefault(row["vulnerability_id"], {})
        if row["range_id"] is not None:
            vulns[row["vulnerability_id"]].setdefault(row["range_id"], []).append(row)
    return vulns


def evaluate_osv_events(pinned_version: str, events: list[dict]) -> bool:
    """Pairs ordered OSV events into intervals, including open-ended ranges."""
    current_intro = None

    for ev in events:
        etype = (ev.get("event_type") or "").lower()
        value = str(ev.get("event_value") or "").strip()

        if etype == "introduced":
            current_intro = value or "0"
        elif etype in ("fixed", "limit", "last_affected") and current_intro is not None:
            if not value:  # malformed event; don't build "< "
                current_intro = None
                continue
            op = "<=" if etype == "last_affected" else "<"
            if is_vulnerable(pinned_version, f">= {current_intro}, {op} {value}"):
                return True
            current_intro = None

    if current_intro is not None and is_vulnerable(pinned_version, f">= {current_intro}"):
        return True
    return False


def check_explicit_versions(pinned_version: str, raw_advisory: dict, pkg_name: str) -> bool:
    """Checks explicit affected[].versions lists from the raw OSV document."""
    target = normalize_name(pkg_name)
    for aff in raw_advisory.get("affected", []):
        pkg = aff.get("package", {})
        if normalize_name(pkg.get("name", "")) == target:
            for explicit_ver in aff.get("versions", []):
                if is_vulnerable(pinned_version, f"== {explicit_ver}"):
                    return True
    return False


def extract_severity(raw_advisory: dict) -> tuple[str, str | None]:
    """
    Returns (label, cvss_vector). OSV's severity[].score is usually a CVSS
    vector string, not a rating, so prefer database_specific.severity.
    """
    label = (raw_advisory.get("database_specific") or {}).get("severity")
    if not label:
        for aff in raw_advisory.get("affected", []):
            label = (aff.get("ecosystem_specific") or {}).get("severity")
            if label:
                break
    sev_list = raw_advisory.get("severity") or []
    vector = sev_list[0].get("score") if sev_list else None
    return (str(label).upper() if label else "UNKNOWN"), vector


def fetch_advisories(mongo_col, vuln_ids: list[str]) -> dict:
    """One batched Mongo query. Degrades gracefully if Mongo is unavailable."""
    if not vuln_ids:
        return {}
    try:
        return {d["id"]: d for d in mongo_col.find({"id": {"$in": vuln_ids}})}
    except Exception as e:
        log.warning("MongoDB enrichment unavailable (%s: %s); using MySQL data only.",
                    type(e).__name__, e)
        return {}


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------
def persist_scan_workflow(
    cursor,
    project_name: str,
    packages: list[tuple[str, str]],
    findings: list[dict],
    started_at: datetime,
    source_filename: str = "requirements.txt",
):
    # 1. Project
    cursor.execute("SELECT project_id FROM projects WHERE name = %s LIMIT 1;", (project_name,))
    row = cursor.fetchone()
    if row:
        project_id = row["project_id"]
    else:
        cursor.execute("INSERT INTO projects (name) VALUES (%s);", (project_name,))
        project_id = cursor.lastrowid

    # 2. Scan
    cursor.execute(
        "INSERT INTO scans (project_id, source_filename, status, started_at, completed_at) "
        "VALUES (%s, %s, 'COMPLETED', %s, NOW());",
        (project_id, source_filename, started_at),
    )
    scan_id = cursor.lastrowid

    # 3. Ecosystem (once)
    cursor.execute("SELECT ecosystem_id FROM ecosystems WHERE name = %s LIMIT 1;", (ECOSYSTEM,))
    eco = cursor.fetchone()
    if eco:
        eco_id = eco["ecosystem_id"]
    else:
        cursor.execute("INSERT INTO ecosystems (name) VALUES (%s);", (ECOSYSTEM,))
        eco_id = cursor.lastrowid

    # 4. Dependencies (deduplicated, reused across scans)
    dep_map: dict[tuple[str, str], int] = {}
    for pkg_name, ver in dict.fromkeys(packages):
        cursor.execute(
            "SELECT package_id FROM packages WHERE ecosystem_id = %s AND name = %s LIMIT 1;",
            (eco_id, pkg_name),
        )
        pkg = cursor.fetchone()
        if pkg:
            package_id = pkg["package_id"]
        else:
            cursor.execute("INSERT INTO packages (ecosystem_id, name) VALUES (%s, %s);", (eco_id, pkg_name))
            package_id = cursor.lastrowid

        cursor.execute(
            "SELECT package_version_id FROM package_versions WHERE package_id = %s AND version = %s LIMIT 1;",
            (package_id, ver),
        )
        pver = cursor.fetchone()
        if pver:
            pv_id = pver["package_version_id"]
        else:
            cursor.execute("INSERT INTO package_versions (package_id, version) VALUES (%s, %s);", (package_id, ver))
            pv_id = cursor.lastrowid

        cursor.execute(
            "SELECT dependency_id FROM project_dependencies "
            "WHERE project_id = %s AND package_version_id = %s LIMIT 1;",
            (project_id, pv_id),
        )
        dep = cursor.fetchone()
        if dep:
            dep_map[(pkg_name, ver)] = dep["dependency_id"]
        else:
            cursor.execute(
                "INSERT INTO project_dependencies (project_id, package_version_id) VALUES (%s, %s);",
                (project_id, pv_id),
            )
            dep_map[(pkg_name, ver)] = cursor.lastrowid

    # 5. Findings
    for f in findings:
        dep_id = dep_map.get((f["package_name"], f["version"]))
        if dep_id:
            cursor.execute(
                """
                INSERT INTO scan_findings
                    (scan_id, dependency_id, vulnerability_id, matched_range_id, match_basis)
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE match_basis = VALUES(match_basis);
                """,
                (scan_id, dep_id, f["vulnerability_id"], f.get("range_id"), f.get("match_basis", "RANGE")),
            )


# --------------------------------------------------------------------------
# Entrypoint
# --------------------------------------------------------------------------
def run_matching_engine(
    packages: list[tuple[str, str]],
    project_name: str = "Uploaded-Manifest",
    source_filename: str = "requirements.txt",
) -> list[dict]:
    """Main entrypoint invoked by Flask app.py."""
    started_at = datetime.now()
    findings: list[dict] = []
    mongo_col = get_mongo_collection()
    mysql_conn = get_mysql_connection()

    try:
        with mysql_conn.cursor() as cursor:
            for pkg_name, pinned_version in packages:
                vuln_map = fetch_package_vulnerabilities(cursor, pkg_name)
                if not vuln_map:
                    continue

                advisories = fetch_advisories(mongo_col, list(vuln_map))

                for vuln_id, ranges_dict in vuln_map.items():
                    raw = advisories.get(vuln_id, {})
                    matched_rid, match_basis = None, None

                    for rid, events in ranges_dict.items():
                        if evaluate_osv_events(pinned_version, events):
                            matched_rid, match_basis = rid, "RANGE"
                            break

                    if not match_basis and check_explicit_versions(pinned_version, raw, pkg_name):
                        match_basis = "EXPLICIT_VERSION"

                    if match_basis:
                        severity, vector = extract_severity(raw)
                        findings.append({
                            "package_name": pkg_name,
                            "version": pinned_version,
                            "vulnerability_id": vuln_id,
                            "severity": severity,
                            "cvss_vector": vector,
                            "summary": raw.get("summary", "No summary available."),
                            "range_id": matched_rid,
                            "match_basis": match_basis,
                        })

            try:
                persist_scan_workflow(cursor, project_name, packages, findings,
                                      started_at, source_filename)
                mysql_conn.commit()
            except Exception:
                mysql_conn.rollback()
                log.exception("Failed to persist scan; results were NOT saved.")
    finally:
        mysql_conn.close()

    return findings


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    for name, status in check_connections().items():
        print(f"{name:6} -> {status}")
