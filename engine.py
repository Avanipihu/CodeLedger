"""
Core matching and persistence engine for CodeLedger.
Resolves OSV boundaries, enriches from MongoDB, and persists scan records in MySQL.
"""
import os
import pymysql
import pymongo
from dotenv import load_dotenv
from matcher import is_vulnerable

load_dotenv()

def get_mysql_connection():
    """Establishes a universal connection to MySQL/MariaDB."""
    return pymysql.connect(
        host=os.getenv('MYSQL_HOST', '127.0.0.1'),
        user=os.getenv('MYSQL_USER', 'root'),
        password=os.getenv('MYSQL_PASSWORD', os.getenv('DB_PASSWORD', '')),
        database=os.getenv('MYSQL_DB', 'codeledger'),
        cursorclass=pymysql.cursors.DictCursor
    )

def get_mongo_collection():
    """Connects to the MongoDB vulnerabilities collection."""
    client = pymongo.MongoClient(os.getenv('MONGO_URI', 'mongodb://localhost:27017/'))
    db = client[os.getenv('MONGO_DB', 'codeledger')]
    return db['vulnerabilities']

def fetch_package_vulnerabilities(cursor, package_name: str) -> dict:
    """
    Fetches range events sequentially instead of self-joining range_event.
    Prevents Cartesian cross-pairing when a range has multiple introduced/fixed pairs.
    """
    query = """
        SELECT 
            v.vulnerability_id,
            ar.range_id,
            re.event_id,
            re.event_type,
            re.event_value
        FROM packages p
        JOIN affected_package ap ON p.package_id = ap.package_id
        JOIN vulnerabilities v ON ap.vulnerability_id = v.vulnerability_id
        LEFT JOIN affected_range ar ON ap.affected_package_id = ar.affected_package_id
        LEFT JOIN range_event re ON ar.range_id = re.range_id
        WHERE p.name = %s
        ORDER BY v.vulnerability_id, ar.range_id, re.event_id ASC;
    """
    cursor.execute(query, (package_name,))
    rows = cursor.fetchall()

    vulns = {}
    for row in rows:
        vid = row['vulnerability_id']
        rid = row['range_id']
        vulns.setdefault(vid, {})
        if rid is not None:
            vulns[vid].setdefault(rid, []).append(row)
    return vulns

def evaluate_osv_events(pinned_version: str, events: list[dict]) -> bool:
    """
    Pairs ordered OSV events ('introduced' -> 'fixed'/'last_affected'/'limit')
    into proper intervals, including open-ended ranges starting at '0'.
    """
    current_intro = None

    for ev in events:
        etype = (ev.get('event_type') or '').lower()
        eval_ver = str(ev.get('event_value') or '').strip()

        if etype == 'introduced':
            current_intro = eval_ver if eval_ver else "0"
        elif etype in ('fixed', 'limit') and current_intro is not None:
            if is_vulnerable(pinned_version, f">= {current_intro}, < {eval_ver}"):
                return True
            current_intro = None
        elif etype == 'last_affected' and current_intro is not None:
            if is_vulnerable(pinned_version, f">= {current_intro}, <= {eval_ver}"):
                return True
            current_intro = None

    # Handle open-ended ranges (introduced, including '0', with no subsequent fix)
    if current_intro is not None:
        if is_vulnerable(pinned_version, f">= {current_intro}"):
            return True

    return False

def check_explicit_versions(pinned_version: str, raw_advisory: dict, pkg_name: str) -> bool:
    """Checks explicit affected['versions'] lists and raw OSV ranges from MongoDB."""
    for aff in raw_advisory.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("name", "").lower() == pkg_name.lower():
            for explicit_ver in aff.get("versions", []):
                if is_vulnerable(pinned_version, f"== {explicit_ver}"):
                    return True
    return False

def _get_table_columns(cursor, table_name: str) -> set[str]:
    """Introspects a table's columns so inserts adapt to schema variations."""
    cursor.execute(f"SHOW COLUMNS FROM `{table_name}`;")
    return {row['Field'] for row in cursor.fetchall()}

def persist_scan_workflow(cursor, project_name: str, packages: list[tuple[str, str]], findings: list[dict]):
    """
    Persists project, scan, dependency, and finding records into MySQL.
    Uses column introspection to remain resilient across schema revisions.
    """
    # 1. Ensure Project exists
    proj_cols = _get_table_columns(cursor, 'projects')
    cursor.execute("SELECT project_id FROM projects WHERE project_name = %s LIMIT 1;", (project_name,))
    proj = cursor.fetchone()
    if proj:
        project_id = proj['project_id']
    else:
        cursor.execute("INSERT INTO projects (project_name) VALUES (%s);", (project_name,))
        project_id = cursor.lastrowid

    # 2. Create Scan record (supports started_at/completed_at or scan_timestamp)
    scan_cols = _get_table_columns(cursor, 'scans')
    if 'started_at' in scan_cols and 'completed_at' in scan_cols:
        cursor.execute(
            "INSERT INTO scans (project_id, status, started_at, completed_at) VALUES (%s, 'COMPLETED', NOW(), NOW());",
            (project_id,)
        )
    else:
        cursor.execute("INSERT INTO scans (project_id) VALUES (%s);", (project_id,))
    scan_id = cursor.lastrowid

    # 3. Map & persist project dependencies
    dep_map = {}
    try:
        dep_table = 'project_dependencies' if _get_table_columns(cursor, 'project_dependencies') else 'project_dependency'
    except Exception:
        dep_table = None

    for pkg_name, ver in packages:
        if dep_table:
            dcols = _get_table_columns(cursor, dep_table)
            if {'project_id', 'package_name', 'pinned_version'}.issubset(dcols):
                cursor.execute(
                    f"INSERT INTO `{dep_table}` (project_id, package_name, pinned_version) VALUES (%s, %s, %s);",
                    (project_id, pkg_name, ver)
                )
                dep_map[(pkg_name, ver)] = cursor.lastrowid

    # 4. Persist confirmed findings
    f_cols = _get_table_columns(cursor, 'scan_findings')
    for f in findings:
        dep_id = dep_map.get((f['package_name'], f['version']))
        if {'scan_id', 'dependency_id', 'vulnerability_id', 'matched_range_id', 'match_basis'}.issubset(f_cols) and dep_id:
            cursor.execute(
                """
                INSERT IGNORE INTO scan_findings 
                (scan_id, dependency_id, vulnerability_id, matched_range_id, match_basis)
                VALUES (%s, %s, %s, %s, %s);
                """,
                (scan_id, dep_id, f['vulnerability_id'], f.get('range_id'), f.get('match_basis', 'RANGE'))
            )

def run_matching_engine(packages: list[tuple[str, str]], project_name: str = "Uploaded-Manifest") -> list[dict]:
    """
    Main entrypoint invoked by Flask app.py.
    Evaluates ranges, enriches from MongoDB, persists records to MySQL, and returns UI dicts.
    """
    findings = []
    mysql_conn = get_mysql_connection()
    mongo_col = get_mongo_collection()

    try:
        with mysql_conn.cursor() as cursor:
            for pkg_name, pinned_version in packages:
                vuln_map = fetch_package_vulnerabilities(cursor, pkg_name)
                if not vuln_map:
                    continue

                for vuln_id, ranges_dict in vuln_map.items():
                    raw_advisory = mongo_col.find_one({"id": vuln_id}) or {}
                    matched_rid = None
                    match_basis = None

                    # 1. Check sequential range events from MySQL
                    for rid, events in ranges_dict.items():
                        if evaluate_osv_events(pinned_version, events):
                            matched_rid = rid
                            match_basis = "RANGE"
                            break

                    # 2. Check explicit affected versions list in MongoDB if range didn't trigger
                    if not match_basis and check_explicit_versions(pinned_version, raw_advisory, pkg_name):
                        match_basis = "EXPLICIT_VERSION"

                    if match_basis:
                        summary = raw_advisory.get("summary", "No summary available.")
                        sev_list = raw_advisory.get("severity", [])
                        severity = sev_list[0].get("score", "UNKNOWN") if sev_list else "UNKNOWN"

                        findings.append({
                            "package_name": pkg_name,
                            "version": pinned_version,
                            "vulnerability_id": vuln_id,
                            "severity": severity,
                            "summary": summary,
                            "range_id": matched_rid,
                            "match_basis": match_basis
                        })

            # Commit the full scan lifecycle to MySQL
            try:
                persist_scan_workflow(cursor, project_name, packages, findings)
                mysql_conn.commit()
            except Exception as db_err:
                mysql_conn.rollback()
                print(f"[!] Persistence warning: {db_err}")

    finally:
        mysql_conn.close()

    return findings
