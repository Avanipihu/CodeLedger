"""Read-only MySQL access for the results page. All queries are parameterized.

Column names follow the proposal's schema. If the Architect's schema.sql uses
different names, change them here only.
"""
import os
import mysql.connector


def connect():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "securedep"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "securedep"),
    )


SCAN_SQL = """
SELECT s.scan_id, s.scan_date, s.status, p.project_name
FROM scan s JOIN project p ON p.project_id = s.project_id
WHERE s.scan_id = %s
"""

FINDINGS_SQL = """
SELECT
  sf.finding_id,
  pk.name  AS package,
  pv.version,
  v.vuln_id,
  v.summary,
  (SELECT GROUP_CONCAT(DISTINCT a.alias_value SEPARATOR ',')
     FROM vuln_alias a WHERE a.vuln_id = v.vuln_id)               AS aliases,
  (SELECT vs.score FROM vuln_severity vs
     WHERE vs.vuln_id = v.vuln_id ORDER BY vs.severity_id LIMIT 1) AS severity,
  (SELECT GROUP_CONCAT(DISTINCT re.version SEPARATOR ',')
     FROM affected_range ar JOIN range_event re ON re.range_id = ar.range_id
     WHERE ar.vuln_id = v.vuln_id AND ar.package_id = pk.package_id
       AND re.event_type = 'fixed')                               AS fixed_version,
  EXISTS(SELECT 1 FROM vuln_alias a JOIN kev_entry k ON k.cve_id = a.alias_value
         WHERE a.vuln_id = v.vuln_id)                             AS kev
FROM scan_finding sf
JOIN package_version pv ON pv.version_id = sf.version_id
JOIN package pk         ON pk.package_id = pv.package_id
JOIN vulnerability v    ON v.vuln_id = sf.vuln_id
WHERE sf.scan_id = %s
ORDER BY pk.name, v.vuln_id
"""


def get_scan(scan_id):
    conn = connect()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(SCAN_SQL, (scan_id,))
        scan = cur.fetchone()
        if not scan:
            return None
        cur.execute(FINDINGS_SQL, (scan_id,))
        findings = cur.fetchall()
        for f in findings:
            f["aliases"] = [a for a in (f["aliases"] or "").split(",") if a]
            f["fixed_version"] = f["fixed_version"] or None
            f["kev"] = bool(f["kev"])
        scan["findings"] = findings
        return scan
    finally:
        conn.close()
