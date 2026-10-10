"""Mock data for Week 1 (decoupled construction).
Week 2: replace each function body with a call into the Weaver's matching
engine / MySQL queries. Keep the return shapes the same so templates don't change.
"""

PROJECTS = [
    {"id": 1, "name": "Inventory API", "description": "Flask service for warehouse stock",
     "created": "2026-09-12", "last_scan": "2026-09-30 10:14", "deps": 14, "findings": 5, "critical": 1},
    {"id": 2, "name": "Campus Chatbot", "description": "FastAPI + LLM wrapper",
     "created": "2026-09-18", "last_scan": "2026-09-29 16:40", "deps": 22, "findings": 2, "critical": 0},
    {"id": 3, "name": "Lab Report Tool", "description": "Pandas scripts for lab data",
     "created": "2026-09-25", "last_scan": None, "deps": 0, "findings": 0, "critical": 0},
]

FINDINGS = [
    {"id": 1, "project_id": 1, "scan_id": 7, "package": "django", "version": "3.2.0",
     "vuln_id": "PYSEC-2021-98", "severity": "CRITICAL", "score": 9.8,
     "summary": "SQL injection in QuerySet.order_by() when user input reaches ordering.",
     "affected_range": ">= 3.2, < 3.2.4", "fixed_in": "3.2.4",
     "aliases": ["CVE-2021-35042", "GHSA-xxxx-1111-aaaa"], "kev": True,
     "kev_note": "Listed in CISA KEV. Added 2021-11-03.",
     "references": [{"type": "ADVISORY", "url": "https://osv.dev/vulnerability/PYSEC-2021-98"},
                    {"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-35042"}]},
    {"id": 2, "project_id": 1, "scan_id": 7, "package": "requests", "version": "2.19.0",
     "vuln_id": "GHSA-x84v-xcm2-53pg", "severity": "MEDIUM", "score": 5.6,
     "summary": "Proxy-Authorization header may leak on cross-host redirect.",
     "affected_range": "< 2.31.0", "fixed_in": "2.31.0",
     "aliases": ["CVE-2023-32681"], "kev": False, "kev_note": "",
     "references": [{"type": "ADVISORY", "url": "https://osv.dev/vulnerability/GHSA-x84v-xcm2-53pg"}]},
    {"id": 3, "project_id": 1, "scan_id": 7, "package": "pyyaml", "version": "5.3",
     "vuln_id": "PYSEC-2020-176", "severity": "HIGH", "score": 8.1,
     "summary": "Arbitrary code execution through full_load on untrusted YAML.",
     "affected_range": "< 5.4", "fixed_in": "5.4",
     "aliases": ["CVE-2020-14343"], "kev": False, "kev_note": "",
     "references": [{"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-14343"}]},
    {"id": 4, "project_id": 1, "scan_id": 7, "package": "jinja2", "version": "2.10",
     "vuln_id": "PYSEC-2019-217", "severity": "HIGH", "score": 7.5,
     "summary": "Sandbox escape allows attribute access via string formatting.",
     "affected_range": "< 2.10.1", "fixed_in": "2.10.1",
     "aliases": ["CVE-2019-10906"], "kev": False, "kev_note": "", "references": []},
    {"id": 5, "project_id": 1, "scan_id": 7, "package": "urllib3", "version": "1.24.1",
     "vuln_id": "GHSA-www2-v7xj-xrc6", "severity": "LOW", "score": 3.7,
     "summary": "CRLF injection through the request method parameter.",
     "affected_range": "< 1.24.3", "fixed_in": None,
     "aliases": ["CVE-2019-11324"], "kev": False, "kev_note": "", "references": []},
]

SCANS = [
    {"id": 7, "project_id": 1, "date": "2026-09-30 10:14", "status": "COMPLETED", "total": 5, "new": 1, "resolved": 0},
    {"id": 5, "project_id": 1, "date": "2026-09-22 09:02", "status": "COMPLETED", "total": 4, "new": 2, "resolved": 1},
    {"id": 2, "project_id": 1, "date": "2026-09-15 18:30", "status": "COMPLETED", "total": 3, "new": 3, "resolved": 0},
]

SNAPSHOT = {"source": "OSV PyPI all.zip", "date": "2026-09-20", "records": 25012,
            "status": "Imported", "errors": 0}


def get_projects():
    return PROJECTS

def get_project(pid):
    return next((p for p in PROJECTS if p["id"] == pid), None)

def get_findings(pid, severity=None, kev_only=False):
    rows = [f for f in FINDINGS if f["project_id"] == pid]
    if severity:
        rows = [f for f in rows if f["severity"] == severity.upper()]
    if kev_only:
        rows = [f for f in rows if f["kev"]]
    return rows

def get_finding(fid):
    return next((f for f in FINDINGS if f["id"] == fid), None)

def get_scans(pid):
    return [s for s in SCANS if s["project_id"] == pid]

def search_vulns(q):
    q = (q or "").lower().strip()
    if not q:
        return FINDINGS
    return [f for f in FINDINGS if q in f["vuln_id"].lower() or q in f["package"].lower()
            or any(q in a.lower() for a in f["aliases"])]
