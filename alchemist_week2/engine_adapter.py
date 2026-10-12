"""The only file that knows how to talk to the Weaver's engine.

CONTRACT (agree this with the Weaver):
    engine.run_scan(project_name: str, packages: list[tuple[str, str]]) -> int
        - creates/reuses the project, creates a scan row, writes scan_finding rows
        - returns the new scan_id

If the Weaver's function has another name or signature, edit _call_engine() only.

Set SECUREDEP_MOCK=1 to run the UI without MySQL/engine (fake MOCK-xxxx data).
"""
import os
import itertools
from datetime import datetime

MOCK = os.getenv("SECUREDEP_MOCK") == "1"

# ---------- mock mode (UI development only) ----------
_MOCK_DB, _ids = {}, itertools.count(1)
_MOCK_VULNS = {
    ("django", "3.2.0"): ("MOCK-0001", "Example SQL injection in ORM (placeholder data).", "8.8", "3.2.25", ["CVE-0000-0001"], True),
    ("requests", "2.19.0"): ("MOCK-0002", "Example credential leak on redirect (placeholder data).", "6.1", "2.20.0", ["CVE-0000-0002"], False),
    ("pyyaml", "5.3"): ("MOCK-0003", "Example arbitrary code execution (placeholder data).", "9.8", None, ["CVE-0000-0003"], False),
}


def _mock_scan(project_name, packages):
    sid = next(_ids)
    findings = []
    for name, ver in packages:
        hit = _MOCK_VULNS.get((name, ver))
        if hit:
            vid, summ, sev, fix, aliases, kev = hit
            findings.append(dict(finding_id=len(findings) + 1, package=name, version=ver, vuln_id=vid,
                                 summary=summ, severity=sev, fixed_version=fix, aliases=aliases, kev=kev))
    _MOCK_DB[sid] = dict(scan_id=sid, project_name=project_name, scan_date=datetime.now(),
                         status="completed", findings=findings)
    return sid


# ---------- real mode ----------
def _call_engine(project_name, packages):
    import engine  # Weaver's module, must be importable from the project root
    return engine.run_scan(project_name, packages)


def run_scan(project_name, packages):
    return _mock_scan(project_name, packages) if MOCK else _call_engine(project_name, packages)


def get_scan(scan_id):
    if MOCK:
        return _MOCK_DB.get(scan_id)
    import db
    return db.get_scan(scan_id)
