import math
import os
import re
import ssl
from datetime import datetime
from urllib.parse import urlparse, unquote

import jinja2
import pymysql
import pymongo
from flask import Flask, render_template, request, redirect, url_for, flash, session

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ----------------------------------------------------------------------------
# Database connections (Aiven MySQL needs SSL + a custom port; Mongo may be Atlas)
#
# Either set one Aiven "Service URI":
#     MYSQL_URI=mysql://avnadmin:PASSWORD@HOST:PORT/defaultdb?ssl-mode=REQUIRED
# or the individual variables:
#     MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB
# Optional: MYSQL_SSL_CA=/path/to/ca.pem  (otherwise SSL is used without CA check)
# ----------------------------------------------------------------------------
def _mysql_settings():
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


def _ssl_option(host):
    ca = os.getenv("MYSQL_SSL_CA")
    if ca and os.path.exists(ca):
        return {"ca": ca}
    use_ssl = os.getenv("MYSQL_SSL", "").lower() in ("1", "true", "yes") or \
        "aivencloud.com" in (host or "") or "aiven.io" in (host or "") or \
        os.getenv("MYSQL_URI") or os.getenv("DATABASE_URL")
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return None


def connect_mysql():
    """Raises on failure (used by the engine)."""
    cfg = _mysql_settings()
    return pymysql.connect(
        host=cfg["host"], port=cfg["port"], user=cfg["user"],
        password=cfg["password"], database=cfg["database"],
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=5, ssl=_ssl_option(cfg["host"]),
    )


def get_db_connection():
    """Returns None instead of raising so pages still render when MySQL is offline."""
    try:
        return connect_mysql()
    except Exception as e:
        print(f"[db] MySQL unavailable: {e}")
        return None


def get_mongo_collection():
    client = pymongo.MongoClient(
        os.getenv("MONGO_URI", "mongodb://localhost:27017/"),
        serverSelectionTimeoutMS=3000,
    )
    return client[os.getenv("MONGO_DB", "codeledger")]["vulnerabilities"]


# ----------------------------------------------------------------------------
# Matching engine (falls back to demo data if engine.py cannot be imported)
# ----------------------------------------------------------------------------
DEMO_FINDINGS = [
    {"package_name": "lodash", "version": "4.17.21", "vulnerability_id": "CVE-2021-23337",
     "severity": "High", "cvss_score": 7.5, "status": "Affected",
     "summary": "Prototype pollution vulnerability in lodash which may allow remote code execution.",
     "fixed_version": "4.17.22", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"]},
    {"package_name": "express", "version": "4.18.2", "vulnerability_id": "CVE-2022-24999",
     "severity": "Medium", "cvss_score": 5.3, "status": "Affected",
     "summary": "Open redirect vulnerability in express server routes.",
     "fixed_version": "4.18.3", "references": ["https://github.com/advisories/GHSA-express"]},
    {"package_name": "axios", "version": "1.5.0", "vulnerability_id": "CVE-2023-45857",
     "severity": "Low", "cvss_score": 3.2, "status": "Not Affected",
     "summary": "SSRF vulnerability in axios HTTP client.",
     "fixed_version": "1.6.0", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-45857"]},
]

try:
    import engine as _engine
    # Make the engine use the same (Aiven / SSL aware) connections as the web app.
    _engine.get_mysql_connection = connect_mysql
    _engine.get_mongo_collection = get_mongo_collection
    ENGINE_OK = True
except Exception as _e:  # missing module, missing dotenv, etc.
    print(f"[engine] not available, using demo data: {_e}")
    _engine = None
    ENGINE_OK = False


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "alchemist-secret-key")
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2MB upload limit


class _CleanLoader(jinja2.FileSystemLoader):
    """Some template files contain an old copy followed by the new copy, which makes Jinja
    fail with 'block content defined twice'. Keep only the last {% extends %} section."""
    def get_source(self, environment, template):
        source, filename, uptodate = super().get_source(environment, template)
        parts = re.split(r"(?=\{%-?\s*extends\b)", source)
        parts = [p for p in parts if p.strip()]
        if len(parts) > 1:
            source = parts[-1]
        return source, filename, uptodate


app.jinja_loader = _CleanLoader(os.path.join(app.root_path, "templates"))

FEEDBACK_STORE = []
SCAN_LOG = []        # in-memory scan history (works even if MySQL is offline)
LAST_SCAN = {"findings": [], "summary": None}


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def login_required():
    return "user" not in session


def parse_dependencies(text):
    pkgs = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^([A-Za-z0-9._\-]+)(?:\[[^\]]*\])?\s*(?:==|@)\s*v?([A-Za-z0-9.\-+!_*]+)$", line)
        if m:
            pkgs.append((m.group(1), m.group(2)))
    return pkgs


def _cvss3_score(vector):
    """Base score from a CVSS:3.x vector string, or None."""
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        av = {"N": .85, "A": .62, "L": .55, "P": .2}[m["AV"]]
        ac = {"L": .77, "H": .44}[m["AC"]]
        scope_changed = m["S"] == "C"
        pr = {"N": .85, "L": .68 if scope_changed else .62, "H": .5 if scope_changed else .27}[m["PR"]]
        ui = {"N": .85, "R": .62}[m["UI"]]
        cia = {"H": .56, "L": .22, "N": 0}
        iss = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
        impact = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if scope_changed else 6.42 * iss
        expl = 8.22 * av * ac * pr * ui
        if impact <= 0:
            return 0.0
        raw = min((impact + expl) * (1.08 if scope_changed else 1), 10)
        return math.ceil(raw * 10) / 10
    except Exception:
        return None


def severity_band(score):
    if score is None:
        return "Unknown"
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    if score > 0:
        return "Low"
    return "Unknown"


def enrich_findings(findings):
    """Normalise whatever the engine returns so the templates always get
    severity (High/Medium/Low/...), cvss_score and status."""
    scores = {}
    conn = get_db_connection()
    if conn:
        try:
            ids = list({f["vulnerability_id"] for f in findings})
            if ids:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT vulnerability_id, MAX(base_score) AS s FROM vulnerability_severity "
                        "WHERE vulnerability_id IN (%s) GROUP BY vulnerability_id" % ",".join(["%s"] * len(ids)),
                        ids)
                    scores = {r["vulnerability_id"]: float(r["s"]) for r in cur.fetchall() if r["s"] is not None}
        except Exception as e:
            print(f"[enrich] {e}")
        finally:
            conn.close()

    for f in findings:
        raw = str(f.get("severity") or "")
        score = f.get("cvss_score")
        if not isinstance(score, (int, float)):
            score = scores.get(f["vulnerability_id"])
        if score is None and raw.upper().startswith("CVSS:3"):
            score = _cvss3_score(raw)
        if raw.capitalize() in ("Critical", "High", "Medium", "Low"):
            band = raw.capitalize()
        else:
            band = severity_band(score)
        f["severity"] = band
        f["cvss_score"] = score if score is not None else "N/A"
        f.setdefault("status", "Affected")
        f.setdefault("summary", "")
    return findings


def summarise(findings):
    sev = [f["severity"] for f in findings]
    return {
        "total": len(findings),
        "high": sev.count("High") + sev.count("Critical"),
        "medium": sev.count("Medium"),
        "low": sev.count("Low"),
    }


def run_scan(packages, project_name):
    """Returns (findings, note). Never raises."""
    if not ENGINE_OK:
        return [dict(f) for f in DEMO_FINDINGS], "Matching engine not available - showing demo data."
    try:
        return _engine.run_matching_engine(packages, project_name=project_name), None
    except TypeError:
        return _engine.run_matching_engine(packages), None
    except Exception as e:
        print(f"[engine] failed: {e}")
        return [dict(f) for f in DEMO_FINDINGS], "Could not reach the databases - showing demo data."


def recent_scans(limit=None):
    rows = list(reversed(SCAN_LOG))
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT s.scan_id, p.name AS project, s.started_at, s.status,
                           (SELECT COUNT(*) FROM scan_findings f WHERE f.scan_id = s.scan_id) AS findings
                    FROM scans s JOIN projects p ON p.project_id = s.project_id
                    ORDER BY s.started_at DESC LIMIT 50""")
                for r in cur.fetchall():
                    rows.append({
                        "scan_id": r["scan_id"], "project": r["project"],
                        "scanned_at": r["started_at"].strftime("%Y-%m-%d %H:%M") if r["started_at"] else "-",
                        "status": (r["status"] or "").capitalize(), "findings": r["findings"],
                    })
        except Exception as e:
            print(f"[scans] {e}")
        finally:
            conn.close()
    if not rows and not conn:
        rows = [
            {"scan_id": 3, "project": "web-app", "scanned_at": "2025-09-10 14:32", "status": "Completed", "findings": 3},
            {"scan_id": 2, "project": "api-service", "scanned_at": "2025-09-09 11:20", "status": "Completed", "findings": 1},
            {"scan_id": 1, "project": "mobile-app", "scanned_at": "2025-09-08 16:45", "status": "Completed", "findings": 0},
        ]
    return rows[:limit] if limit else rows


def lookup_finding(vid):
    """Best-effort details for one vulnerability: MySQL -> MongoDB -> last scan -> demo."""
    last = next((f for f in LAST_SCAN["findings"] if f["vulnerability_id"] == vid), None)
    out = {
        "vulnerability_id": vid,
        "severity": (last or {}).get("severity", "Unknown"),
        "package": (last or {}).get("package_name", "-"),
        "affected_version": (last or {}).get("version", "-"),
        "fixed_version": (last or {}).get("fixed_version", "-"),
        "cvss_score": (last or {}).get("cvss_score", "N/A"),
        "description": (last or {}).get("summary") or "No description available.",
        "references": list((last or {}).get("references", [])),
    }
    found = False

    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT summary, details FROM vulnerabilities WHERE vulnerability_id=%s", (vid,))
                v = cur.fetchone()
                if v:
                    found = True
                    out["description"] = v["summary"] or v["details"] or out["description"]
                    cur.execute("SELECT MAX(base_score) AS s FROM vulnerability_severity WHERE vulnerability_id=%s", (vid,))
                    s = cur.fetchone()
                    if s and s["s"] is not None:
                        out["cvss_score"] = float(s["s"])
                        out["severity"] = severity_band(float(s["s"]))
                    cur.execute("SELECT url FROM vulnerability_reference WHERE vulnerability_id=%s LIMIT 10", (vid,))
                    out["references"] = [r["url"] for r in cur.fetchall()] or out["references"]
                    cur.execute("""
                        SELECT pk.name, re.event_type, re.event_value
                        FROM affected_package ap
                        JOIN packages pk ON pk.package_id = ap.package_id
                        JOIN affected_range ar ON ar.affected_package_id = ap.affected_package_id
                        JOIN range_event re ON re.range_id = ar.range_id
                        WHERE ap.vulnerability_id=%s ORDER BY ar.range_id, re.event_order LIMIT 20""", (vid,))
                    ev = cur.fetchall()
                    if ev:
                        out["package"] = ev[0]["name"]
                        fixed = [e["event_value"] for e in ev if e["event_type"] == "fixed"]
                        intro = [e["event_value"] for e in ev if e["event_type"] == "introduced"]
                        if fixed:
                            out["fixed_version"] = fixed[0]
                            out["affected_version"] = f"< {fixed[0]}" if (not intro or intro[0] == "0") \
                                else f">= {intro[0]}, < {fixed[0]}"
        except Exception as e:
            print(f"[finding] {e}")
        finally:
            conn.close()

    if not found:
        try:
            doc = get_mongo_collection().find_one({"id": vid}, {"_id": 0})
            if doc:
                found = True
                out["description"] = doc.get("summary") or doc.get("details") or out["description"]
                out["references"] = [r.get("url") for r in doc.get("references", []) if r.get("url")] or out["references"]
                sev = doc.get("severity") or []
                if sev:
                    sc = _cvss3_score(sev[0].get("score", ""))
                    if sc is not None:
                        out["cvss_score"], out["severity"] = sc, severity_band(sc)
        except Exception:
            pass

    if not found and not last:
        demo = next((d for d in DEMO_FINDINGS if d["vulnerability_id"] == vid), DEMO_FINDINGS[0])
        out.update(package=demo["package_name"], affected_version=f"< {demo['fixed_version']}",
                   fixed_version=demo["fixed_version"], cvss_score=demo["cvss_score"],
                   severity=demo["severity"], description=demo["summary"], references=demo["references"])
    if isinstance(out["cvss_score"], (int, float)):
        out["cvss_score"] = f"{out['cvss_score']} ({out['severity']})"
    return out


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------
@app.errorhandler(413)
def too_large(_e):
    flash("File too large (max 2MB).", "danger")
    return redirect(url_for("index"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("username") == "admin" and request.form.get("password") == "password123":
            session["user"] = "admin"
            flash("Logged in successfully!", "success")
            return redirect(url_for("index"))
        flash("Invalid username or password (try admin / password123)", "danger")
    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        flash("Account registered successfully! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("signup.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


@app.route("/")
@app.route("/import")
@app.route("/scan")
def index():
    if login_required():
        return redirect(url_for("login"))
    return render_template("import.html", recent_scans=recent_scans(5))


@app.route("/upload", methods=["GET", "POST"])
def upload_file():
    if login_required():
        return redirect(url_for("login"))
    if request.method == "GET":
        return redirect(url_for("findings"))

    raw_text = request.form.get("dependencies_text", "").strip()
    file = request.files.get("file") or request.files.get("requirements")
    project_name = "Uploaded-Manifest"

    if raw_text:
        text = raw_text
    elif file and file.filename:
        if not file.filename.lower().endswith(".txt"):
            flash("Invalid file format. Only plain text (.txt) files are supported.", "danger")
            return redirect(url_for("index"))
        try:
            text = file.stream.read().decode("utf-8-sig")
        except UnicodeDecodeError:
            flash("Encoding Error: Binary or non-text file detected.", "danger")
            return redirect(url_for("index"))
        project_name = os.path.splitext(os.path.basename(file.filename))[0] or project_name
    else:
        flash("Please upload a valid requirements.txt file or paste dependencies.", "warning")
        return redirect(url_for("index"))

    packages = parse_dependencies(text)
    if not packages:
        flash("No pinned dependencies (e.g., package==1.0.0) found.", "warning")
        return redirect(url_for("index"))

    raw, note = run_scan(packages, project_name)
    findings = enrich_findings(raw)
    summary = summarise(findings)
    LAST_SCAN.update(findings=findings, summary=summary)
    SCAN_LOG.append({
        "scan_id": f"local-{len(SCAN_LOG) + 1}", "project": project_name,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "status": "Completed", "findings": len(findings),
    })
    del SCAN_LOG[:-20]
    if note:
        flash(note, "warning")
    return render_template("results.html", findings=findings, summary=summary)


@app.route("/findings")
def findings():
    if login_required():
        return redirect(url_for("login"))
    if not LAST_SCAN["summary"]:
        flash("No scan has been run yet - upload a requirements file to start.", "info")
        return redirect(url_for("index"))
    return render_template("results.html", findings=LAST_SCAN["findings"], summary=LAST_SCAN["summary"])


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if login_required():
        return redirect(url_for("login"))
    if request.method == "POST":
        msg = request.form.get("feedback_message")
        if msg:
            FEEDBACK_STORE.append({"user": session["user"], "message": msg, "rating": request.form.get("rating")})
            flash("Thank you! Your feedback has been submitted successfully.", "success")
        return redirect(url_for("feedback"))
    return render_template("feedback.html", feedbacks=list(reversed(FEEDBACK_STORE)))


@app.route("/projects")
def projects():
    if login_required():
        return redirect(url_for("login"))
    data = []
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT project_id, name, created_at FROM projects ORDER BY created_at DESC")
                data = cur.fetchall()
        except Exception as e:
            print(f"[projects] {e}")
        finally:
            conn.close()
    else:
        data = [{"name": "sample-web-scanner", "created_at": "2026-03-01 12:00:00"},
                {"name": "api-gateway-audit", "created_at": "2026-03-05 14:30:00"}]
    return render_template("projects.html", projects=data)


@app.route("/explorer")
def explorer():
    if login_required():
        return redirect(url_for("login"))
    docs = []
    try:
        docs = list(get_mongo_collection().find({}, {"_id": 0}).limit(25))
        for d in docs:
            d["vulnerability_id"] = d.get("vulnerability_id") or d.get("id", "-")
            d["summary"] = d.get("summary") or d.get("details", "")[:160]
    except Exception:
        conn = get_db_connection()
        if conn:
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT vulnerability_id, summary FROM vulnerabilities ORDER BY modified_at DESC LIMIT 25")
                    docs = cur.fetchall()
            except Exception as e:
                print(f"[explorer] {e}")
            finally:
                conn.close()
    return render_template("explorer.html", vulnerabilities=docs)


@app.route("/finding/<finding_id>")
def finding_detail(finding_id):
    if login_required():
        return redirect(url_for("login"))
    return render_template("finding.html", finding=lookup_finding(finding_id))


@app.route("/history")
def history():
    if login_required():
        return redirect(url_for("login"))
    rows = [{"scan_id": r["scan_id"], "scan_timestamp": f"{r['scanned_at']}  ({r['project']}, {r['findings']} findings)"}
            for r in recent_scans()]
    return render_template("history.html", scans=rows)


@app.route("/status")
def status():
    if login_required():
        return redirect(url_for("login"))
    info = {"mysql": "Disconnected", "mongo": "Disconnected"}
    conn = get_db_connection()
    if conn:
        try:
            conn.ping()
            info["mysql"] = "Connected"
        except Exception:
            pass
        finally:
            conn.close()
    try:
        get_mongo_collection().database.client.admin.command("ping")
        info["mongo"] = "Connected"
    except Exception:
        pass
    return render_template("status.html", status=info)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
