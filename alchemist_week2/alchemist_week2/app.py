import logging
from flask import Flask, render_template, request, redirect, url_for, flash, abort

import engine_adapter
from req_parser import parse_requirements

app = Flask(__name__)
app.secret_key = "change-me-before-demo"      # needed for flash()
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024  # 1 MB upload cap
log = logging.getLogger("securedep")

SEVERITY_ORDER = ["critical", "high", "medium", "low", "unrated"]


def severity_label(raw):
    """Map a numeric CVSS score or a word to a display band."""
    if raw is None:
        return "unrated"
    s = str(raw).strip().lower()
    if s in SEVERITY_ORDER:
        return s
    try:
        x = float(s)
    except ValueError:
        return "unrated"  # e.g. a raw CVSS vector string
    return "critical" if x >= 9 else "high" if x >= 7 else "medium" if x >= 4 else "low"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    project = (request.form.get("project_name") or "").strip()
    upload = request.files.get("requirements")
    if not project:
        flash("Enter a project name.", "error")
        return render_template("index.html"), 400
    if not upload or not upload.filename:
        flash("Choose a requirements.txt file.", "error")
        return render_template("index.html", project=project), 400
    if not upload.filename.lower().endswith(".txt"):
        flash("Only .txt dependency files are supported.", "error")
        return render_template("index.html", project=project), 400
    raw = upload.read()
    try:
        if b"\x00" in raw:
            raise UnicodeDecodeError("utf-8", b"", 0, 1, "binary")
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        flash("That file is not plain text. Upload a requirements.txt file.", "error")
        return render_template("index.html", project=project), 400

    packages, problems = parse_requirements(text)
    if not packages:
        for p in problems:
            flash(p, "error")
        flash("No pinned packages found. Each line needs the form name==version.", "error")
        return render_template("index.html", project=project), 400
    for p in problems:
        flash(p, "warn")

    try:
        scan_id = engine_adapter.run_scan(project, packages)
    except Exception:
        log.exception("engine failure")
        flash("The scan engine failed. Check the server log and try again.", "error")
        return render_template("index.html", project=project), 500
    return redirect(url_for("results", scan_id=scan_id))


@app.route("/scan/<int:scan_id>")
def results(scan_id):
    data = engine_adapter.get_scan(scan_id)
    if not data:
        abort(404)
    findings = data["findings"]
    for f in findings:
        f["band"] = severity_label(f.get("severity"))
    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["band"]), f["package"]))
    counts = {b: sum(1 for f in findings if f["band"] == b) for b in SEVERITY_ORDER}
    return render_template("results.html", scan=data, findings=findings, counts=counts,
                           order=SEVERITY_ORDER)


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", title="Scan not found",
                           message="No scan exists with that ID."), 404


@app.errorhandler(413)
def too_large(_e):
    return render_template("error.html", title="File too large",
                           message="Dependency files must be under 1 MB."), 413


if __name__ == "__main__":
    app.run(debug=True)
