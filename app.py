"""CodeLedger - Flask app (Week 1 scaffold, mock data only)."""
from flask import Flask, render_template, request, redirect, url_for, flash, abort
import mock_data as data

app = Flask(__name__)
app.secret_key = "dev-only-change-me"
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024  # 256 KB upload cap


@app.route("/")
def projects():
    return render_template("projects.html", projects=data.get_projects())


@app.route("/projects/new")
def new_project():
    return render_template("import.html")


@app.route("/projects/<int:pid>")
def scan_results(pid):
    project = data.get_project(pid) or abort(404)
    sev = request.args.get("severity") or None
    kev = request.args.get("kev") == "1"
    return render_template("results.html", project=project,
                           findings=data.get_findings(pid, sev, kev),
                           sel=(sev or "").lower(), kev=kev)


@app.route("/findings/<int:fid>")
def finding_detail(fid):
    f = data.get_finding(fid) or abort(404)
    return render_template("finding.html", f=f, project=data.get_project(f["project_id"]))


@app.route("/explorer")
def explorer():
    q = request.args.get("q", "")
    return render_template("explorer.html", q=q, results=data.search_vulns(q))


@app.route("/projects/<int:pid>/history")
def history(pid):
    project = data.get_project(pid) or abort(404)
    return render_template("history.html", project=project, scans=data.get_scans(pid))


@app.route("/status")
def status():
    return render_template("status.html", snap=data.SNAPSHOT)


# ---- Week 1 dummy endpoint: accepts requirements.txt, only prints it ----
@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("requirements")
    if not file or file.filename == "":
        flash("Choose a requirements.txt file to upload.", "error")
        return redirect(url_for("new_project"))
    try:
        text = file.read().decode("utf-8")
    except UnicodeDecodeError:
        flash("That file is not plain text. Upload a requirements.txt file.", "error")
        return redirect(url_for("new_project"))
    # Treated as plain text only: never executed.
    print("=" * 40, f"\nReceived: {file.filename}\n", "=" * 40)
    print(text)
    # TODO Week 2: from matcher import ...  then pass `text` to the Weaver's logic.
    flash(f"Received {file.filename} ({len(text.splitlines())} lines). Parsing is not connected yet.", "ok")
    return redirect(url_for("new_project"))


@app.errorhandler(413)
def too_large(_):
    flash("File is too large. Upload a file under 256 KB.", "error")
    return redirect(url_for("new_project"))


if __name__ == "__main__":
    app.run(debug=True)
