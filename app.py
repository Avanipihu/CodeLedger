from flask import Flask, render_template, request, redirect, url_for, flash
import os
import sqlite3

app = Flask(__name__)
app.secret_key = 'codeledger_secure_secret_key'

def get_db_connection():
    # Connects to the local CodeLedger database
    db_path = os.path.join(os.path.dirname(__file__), 'codeledger.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    """Home / Dashboard view with recent scans and upload widget."""
    return render_template('projects.html')

@app.route('/import', methods=['GET', 'POST'])
def import_manifest():
    """Upload requirements.txt or paste dependencies."""
    if request.method == 'POST':
        # Handle manifest file upload or raw text input
        flash('Requirements uploaded successfully. Initiating scan...', 'success')
        return redirect(url_for('results'))
    return render_template('import.html')

@app.route('/projects')
def projects():
    """List monitored projects and repositories."""
    return render_template('projects.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """Trigger vulnerability scan against OSV/CISA databases."""
    if request.method == 'POST':
        return redirect(url_for('results'))
    return render_template('explorer.html')

@app.route('/findings')
def results():
    """Scan Results Dashboard showing vulnerabilities, CVSS scores, and severities."""
    return render_template('results.html')

@app.route('/finding/<int:finding_id>')
def finding_detail(finding_id):
    """Detailed view for a specific vulnerability (CVE, affected/fixed versions, references)."""
    return render_template('finding.html', finding_id=finding_id)

@app.route('/explorer')
def explorer():
    """Dependency and component explorer."""
    return render_template('explorer.html')

@app.route('/history')
def history():
    """Scan history and audit logs."""
    return render_template('history.html')

@app.route('/status')
def status():
    """System and database status check."""
    return render_template('status.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
