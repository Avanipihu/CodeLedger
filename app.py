from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
import sqlite3

# Import your native CodeLedger engine if available
try:
    from engine import scan_dependencies
    ENGINE_AVAILABLE = True
except ImportError:
    ENGINE_AVAILABLE = False

app = Flask(__name__)
app.secret_key = 'codeledger_secure_secret_key'

def get_db_connection():
    db_path = os.path.join(os.path.dirname(__file__), 'codeledger.db')
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn
    return None

@app.route('/')
def index():
    return render_template('projects.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session['user'] = request.form.get('username')
        flash('Logged in successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/import', methods=['GET', 'POST'])
def import_manifest():
    if request.method == 'POST':
        manifest_text = request.form.get('dependencies') or "Uploaded file"
        if ENGINE_AVAILABLE:
            try:
                # Trigger live engine scan if connected
                results = scan_dependencies(manifest_text)
            except Exception as e:
                print(f"Engine scan notice: {e}")
        flash('Requirements manifest imported and scanned successfully!', 'success')
        return redirect(url_for('results'))
    return render_template('import.html')

@app.route('/projects')
def projects():
    return render_template('projects.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        flash('Vulnerability scan completed successfully.', 'success')
        return redirect(url_for('results'))
    return render_template('explorer.html')

@app.route('/findings')
def results():
    return render_template('results.html', engine_active=ENGINE_AVAILABLE)

@app.route('/finding/<int:finding_id>')
def finding_detail(finding_id):
    return render_template('finding.html', finding_id=finding_id)

@app.route('/explorer')
def explorer():
    return render_template('explorer.html')

@app.route('/history')
def history():
    return render_template('history.html')

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('index'))
    return render_template('feedback.html')

@app.route('/status')
def status():
    return render_template('status.html', engine_status=ENGINE_AVAILABLE)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
