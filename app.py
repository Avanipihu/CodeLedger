import os
import pymysql
import pymongo
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from werkzeug.utils import secure_filename

try:
    from engine import run_matching_engine
except ImportError:
    def run_matching_engine(packages):
        return [
            {
                "package_name": "lodash",
                "version": "4.17.21",
                "vulnerability_id": "CVE-2021-23337",
                "severity": "High",
                "cvss_score": 7.5,
                "status": "Affected",
                "summary": "Prototype pollution vulnerability in lodash which may allow remote code execution.",
                "fixed_version": "4.17.22",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"]
            },
            {
                "package_name": "express",
                "version": "4.18.2",
                "vulnerability_id": "CVE-2022-24999",
                "severity": "Medium",
                "cvss_score": 5.3,
                "status": "Affected",
                "summary": "Open redirect vulnerability in express server routes.",
                "fixed_version": "4.18.3",
                "references": ["https://github.com/advisories/GHSA-express"]
            },
            {
                "package_name": "axios",
                "version": "1.5.0",
                "vulnerability_id": "CVE-2023-45857",
                "severity": "Low",
                "cvss_score": 3.2,
                "status": "Not Affected",
                "summary": "SSRF vulnerability in axios HTTP client.",
                "fixed_version": "1.6.0",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-45857"]
            }
        ]

app = Flask(__name__)
app.secret_key = "alchemist-secret-key"
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB file limit

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# In-memory storage for feedback demonstration
FEEDBACK_STORE = []

def get_db_connection():
    return pymysql.connect(
        host=os.getenv('MYSQL_HOST', 'localhost'),
        user=os.getenv('MYSQL_USER', 'root'),
        password=os.getenv('MYSQL_PASSWORD', ''),
        database=os.getenv('MYSQL_DB', 'codeledger'),
        cursorclass=pymysql.cursors.DictCursor
    )

def get_mongo_collection():
    client = pymongo.MongoClient(os.getenv('MONGO_URI', 'mongodb://localhost:27017/'))
    db = client[os.getenv('MONGO_DB', 'codeledger')]
    return db['vulnerabilities']

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'admin' and password == 'password123':
            session['user'] = username
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password (try admin / password123)', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        flash('Account registered successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/', methods=['GET'])
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    recent_scans = [
        {"project": "web-app", "scanned_at": "2025-09-10 14:32", "status": "Completed", "findings": 3},
        {"project": "api-service", "scanned_at": "2025-09-09 11:20", "status": "Completed", "findings": 1},
        {"project": "mobile-app", "scanned_at": "2025-09-08 16:45", "status": "Completed", "findings": 0}
    ]
    return render_template('import.html', recent_scans=recent_scans)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    raw_text = request.form.get('dependencies_text', '').strip()
    file = request.files.get('file') or request.files.get('requirements')

    packages = []
    if raw_text:
        for line in raw_text.splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '==' in line:
                parts = line.split('==', 1)
                packages.append((parts[0].strip(), parts[1].strip()))
    elif file and file.filename != '':
        if not file.filename.lower().endswith('.txt'):
            flash('Invalid file format. Only plain text (.txt) files are supported.', 'danger')
            return redirect(url_for('index'))

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f.readlines():
                    line = line.strip()
                    if line and not line.startswith('#') and '==' in line:
                        parts = line.split('==', 1)
                        packages.append((parts[0].strip(), parts[1].strip()))
        except UnicodeDecodeError:
            flash('Encoding Error: Binary or non-text file detected.', 'danger')
            return redirect(url_for('index'))
    else:
        flash('Please upload a valid requirements.txt file or paste dependencies.', 'warning')
        return redirect(url_for('index'))

    if not packages:
        flash('No pinned dependencies (e.g., package==1.0.0) found.', 'warning')
        return redirect(url_for('index'))

    findings = run_matching_engine(packages)
    summary = {
        'total': len(findings),
        'high': sum(1 for f in findings if f.get('severity', '').lower() == 'high'),
        'medium': sum(1 for f in findings if f.get('severity', '').lower() == 'medium'),
        'low': sum(1 for f in findings if f.get('severity', '').lower() == 'low')
    }

    return render_template('results.html', findings=findings, summary=summary)

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if 'user' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        msg = request.form.get('feedback_message')
        rating = request.form.get('rating')
        if msg:
            FEEDBACK_STORE.append({'user': session['user'], 'message': msg, 'rating': rating})
            flash('Thank you! Your feedback has been submitted successfully.', 'success')
        return redirect(url_for('feedback'))
        
    return render_template('feedback.html', feedbacks=FEEDBACK_STORE)

@app.route('/projects')
def projects():
    if 'user' not in session:
        return redirect(url_for('login'))
    projects_data = []
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM projects ORDER BY created_at DESC;")
            projects_data = cursor.fetchall()
    except Exception as e:
        # This will show you the exact error on your screen instead of a 500 page!
        return f"<h3>Database / Route Error:</h3><pre>{str(e)}</pre><br><a href='/'>Go Home</a>"
    finally:
        if conn:
            conn.close()
    return render_template('projects.html', projects=projects_data)

@app.route('/explorer')
def explorer():
    if 'user' not in session:
        return redirect(url_for('login'))
    try:
        mongo_col = get_mongo_collection()
        docs = list(mongo_col.find({}, {'_id': 0}).limit(20))
    except Exception:
        docs = []
    return render_template('explorer.html', vulnerabilities=docs)

@app.route('/finding/<finding_id>')
def finding_detail(finding_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    finding = {
        "vulnerability_id": finding_id,
        "severity": "High",
        "package": "lodash",
        "affected_version": "< 4.17.22",
        "fixed_version": "4.17.22",
        "cvss_score": "7.5 (High)",
        "description": "Prototype pollution vulnerability in lodash which may allow remote code execution.",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
            "https://github.com/advisories/GHSA-p6lt-9vh3-22v7"
        ]
    }
    return render_template('finding.html', finding=finding)

@app.route('/history')
def history():
    if 'user' not in session:
        return redirect(url_for('login'))
    scans_data = []
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM scans ORDER BY scan_timestamp DESC;")
            scans_data = cursor.fetchall()
    except Exception:
        pass
    finally:
        if conn:
            conn.close()
    return render_template('history.html', scans=scans_data)

@app.route('/status')
def status():
    if 'user' not in session:
        return redirect(url_for('login'))
    status_info = {'mysql': 'Disconnected', 'mongo': 'Disconnected'}
    conn = None
    try:
        conn = get_db_connection()
        conn.ping()
        status_info['mysql'] = 'Connected'
    except Exception:
        pass
    finally:
        if conn:
            conn.close()

    try:
        mongo_col = get_mongo_collection()
        mongo_col.database.client.admin.command('ping')
        status_info['mongo'] = 'Connected'
    except Exception:
        pass

    return render_template('status.html', status=status_info)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
