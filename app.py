import os
import pymysql
import pymongo
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from engine import run_matching_engine

app = Flask(__name__)
app.secret_key = "alchemist-secret-key"
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB file limit

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

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

def load_ai_prompt_template():
    prompt_path = os.path.join(os.getcwd(), 'prompts', 'explanation_prompt.txt')
    if os.path.exists(prompt_path):
        with open(prompt_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "Explain vulnerability {vulnerability_id} for package {package_name} v{installed_version}."

def generate_ai_explanation(finding):
    template = load_ai_prompt_template()
    prompt = template.format(
        package_name=finding.get('package_name', finding.get('package', 'Unknown')),
        installed_version=finding.get('version', 'Unknown'),
        vulnerability_id=finding.get('vulnerability_id', finding.get('id', 'N/A')),
        vulnerability_summary=finding.get('summary', 'No summary provided.'),
        fixed_version=finding.get('fixed_version', 'See advisory')
    )
    
    # Offline / Fallback Local Explanation Builder
    explanation = (
        f"Security Risk Analysis for {finding.get('vulnerability_id', 'Vulnerability')}:\n\n"
        f"1. Explanation: The installed version ({finding.get('version')}) of "
        f"'{finding.get('package_name', finding.get('package'))}' contains a known security flaw: {finding.get('summary')}.\n"
        f"2. Potential Impact: Unauthenticated remote attackers may exploit this issue to trigger denial of service or unauthorized data exposure in production.\n"
        f"3. Remediation Command: Run `pip install --upgrade {finding.get('package_name', finding.get('package'))}` to update to a non-vulnerable release."
    )
    return explanation

@app.route('/', methods=['GET'])
def index():
    return render_template('import.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files and 'requirements' not in request.files:
        flash('No file part provided in request.', 'danger')
        return redirect(url_for('index'))
    
    file = request.files.get('file') or request.files.get('requirements')
    
    if not file or file.filename == '':
        flash('No file selected. Please select a valid requirements.txt file.', 'warning')
        return redirect(url_for('index'))

    # Edge Case Handler: Reject non-txt uploads (e.g., cat images, binary files)
    if not file.filename.lower().endswith('.txt'):
        flash('Invalid file format. Only plain text manifest files (.txt) are supported.', 'danger')
        return redirect(url_for('index'))

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        if not lines or all(not line.strip() for line in lines):
            flash('Uploaded file is empty.', 'warning')
            return redirect(url_for('index'))

        packages = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and '==' in line:
                parts = line.split('==', 1)
                packages.append((parts[0].strip(), parts[1].strip()))

        if not packages:
            flash('No pinned dependencies (e.g., package==1.0.0) found in the file.', 'warning')
            return redirect(url_for('index'))

        findings = run_matching_engine(packages)
        return render_template('results.html', findings=findings, filename=file.filename)

    except UnicodeDecodeError:
        flash('Encoding Error: Binary or image file detected instead of a plain text file.', 'danger')
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'An unexpected error occurred during processing: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/explain', methods=['POST'])
def explain_finding():
    data = request.json or {}
    explanation = generate_ai_explanation(data)
    return jsonify({'status': 'success', 'explanation': explanation})

@app.route('/projects')
def projects():
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM projects ORDER BY created_at DESC;")
            projects_data = cursor.fetchall()
        conn.close()
    except Exception:
        projects_data = []
    return render_template('projects.html', projects=projects_data)

@app.route('/explorer')
def explorer():
    try:
        mongo_col = get_mongo_collection()
        docs = list(mongo_col.find({}, {'_id': 0}).limit(20))
    except Exception:
        docs = []
    return render_template('explorer.html', vulnerabilities=docs)

@app.route('/finding/<finding_id>')
def finding_detail(finding_id):
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM scan_findings WHERE finding_id = %s;", (finding_id,))
            finding = cursor.fetchone()
        conn.close()
    except Exception:
        finding = None
    return render_template('finding.html', finding=finding)

@app.route('/history')
def history():
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM scans ORDER BY scan_timestamp DESC;")
            scans_data = cursor.fetchall()
        conn.close()
    except Exception:
        scans_data = []
    return render_template('history.html', scans=scans_data)

@app.route('/status')
def status():
    status_info = {'mysql': 'Disconnected', 'mongo': 'Disconnected'}
    try:
        conn = get_db_connection()
        conn.ping()
        status_info['mysql'] = 'Connected'
        conn.close()
    except Exception:
        pass

    try:
        mongo_col = get_mongo_collection()
        mongo_col.database.client.admin.command('ping')
        status_info['mongo'] = 'Connected'
    except Exception:
        pass

    return render_template('status.html', status=status_info)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
