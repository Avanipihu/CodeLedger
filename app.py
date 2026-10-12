import os
import pymysql
import pymongo
from flask import Flask, render_template, request, redirect, url_for, flash

# 1. Fixed Import Interface with Person 3 (Weaver)
from engine import run_matching_engine

app = Flask(__name__)
app.secret_key = "alchemist-secret-key"
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2 MB max file size limit

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database Helper Functions
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


@app.route('/', methods=['GET'])
def index():
    return render_template('import.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Poison Pill Handled Upload Endpoint"""
    if 'file' not in request.files:
        flash('No file part provided in the request.', 'danger')
        return redirect(url_for('index'))
    
    file = request.files['file']
    
    if not file or file.filename == '':
        flash('No file selected. Please choose a requirements.txt file.', 'warning')
        return redirect(url_for('index'))

    # Reject non-text/invalid files
    if not file.filename.endswith('.txt'):
        flash('Invalid file type! Only plain text (.txt) files are accepted.', 'danger')
        return redirect(url_for('index'))

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)

    packages = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        if not lines or all(not line.strip() for line in lines):
            flash('Uploaded file is completely empty.', 'warning')
            return redirect(url_for('index'))

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '==' in line:
                pkg_name, version = line.split('==', 1)
                packages.append((pkg_name.strip(), version.strip()))
            else:
                # Basic check for unpinned or malformed lines
                pass

        if not packages:
            flash('No valid pinned dependencies (e.g. package==1.0.0) found in file.', 'warning')
            return redirect(url_for('index'))

        # Invoke Weaver's matching engine
        findings = run_matching_engine(packages)
        return render_template('results.html', findings=findings, filename=file.filename)

    except UnicodeDecodeError:
        flash('File encoding error: Uploaded binary or image file instead of a valid text file.', 'danger')
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'An unexpected error occurred while processing: {str(e)}', 'danger')
        return redirect(url_for('index'))


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
