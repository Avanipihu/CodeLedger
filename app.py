import os
from flask import Flask, render_template, request, redirect, url_for, flash
# Import Weaver's matching engine from your repository
from engine import run_matching_engine

app = Flask(__name__)
app.secret_key = "alchemist-secret-key"
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/', methods=['GET'])
def index():
    return render_template('import.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part uploaded.')
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file.')
        return redirect(url_for('index'))

    if file and file.filename.endswith('.txt'):
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)

        # Parse requirements.txt lines into (package_name, version) tuples
        packages = []
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '==' in line:
                    parts = line.split('==')
                    packages.append((parts[0].strip(), parts[1].strip()))

        # Trigger Weaver's matching engine
        try:
            findings = run_matching_engine(packages)
        except Exception as e:
            findings = []
            flash(f"Error executing matching engine: {str(e)}")

        return render_template('results.html', findings=findings, filename=file.filename)

    flash('Invalid file format. Please upload a .txt file.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
