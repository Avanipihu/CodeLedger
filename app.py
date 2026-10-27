from flask import Flask, render_template, request, redirect, url_for, flash
import os
import sqlite3

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
    """Home / Dashboard view."""
    return render_template('base.html', active_page='index')

@app.route('/import', methods=['GET', 'POST'])
def import_manifest():
    if request.method == 'POST':
        flash('Manifest uploaded successfully!', 'success')
        return redirect(url_for('results'))
    return render_template('base.html', active_page='import')

@app.route('/projects')
def projects():
    return render_template('base.html', active_page='projects')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        return redirect(url_for('results'))
    return render_template('base.html', active_page='scan')

@app.route('/findings')
def results():
    return render_template('base.html', active_page='findings')

@app.route('/explorer')
def explorer():
    return render_template('base.html', active_page='explorer')

@app.route('/history')
def history():
    return render_template('base.html', active_page='history')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
