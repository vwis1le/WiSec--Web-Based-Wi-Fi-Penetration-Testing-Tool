from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from database import get_db
from scanner import run_scan_background
import bcrypt

app = Flask(__name__)
app.secret_key = 'wifipentool_secret_key'

# Login route
@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        db.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            session['user'] = username
            session['user_id'] = user['user_id']
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials. Please try again.'

    return render_template('login.html', error=error)

# Dashboard route
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    db = get_db()
    scans = db.execute(
        'SELECT * FROM scans WHERE user_id = ? ORDER BY timestamp DESC',
        (session['user_id'],)
    ).fetchall()

    total_scans = db.execute(
        'SELECT COUNT(*) FROM scans WHERE user_id = ?',
        (session['user_id'],)
    ).fetchone()[0]

    total_vulns = db.execute(
        'SELECT COUNT(*) FROM vulnerabilities v JOIN scans s ON v.scan_id = s.scan_id WHERE s.user_id = ?',
        (session['user_id'],)
    ).fetchone()[0]

    total_reports = db.execute(
        'SELECT COUNT(*) FROM reports r JOIN scans s ON r.scan_id = s.scan_id WHERE s.user_id = ?',
        (session['user_id'],)
    ).fetchone()[0]

    db.close()

    return render_template('dashboard.html',
                           scans=scans,
                           total_scans=total_scans,
                           total_vulns=total_vulns,
                           total_reports=total_reports)

# Module selection route
@app.route('/modules', methods=['GET', 'POST'])
def modules():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        selected_modules = request.form.getlist('modules')
        if selected_modules:
            # Create scan record in database
            db = get_db()
            db.execute(
                'INSERT INTO scans (user_id, network_name, modules_run, status) VALUES (?, ?, ?, ?)',
                (session['user_id'], 'Target Network', ', '.join(selected_modules), 'running')
            )
            db.commit()

            # Get the new scan_id
            scan_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
            db.close()

            # Store scan_id in session
            session['scan_id'] = scan_id
            session['selected_modules'] = selected_modules

            # Start scan in background thread
            run_scan_background(scan_id, selected_modules)

            return redirect(url_for('progress'))

    return render_template('modules.html')

# Progress route
@app.route('/progress')
def progress():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('progress.html')

# Scan status route — called by progress page to check if scan is done
from scanner import run_scan_background, scan_progress

@app.route('/scan_status')
def scan_status():
    if 'user' not in session:
        return jsonify({'status': 'error'})

    scan_id = session.get('scan_id')
    if not scan_id:
        return jsonify({'status': 'error'})

    db = get_db()
    scan = db.execute('SELECT status FROM scans WHERE scan_id = ?', (scan_id,)).fetchone()
    db.close()

    progress = scan_progress.get(scan_id, {'phase': 'Reconnaissance', 'percent': 0, 'log': []})

    return jsonify({
        'status': scan['status'],
        'phase': progress['phase'],
        'percent': progress['percent'],
        'log': progress['log']
    })

# Results route
@app.route('/results')
def results():
    if 'user' not in session:
        return redirect(url_for('login'))

    scan_id = request.args.get('scan_id') or session.get('scan_id')
    if not scan_id:
        return redirect(url_for('dashboard'))

    db = get_db()

    # Get scan info
    scan = db.execute(
        'SELECT * FROM scans WHERE scan_id = ? AND user_id = ?',
        (scan_id, session['user_id'])
    ).fetchone()

    # Get vulnerabilities with their types
    vulns = db.execute('''
        SELECT v.*, vt.type as vuln_type, r.recommendation
        FROM vulnerabilities v
        JOIN vulnerability_type vt ON v.vulntype_id = vt.vulntype_id
        LEFT JOIN recommendations r ON v.vuln_id = r.vuln_id
        WHERE v.scan_id = ?
        ORDER BY v.cvss_score DESC
    ''', (scan_id,)).fetchall()

    db.close()

    return render_template('results.html', scan=scan, vulns=vulns)

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
