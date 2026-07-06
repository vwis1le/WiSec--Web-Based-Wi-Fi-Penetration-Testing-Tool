from scanner import run_scan_background, scan_progress
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from database import get_db
from scanner import run_scan_background
import bcrypt
import socket
import ipaddress
from report import generate_report
from flask import send_file
import os
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from datetime import datetime, timezone, timedelta

app = Flask(__name__)
app.secret_key = 'wifipentool_secret_key'

EAT = timezone(timedelta(hours=3))

def now_eat():
    return datetime.now(EAT).strftime('%Y-%m-%d %H:%M:%S')

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

# Automatically optaining the ip network
def get_local_subnet():
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  
        local_ip = s.getsockname()[0]
        s.close()

        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return str(network)
    except Exception:
        return "192.168.1.0/24"  

# Module selection route
@app.route('/modules', methods=['GET', 'POST'])
def modules():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        target_ip = request.form.get('target_ip', '').strip() or get_local_subnet()
        selected_modules = request.form.getlist('modules')
        if selected_modules:
            # Create scan record in database
            db = get_db()
            db.execute(
                'INSERT INTO scans (user_id, network_name, modules_run, status, timestamp) VALUES (? , ?, ?, ?, ?)',
                (session['user_id'], target_ip, ', '.join(selected_modules), 'running', now_eat())
            )
            db.commit()

            # Get the new scan_id
            scan_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
            db.close()

            # Store scan_id in session
            session['scan_id'] = scan_id
            session['selected_modules'] = selected_modules

            target_ssid = request.form.get('target_ssid', '').strip()
            session['target_ssid'] = target_ssid

            # Start scan in background thread
            run_scan_background(scan_id, selected_modules, target_ip=target_ip, target_ssid=target_ssid)


            return redirect(url_for('progress'))
    
    suggested_network = get_local_subnet()
    return render_template('modules.html', suggested_network=suggested_network)

# Progress route
@app.route('/progress')
def progress():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('progress.html')

# Scan status route — called by progress page to check if scan is done
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

#Report Download
@app.route('/download_report/<int:scan_id>')
def download_report(scan_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    db = get_db()
    # Verify scan belongs to this user
    scan = db.execute(
        'SELECT * FROM scans WHERE scan_id = ? AND user_id = ?',
        (scan_id, session['user_id'])
    ).fetchone()

    # Get most recent report for this scan
    report = db.execute(
        'SELECT * FROM reports WHERE scan_id = ? ORDER BY generated_at DESC LIMIT 1',
        (scan_id,)
    ).fetchone()
    db.close()

    if not scan or not report:
        return redirect(url_for('dashboard'))

    return send_file(
        report['pdf_path'],
        as_attachment=True,
        download_name=f'wisec_report_scan{scan_id}.pdf'
    )

#Report Regeneration
@app.route('/generate_report/<int:scan_id>')
def generate_report_route(scan_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    db = get_db()
    scan = db.execute(
        'SELECT * FROM scans WHERE scan_id = ? AND user_id = ?',
        (scan_id, session['user_id'])
    ).fetchone()
    db.close()

    if not scan:
        return redirect(url_for('dashboard'))

    try:
        generate_report(scan_id)
    except Exception as e:
        print(f'Report generation error: {e}')

    return redirect(url_for('results', scan_id=scan_id))


# Logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
