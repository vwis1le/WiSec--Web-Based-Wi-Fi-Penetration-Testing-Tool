from flask import Flask, render_template, request, redirect, url_for, session
from database import get_db
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
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
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
    
    # Get all scans
    scans = db.execute(
        'SELECT * FROM scans WHERE user_id = ? ORDER BY timestamp DESC',
        (session['user_id'],)
    ).fetchall()
    
    # Get total scans count
    total_scans = db.execute(
        'SELECT COUNT(*) FROM scans WHERE user_id = ?',
        (session['user_id'],)
    ).fetchone()[0]
    
    # Get total vulnerabilities found
    total_vulns = db.execute(
        'SELECT COUNT(*) FROM vulnerabilities v JOIN scans s ON v.scan_id = s.scan_id WHERE s.user_id = ?',
        (session['user_id'],)
    ).fetchone()[0]
    
    # Get total reports generated
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
            session['selected_modules'] = selected_modules
            return redirect(url_for('progress'))
    return render_template('modules.html')

# Progress route
@app.route('/progress')
def progress():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('progress.html')

# Results route
@app.route('/results')
def results():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('results.html')

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
