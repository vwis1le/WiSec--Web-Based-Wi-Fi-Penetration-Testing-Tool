from flask import Flask, render_template, request, redirect, url_for, session
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Login route
@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Authentication will be added once database is confirmed
        # For now just checking hardcoded credentials for testing
        if username == 'admin' and password == 'admin123':
            session['user'] = username
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials. Please try again.'
    return render_template('login.html', error=error)

# Dashboard route
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

# Logout route
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# Selcting modules
@app.route('/modules', methods=['GET', 'POST'])
def modules():
    if 'user' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        selected_modules = request.form.getlist('modules')
        if selected_modules:
            return redirect(url_for('progress'))
    return render_template('modules.html')

# Displaying progress
@app.route('/progress')
def progress():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('progress.html')

# Displaying results
@app.route('/results')
def results():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('results.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
