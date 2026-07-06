import sqlite3
import bcrypt

DATABASE = 'wifi_pentool.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # USERS table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # SCANS table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            network_name TEXT,
            modules_run TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'in progress',
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    ''')

    # VULNERABILITY TYPE table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerability_type (
            vulntype_id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL
        )
    ''')

    # VULNERABILITIES table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            vulntype_id INTEGER,
            severity TEXT,
            cvss_score REAL,
            description TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
            FOREIGN KEY (vulntype_id) REFERENCES vulnerability_type(vulntype_id)
        )
    ''')

    # RECOMMENDATIONS table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS recommendations (
            rec_id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_id INTEGER,
            recommendation TEXT,
            FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(vuln_id)
        )
    ''')

    # REPORTS table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            report_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            pdf_path TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
        )
    ''')

    # Seed vulnerability types
    vuln_types = [
        'vsftpd Backdoor (CVE-2011-2523)',
        'UnrealIRCd Backdoor (CVE-2010-2075)',
        'Exposed Root Shell',
        'Exposed Database Service',
        'VNC Remote Access Exposed',
        'Telnet Unencrypted Access',
        'FTP Unencrypted Access',
        'SMTP Service Exposed',
        'RPC/NFS Service Exposed',
    ]
    for vtype in vuln_types:
        cursor.execute('SELECT * FROM vulnerability_type WHERE type = ?', (vtype,))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO vulnerability_type (type) VALUES (?)', (vtype,))

    # Seed admin credential
    cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if not cursor.fetchone():
        password = 'admin123'
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                      ('admin', password_hash.decode('utf-8')))
        print('Admin credentials seeded successfully')

    conn.commit()
    conn.close()
    print('Database initialized successfully')

if __name__ == '__main__':
    init_db()
