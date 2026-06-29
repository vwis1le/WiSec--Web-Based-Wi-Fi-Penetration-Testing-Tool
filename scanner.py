import subprocess
import threading
from database import get_db
from datetime import datetime

def run_nmap(target_ip, scan_id):
    """Run Nmap scan and store results"""
    try:
        result = subprocess.run(
            ['nmap', '-sV', target_ip],
            capture_output=True,
            text=True,
            timeout=120
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Nmap scan timed out"
    except Exception as e:
        return f"Nmap error: {str(e)}"

def run_aircrack(interface, scan_id):
    """Simulate WPA2 cracking — requires wireless adapter"""
    # Simulated output for controlled lab environment
    return """
[+] Initializing Aircrack-ng...
[+] Setting interface to monitor mode...
[*] Scanning for WPA2 networks...
[+] Target network found
[*] Capturing WPA2 handshake...
[+] Handshake captured successfully
[*] Running dictionary attack...
[+] Weak password detected — network is vulnerable to WPA2 cracking
"""

def run_wifite(interface, scan_id):
    """Simulate deauthentication attack — requires wireless adapter"""
    return """
[+] Initializing Wifite...
[+] Setting interface to monitor mode...
[*] Scanning for target network...
[+] Target network found
[*] Sending deauthentication packets...
[+] Devices successfully disconnected
[+] Network is vulnerable to deauthentication attacks
[!] No Management Frame Protection (MFP) detected
"""

def run_hostapd(interface, scan_id):
    """Simulate evil twin attack — requires wireless adapter"""
    return """
[+] Initializing Hostapd...
[*] Creating rogue access point...
[+] Evil twin access point created successfully
[*] Broadcasting with same SSID as target network...
[+] Network is vulnerable to evil twin attacks
[!] Clients may connect to rogue access point
"""

def store_results(scan_id, module, output):
    """Store scan results and vulnerabilities in database"""
    db = get_db()

    # Determine vulnerabilities based on module output
    vulns = []

    if module == 'network_scan':
        # Check for open ports in nmap output
        open_ports = []
        for line in output.split('\n'):
            if 'open' in line.lower() and '/tcp' in line.lower():
                open_ports.append(line.strip())
    
        if open_ports:
            vulns.append({
                'vulntype': 'Open port detected',
                'severity': 'Medium',
                'cvss_score': 5.3,
                'description': f'Open ports detected: {", ".join(open_ports)}'
            })
    
        # Check for unencrypted services
        if 'http' in output.lower() and 'https' not in output.lower():
            vulns.append({
                'vulntype': 'Unencrypted service exposed',
                'severity': 'Medium',
                'cvss_score': 5.9,
                'description': 'Unencrypted HTTP service detected on the network'
            })

    elif module == 'wpa2_crack':
        if 'vulnerable' in output.lower():
            vulns.append({
                'vulntype': 'WPA2 weak password',
                'severity': 'High',
                'cvss_score': 8.1,
                'description': 'Network password is susceptible to dictionary-based cracking'
            })
            vulns.append({
                'vulntype': 'WPA2 handshake captured',
                'severity': 'High',
                'cvss_score': 7.5,
                'description': 'WPA2 handshake was successfully captured during authentication'
            })

    elif module == 'deauth':
        if 'vulnerable' in output.lower():
            vulns.append({
                'vulntype': 'Deauthentication attack',
                'severity': 'High',
                'cvss_score': 7.4,
                'description': 'Network is vulnerable to forged deauthentication packet attacks'
            })
            vulns.append({
                'vulntype': 'No Management Frame Protection',
                'severity': 'Medium',
                'cvss_score': 5.8,
                'description': 'Network does not implement Management Frame Protection (MFP/802.11w)'
            })

    elif module == 'evil_twin':
        if 'vulnerable' in output.lower():
            vulns.append({
                'vulntype': 'Evil twin access point',
                'severity': 'High',
                'cvss_score': 8.2,
                'description': 'Network is vulnerable to evil twin access point simulation'
            })
            vulns.append({
                'vulntype': 'Rogue access point detected',
                'severity': 'High',
                'cvss_score': 7.8,
                'description': 'A rogue access point impersonating the target network was created successfully'
            })

    # Store each vulnerability in database
    for vuln in vulns:
        # Get vulntype_id
        vulntype = db.execute(
            'SELECT vulntype_id FROM vulnerability_type WHERE type = ?',
            (vuln['vulntype'],)
        ).fetchone()

        if vulntype:
            db.execute('''
                INSERT INTO vulnerabilities (scan_id, vulntype_id, severity, cvss_score, description)
                VALUES (?, ?, ?, ?, ?)
            ''', (scan_id, vulntype['vulntype_id'], vuln['severity'], vuln['cvss_score'], vuln['description']))

            # Get the vuln_id just inserted
            vuln_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]

            # Store recommendation
            recommendation = get_recommendation(vuln['vulntype'])
            db.execute('''
                INSERT INTO recommendations (vuln_id, recommendation)
                VALUES (?, ?)
            ''', (vuln_id, recommendation))

    db.commit()
    db.close()

def get_recommendation(vulntype):
    """Return remediation advice for each vulnerability type"""
    recommendations = {
        'Open port detected': 'Close unnecessary ports using a firewall. Only keep ports open that are required for business operations.',
        'WPA2 weak password': 'Change the Wi-Fi password to a strong passphrase of at least 12 characters including uppercase, lowercase, numbers and symbols.',
        'WPA2 handshake captured': 'Enable WPA3 if supported by your router. Use a strong password to make dictionary attacks infeasible.',
        'Deauthentication attack': 'Enable Management Frame Protection (802.11w) on your router if supported to prevent deauthentication attacks.',
        'No Management Frame Protection': 'Enable 802.11w/MFP in your router settings to protect against deauthentication and disassociation attacks.',
        'Evil twin access point': 'Educate users to verify network authenticity before connecting. Consider implementing 802.1X authentication.',
        'Rogue access point detected': 'Deploy wireless intrusion detection systems (WIDS) to detect and alert on rogue access points.',
        'Unencrypted service exposed': 'Replace unencrypted services with encrypted alternatives such as HTTPS, SFTP, and SSH.',
        'Outdated service version': 'Update all network services and firmware to the latest versions to patch known vulnerabilities.'
    }
    return recommendations.get(vulntype, 'Consult a cybersecurity professional for remediation advice.')

def run_scan(scan_id, modules, target_ip='192.168.1.0/24', interface='wlan0'):
    """Main scan function — runs selected modules and stores results"""
    db = get_db()

    # Update scan status to running
    db.execute('UPDATE scans SET status = ? WHERE scan_id = ?', ('running', scan_id))
    db.commit()
    db.close()

    scan_log = []

    for module in modules:
        scan_log.append(f'[+] Starting module: {module}')

        if module == 'network_scan':
            output = run_nmap(target_ip, scan_id)
        elif module == 'wpa2_crack':
            output = run_aircrack(interface, scan_id)
        elif module == 'deauth':
            output = run_wifite(interface, scan_id)
        elif module == 'evil_twin':
            output = run_hostapd(interface, scan_id)
        else:
            output = ''

        scan_log.append(output)
        store_results(scan_id, module, output)

    # Update scan status to complete
    db = get_db()
    db.execute('UPDATE scans SET status = ? WHERE scan_id = ?', ('complete', scan_id))
    db.commit()
    db.close()

    return '\n'.join(scan_log)

def run_scan_background(scan_id, modules, target_ip='192.168.1.0/24', interface='wlan0'):
    """Run scan in background thread so Flask stays responsive"""
    thread = threading.Thread(
        target=run_scan,
        args=(scan_id, modules, target_ip, interface)
    )
    thread.daemon = True
    thread.start()
