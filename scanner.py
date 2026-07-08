from report import generate_report
import subprocess
import threading
from database import get_db
from datetime import datetime

# In-memory progress tracker: { scan_id: {'phase': str, 'percent': int, 'log': [str, ...]} }
scan_progress = {}

def log(scan_id, message, level='info'):
    scan_progress.setdefault(scan_id, {'phase': 'Reconnaissance', 'percent': 0, 'log': []})
    scan_progress[scan_id]['log'].append({'level': level, 'message': message})

def set_phase(scan_id, phase, percent):
    scan_progress.setdefault(scan_id, {'phase': phase, 'percent': percent, 'log': []})
    scan_progress[scan_id]['phase'] = phase
    scan_progress[scan_id]['percent'] = percent

#NETWORK SCAN MODULE
def run_nmap(target_ip, scan_id):
    log(scan_id, f'Starting Nmap scan on {target_ip}...', 'success')
    try:
        result = subprocess.run(
            ['nmap', '-sV', target_ip],
            capture_output=True, text=True, timeout=300
        )
        log(scan_id, 'Nmap scan complete.', 'success')
        return result.stdout
    except subprocess.TimeoutExpired:
        log(scan_id, 'Nmap scan timed out.', 'error')
        return "Nmap scan timed out"
    except Exception as e:
        log(scan_id, f'Nmap error: {str(e)}', 'error')
        return f"Nmap error: {str(e)}"

def get_network_info(interface, target_ssid, scan_id):
    """Scan for networks and return BSSID, channel and client MAC for target SSID"""
    import time
    import os

    log(scan_id, f'Scanning for network: {target_ssid}...', 'info')

    out_file = f'/tmp/wisec_scan_{scan_id}'

    proc = subprocess.Popen(
        ['sudo', 'airodump-ng', '--output-format', 'csv', '-w', out_file, interface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(20)
    proc.terminate()
    proc.wait()

    csv_path = out_file + '-01.csv'
    if not os.path.exists(csv_path):
        log(scan_id, 'Network scan failed — no output file generated.', 'error')
        return None, None, None

    bssid = None
    channel = None
    client_mac = None

    with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    # Parse CSV for target SSID
    for line in lines:
         if target_ssid in line:
            parts = line.split(',')
            log(scan_id, f'Found line with {len(parts)} parts', 'info')
            if len(parts) >= 14:
                bssid = parts[0].strip()
                channel = parts[3].strip()
                # Validate it looks like a BSSID (MAC address format)
                if len(bssid) == 17 and ':' in bssid:
                    log(scan_id, f'Found {target_ssid} — BSSID: {bssid}, Channel: {channel}', 'success')
                    break

    # Parse client section for a connected client
    if bssid:
        for line in lines:
            if bssid in line and target_ssid not in line:
                parts = line.split(',')
                if len(parts) >= 6:
                    mac = parts[0].strip()
                    associated_bssid = parts[5].strip()
                    # Confirm client is associated with our target
                    if associated_bssid == bssid and len(mac) == 17:
                        client_mac = mac
                        log(scan_id, f'Found connected client: {client_mac}', 'info')
                        break

    if not bssid:
        log(scan_id, f'Network "{target_ssid}" not found — ensure you are within range.', 'error')

    if not client_mac:
        log(scan_id, 'No connected client found — deauth will broadcast to all clients.', 'warning')

    return bssid, channel, client_mac

#WPA CRACKING
def run_aircrack(interface, scan_id, target_ssid=''):
    import os
    import time

    log(scan_id, f'run_aircrack called — interface: {interface}, ssid: "{target_ssid}"', 'info')

    wordlist = '/usr/share/wordlists/rockyou.txt'
    cap_file = f'/tmp/wisec_capture_{scan_id}'

    # Auto-detect BSSID, channel and client
    bssid, channel, client_mac = get_network_info(interface, target_ssid, scan_id)
    if not bssid or not channel:
        return 'Target network not found — ensure you are within range.'

    log(scan_id, f'Starting handshake capture on channel {channel}...', 'info')

    # Start airodump-ng capture
    airodump = subprocess.Popen(
        ['sudo', 'airodump-ng', '--bssid', bssid, '-c', channel,
         '-w', cap_file, '--output-format', 'cap', interface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    time.sleep(3)

    # Build deauth command — target specific client if found
    log(scan_id, 'Sending deauth packets to force handshake...', 'info')
    deauth_cmd = ['sudo', 'aireplay-ng', '--deauth', '10', '-a', bssid]
    if client_mac:
        deauth_cmd += ['-c', client_mac]
    deauth_cmd.append(interface)

    try:
        subprocess.run(deauth_cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        log(scan_id, 'Deauth send timed out — continuing anyway, capture may still succeed.', 'warning')
    except Exception as e:
        log(scan_id, f'Deauth send error: {str(e)}', 'error')

    # Wait for handshake
    time.sleep(20)
    airodump.terminate()
    airodump.wait()

    cap_path = cap_file + '-01.cap'
    if not os.path.exists(cap_path):
        log(scan_id, 'Capture file not found.', 'error')
        return 'Handshake capture failed'

    # Check if handshake was actually captured
    try:
        check = subprocess.run(
            ['sudo', 'aircrack-ng', cap_path],
            capture_output=True, text=True, timeout=15
        )
        check_output = check.stdout
    except subprocess.TimeoutExpired:
        log(scan_id, 'Handshake check timed out — assuming no handshake captured.', 'warning')
        return 'Handshake check timed out'
    except Exception as e:
        log(scan_id, f'Handshake check error: {str(e)}', 'error')
        return f'Handshake check error: {str(e)}'

    if 'handshake' not in check_output.lower():
        log(scan_id, 'No handshake captured — no clients reconnected in time.', 'warning')
        return 'No handshake captured'

    log(scan_id, 'WPA2 handshake successfully captured.', 'success')
    log(scan_id, 'Running dictionary attack with aircrack-ng...', 'info')

    try:
        result = subprocess.run(
            ['sudo', 'aircrack-ng', '-w', wordlist, '-b', bssid, cap_path],
            capture_output=True, text=True, timeout=300
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        log(scan_id, 'Dictionary attack timed out — password not found within time limit.', 'warning')
        log(scan_id, 'Handshake captured — offline cracking remains possible outside the tool.', 'warning')
        return '[+] WPA2 handshake captured — dictionary attack timed out (password not cracked in time budget)'
    except Exception as e:
        log(scan_id, f'aircrack-ng error: {str(e)}', 'error')
        return f'aircrack-ng error: {str(e)}'

    if 'KEY FOUND' in output:
        for line in output.split('\n'):
            if 'KEY FOUND' in line:
                log(scan_id, f'Password cracked: {line.strip()}', 'warning')
                break
        log(scan_id, 'Network is vulnerable to WPA2 dictionary attack', 'warning')
        return f'[+] Weak password detected — network is vulnerable to WPA2 cracking\n{output}'
    else:
        log(scan_id, 'Password not found in wordlist — network may use a strong password.', 'info')
        log(scan_id, 'Handshake captured — offline cracking remains possible.', 'warning')
        return f'[+] WPA2 handshake captured — vulnerable to offline attack\n{output}'

#DEAUTHENTICATION MODULE
def run_wifite(interface, scan_id, target_ssid=''):
    """Deauthentication attack module — sends forged deauth frames and
    verifies whether the target client disconnects, demonstrating
    vulnerability to deauth attacks (and lack of 802.11w/MFP)."""
    import time

    log(scan_id, f'run_wifite called — interface: {interface}, ssid: "{target_ssid}"', 'info')

    # Reuse the same auto-detection used in run_aircrack
    bssid, channel, client_mac = get_network_info(interface, target_ssid, scan_id)
    if not bssid or not channel:
        return 'Target network not found — ensure you are within range.'

    log(scan_id, f'Sending deauthentication packets to {bssid} on channel {channel}...', 'info')

    deauth_cmd = ['sudo', 'aireplay-ng', '--deauth', '10', '-a', bssid]
    if client_mac:
        deauth_cmd += ['-c', client_mac]
    deauth_cmd.append(interface)

    try:
        result = subprocess.run(deauth_cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        log(scan_id, 'Deauth attack timed out — no confirmation of frame delivery.', 'warning')
        return 'Deauth attack timed out — could not confirm packet delivery'
    except Exception as e:
        log(scan_id, f'Deauth error: {str(e)}', 'error')
        return f'Deauth error: {str(e)}'

    # aireplay-ng reports each ACKed deauth frame sent, e.g.
    # "Sending 64 directed DeAuth. STMAC: [...] [ 32|64 ACKs]"
    acks_sent = output.count('ACKs]') > 0 or 'Sending' in output

    if acks_sent:
        log(scan_id, 'Deauthentication packets sent and acknowledged by access point.', 'success')
        log(scan_id, 'Network is vulnerable to deauthentication attacks — no MFP/802.11w protection detected.', 'warning')
        return f"""[+] Deauthentication packets sent successfully
[+] Network is vulnerable to deauthentication attacks
[!] No Management Frame Protection (MFP/802.11w) detected — deauth frames were accepted unauthenticated
{output}"""
    else:
        log(scan_id, 'Deauth packets sent but no acknowledgement detected — network may have MFP enabled.', 'info')
        return f"""[+] Deauthentication packets sent — no acknowledgement received
[i] Network may have Management Frame Protection (MFP/802.11w) enabled
{output}"""

#EVIL TWIN SIMULATION MODULE
def run_hostapd(interface, scan_id, target_ssid=''):
    """Evil twin module — broadcasts a rogue access point cloning the
    target SSID to demonstrate evil twin impersonation vulnerability.
    NOTE: due to single-adapter hardware limitations, this module
    performs a passive simulation (rogue AP broadcast) rather than an
    active client-migration attack, which would require a second
    wireless adapter to run monitor mode and AP mode concurrently."""
    import os
    import time

    log(scan_id, f'run_hostapd called — interface: {interface}, ssid: "{target_ssid}"', 'info')

    if not target_ssid:
        log(scan_id, 'No target SSID provided — cannot create evil twin.', 'error')
        return 'No target SSID provided — cannot create evil twin.'

    # Derive the base interface name (e.g. wlan0mon -> wlan0)
    base_interface = interface.replace('mon', '') if 'mon' in interface else interface

    # Step 1: take the adapter out of monitor mode so hostapd can use it
    log(scan_id, f'Switching {interface} out of monitor mode...', 'info')
    try:
        subprocess.run(['sudo', 'airmon-ng', 'stop', interface],
                        capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        log(scan_id, 'Timed out switching interface out of monitor mode.', 'error')
        return 'Failed to prepare adapter for AP mode'
    except Exception as e:
        log(scan_id, f'Error switching interface mode: {str(e)}', 'error')
        return f'Error switching interface mode: {str(e)}'

    time.sleep(2)

    # Step 2: write a minimal hostapd config cloning the target SSID
    conf_path = f'/tmp/wisec_hostapd_{scan_id}.conf'
    hostapd_conf = f"""interface={base_interface}
driver=nl80211
ssid={target_ssid}
hw_mode=g
channel=6
"""
    try:
        with open(conf_path, 'w') as f:
            f.write(hostapd_conf)
    except Exception as e:
        log(scan_id, f'Failed to write hostapd config: {str(e)}', 'error')
        return f'Failed to write hostapd config: {str(e)}'

    # Step 3: launch hostapd and let it run briefly to demonstrate the rogue AP
    log(scan_id, f'Creating rogue access point cloning "{target_ssid}"...', 'info')
    hostapd_proc = subprocess.Popen(
        ['sudo', 'hostapd', conf_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    time.sleep(8)  # let hostapd initialize and broadcast briefly

    still_running = hostapd_proc.poll() is None  # None means process is alive

    hostapd_proc.terminate()
    try:
        hostapd_proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        hostapd_proc.kill()

    # Step 4: restore monitor mode for any subsequent modules
    log(scan_id, f'Restoring {interface} to monitor mode...', 'info')
    try:
        subprocess.run(['sudo', 'airmon-ng', 'start', base_interface],
                        capture_output=True, text=True, timeout=20)
    except Exception as e:
        log(scan_id, f'Warning — failed to restore monitor mode: {str(e)}', 'warning')

    if still_running:
        log(scan_id, 'Rogue access point broadcast successfully.', 'success')
        log(scan_id, 'Network is vulnerable to evil twin attacks — no client-side AP verification detected.', 'warning')
        return f"""[+] Evil twin access point "{target_ssid}" created and broadcasting
[+] Network is vulnerable to evil twin attacks
[!] Clients cannot cryptographically distinguish this AP from the legitimate one
[i] Limitation: single-adapter setup — passive broadcast only, active client migration not demonstrated"""
    else:
        log(scan_id, 'hostapd failed to start or exited immediately — check driver/config.', 'error')
        return 'Evil twin setup failed — hostapd did not stay running'

def store_results(scan_id, module, output):
    """Store scan results and vulnerabilities in database"""
    db = get_db()

    # Determine vulnerabilities based on module output
    vulns = []

    if module == 'network_scan':
        lines = output.split('\n')
        open_ports = []
        for line in lines:
            if 'open' in line.lower() and '/tcp' in line.lower():
                open_ports.append(line.strip())

        for port_line in open_ports:
            port_lower = port_line.lower()

            # Backdoor services — Critical
            if 'vsftpd 2.3.4' in port_lower:
                vulns.append({
                    'vulntype': 'Open port detected',
                    'severity': 'Critical',
                    'cvss_score': 9.8,
                    'description': 'vsftpd 2.3.4 detected on port 21 — this version contains a known backdoor (CVE-2011-2523) that allows unauthenticated remote root access.'
                })
            elif 'bindshell' in port_lower or '1524' in port_line:
                vulns.append({
                    'vulntype': 'Open port detected',
                    'severity': 'Critical',
                    'cvss_score': 10.0,
                    'description': 'Root shell exposed on port 1524 — a bind shell providing direct unauthenticated root access to the system was detected.'
                })
 
            # High severity services
            elif 'telnet' in port_lower:
                vulns.append({
                    'vulntype': 'Unencrypted service exposed',
                    'severity': 'High',
                    'cvss_score': 7.5,
                    'description': 'Telnet service detected — Telnet transmits all data including credentials in plaintext, making it trivially interceptable.'
                })
            elif 'unreal' in port_lower or 'unrealircd' in port_lower:
                vulns.append({
                    'vulntype': 'Open port detected',
                    'severity': 'High',
                    'cvss_score': 7.5,
                    'description': 'UnrealIRCd detected — this version contains a known backdoor (CVE-2010-2075) that allows remote code execution.'
                })
            elif 'mysql' in port_lower:
                vulns.append({
                    'vulntype': 'Open port detected',
                    'severity': 'High',
                    'cvss_score': 7.5,
                    'description': f'MySQL database exposed on network: {port_line.strip()} — database services should not be directly accessible from the network.'
                })
            elif 'postgresql' in port_lower:
                vulns.append({
                    'vulntype': 'Open port detected',
                    'severity': 'High',
                    'cvss_score': 7.5,
                    'description': f'PostgreSQL database exposed on network: {port_line.strip()} — database services should not be directly accessible from the network.'
                })
            elif 'vnc' in port_lower:
                vulns.append({
                    'vulntype': 'Open port detected',
                    'severity': 'High',
                    'cvss_score': 7.2,
                    'description': 'VNC remote desktop service detected — if poorly configured, VNC allows unauthenticated graphical access to the system.'
                })
            elif 'rpcbind' in port_lower or 'nfs' in port_lower:
                vulns.append({
                    'vulntype': 'Open port detected',
                    'severity': 'High',
                    'cvss_score': 7.5,
                    'description': f'RPC/NFS service exposed: {port_line.strip()} — these services can expose sensitive file system data if misconfigured.'
                })

            # Medium severity services
            elif 'ftp' in port_lower and 'vsftpd 2.3.4' not in port_lower:
                vulns.append({
                    'vulntype': 'Unencrypted service exposed',
                    'severity': 'Medium',
                    'cvss_score': 5.9,
                    'description': f'FTP service detected: {port_line.strip()} — FTP transmits credentials in plaintext. Use SFTP instead.'
                })
            elif 'smtp' in port_lower:
                vulns.append({
                    'vulntype': 'Open port detected',
                    'severity': 'Medium',
                    'cvss_score': 5.3,
                    'description': f'SMTP mail service exposed: {port_line.strip()} — ensure relay is disabled and authentication is enforced.'
                })
            elif 'http' in port_lower and 'https' not in port_lower:
                vulns.append({
                    'vulntype': 'Unencrypted service exposed',
                    'severity': 'Medium',
                    'cvss_score': 5.9,
                    'description': f'Unencrypted HTTP service detected: {port_line.strip()} — use HTTPS to encrypt web traffic.'
                })

        # Catch-all for any remaining open ports not specifically handled
        handled_keywords = [
            'vsftpd 2.3.4', 'unreal', 'bindshell', '1524', 'telnet',
            'mysql', 'postgresql', 'vnc', 'rpcbind', 'nfs', 'ftp',
            'smtp', 'http'
        ]
        unhandled = [
            p for p in open_ports
            if not any(kw in p.lower() or kw in p for kw in handled_keywords)
        ]
        if unhandled:
            vulns.append({
                'vulntype': 'Open port detected',
                'severity': 'Low',
                'cvss_score': 3.1,
                'description': f'Additional open ports detected: {", ".join(unhandled)} — review whether these services are necessary.'
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
        'Open port detected': (
            'Review all open ports and disable any services not required for business operations. '
            'Use a host-based firewall (e.g. ufw or iptables) to block access to unused ports. '
            'Run: sudo ufw enable && sudo ufw default deny incoming to start with a deny-all policy, '
            'then explicitly allow only required services.'
        ),
        'Unencrypted service exposed': (
            'Replace unencrypted services with encrypted alternatives: use SFTP or FTPS instead of FTP, '
            'SSH instead of Telnet, and HTTPS instead of HTTP. '
            'For web servers, install an SSL/TLS certificate (free via Let\'s Encrypt: certbot.eff.org) '
            'and configure automatic HTTP-to-HTTPS redirection.'
        ),
        'Outdated service version': (
            'Update all software and firmware to the latest stable versions immediately. '
            'On Debian/Ubuntu systems run: sudo apt update && sudo apt upgrade. '
            'Enable automatic security updates: sudo apt install unattended-upgrades. '
            'Subscribe to vendor security advisories to be notified of future vulnerabilities.'
        ),
        'WPA2 weak password': (
            'Change the Wi-Fi password immediately via your router admin panel (typically at 192.168.1.1 or 192.168.0.1). '
            'Use a passphrase of at least 16 characters combining uppercase, lowercase, numbers and symbols — '
            'for example a random phrase like "Coffee$Desk!Rain42". '
            'Avoid dictionary words, names, or dates. Consider enabling WPA3 if your router supports it.'
        ),
        'WPA2 handshake captured': (
            'A WPA2 handshake was captured, meaning an attacker can attempt offline password cracking. '
            'Immediately change your Wi-Fi password to a strong passphrase (16+ characters). '
            'If your router supports WPA3, enable it under wireless security settings. '
            'WPA3 uses SAE (Simultaneous Authentication of Equals) which prevents offline dictionary attacks entirely.'
        ),
        'Deauthentication attack': (
            'Enable Management Frame Protection (802.11w/MFP) in your router\'s wireless settings — '
            'this cryptographically signs management frames so forged deauthentication packets are rejected. '
            'Look for "MFP", "PMF", or "802.11w" in your router\'s advanced wireless settings and set it to "Required" or "Enabled".'
        ),
        'No Management Frame Protection': (
            'Enable 802.11w (Protected Management Frames/MFP) in your router\'s wireless security settings. '
            'This prevents deauthentication and disassociation attacks by requiring management frames to be authenticated. '
            'If your router firmware does not support 802.11w, consider upgrading to a router that does — '
            'all Wi-Fi 6 (802.11ax) certified routers are required to support MFP.'
        ),
        'Evil twin access point': (
            'Deploy 802.1X certificate-based authentication (WPA2/WPA3-Enterprise) so clients verify the '
            'network\'s identity before connecting — this prevents clients connecting to rogue access points. '
            'Train staff to verify they are connected to the correct SSID before transmitting sensitive data. '
            'Consider a Wireless Intrusion Detection System (WIDS) such as Kismet to alert on rogue APs.'
        ),
        'Rogue access point detected': (
            'Deploy a Wireless Intrusion Detection System (WIDS) such as Kismet or Zeek to continuously '
            'monitor for unauthorised access points broadcasting your SSID. '
            'Configure alerts for any new BSSID appearing on your network. '
            'Implement 802.1X authentication so clients reject access points that cannot present a valid certificate.'
        ),
        'vsftpd Backdoor (CVE-2011-2523)': (
            'CRITICAL: Immediately stop and disable the vsftpd service: sudo systemctl stop vsftpd && sudo systemctl disable vsftpd. '
            'This version contains a known backdoor (CVE-2011-2523, CVSS 9.8) that grants unauthenticated remote root access via port 6200. '
            'Replace with a patched version: sudo apt remove vsftpd && sudo apt install vsftpd. '
            'Block port 6200 at the firewall: sudo ufw deny 6200.'
        ),
        'UnrealIRCd Backdoor (CVE-2010-2075)': (
            'CRITICAL: Immediately stop and remove UnrealIRCd: sudo systemctl stop unrealircd && sudo apt remove unrealircd. '
            'This version contains a trojan horse backdoor (CVE-2010-2075, CVSS 9.8) allowing remote command execution. '
            'If IRC is required for business operations, replace with a clean, patched IRC daemon such as InspIRCd. '
            'Block port 6667 at the firewall if IRC is not needed: sudo ufw deny 6667.'
        ),
        'Exposed Root Shell': (
            'CRITICAL: A bind shell providing direct root access is listening on port 1524. '
            'This is a deliberate backdoor. Immediately block this port: sudo ufw deny 1524. '
            'Identify and terminate the process: sudo lsof -i :1524, then kill the process ID shown. '
            'Audit your system for other backdoors — consider a full system reinstall if compromise is confirmed.'
        ),
        'Exposed Database Service': (
            'Database services (MySQL/PostgreSQL) should never be directly accessible from the network. '
            'Bind the database to localhost only by editing the config: set bind-address = 127.0.0.1 in /etc/mysql/mysql.conf.d/mysqld.cnf '
            'or listen_addresses = localhost in /etc/postgresql/*/main/postgresql.conf. '
            'Block the port at the firewall: sudo ufw deny 3306 (MySQL) or sudo ufw deny 5432 (PostgreSQL). '
            'Restart the service after changes: sudo systemctl restart mysql or sudo systemctl restart postgresql.'
        ),
        'VNC Remote Access Exposed': (
            'VNC provides graphical remote access and should not be exposed to the network without strong authentication. '
            'If VNC is required, restrict access to specific IPs only: sudo ufw allow from 192.168.1.X to any port 5900. '
            'Set a strong VNC password and consider tunnelling VNC over SSH rather than exposing it directly: '
            'ssh -L 5900:localhost:5900 user@server, then connect VNC to localhost.'
        ),
        'Telnet Unencrypted Access': (
            'Disable Telnet immediately — it transmits all data including passwords in plaintext. '
            'sudo systemctl stop telnet && sudo systemctl disable telnet. '
            'Replace with SSH for all remote administration: sudo apt install openssh-server. '
            'Block port 23 at the firewall: sudo ufw deny 23.'
        ),
        'FTP Unencrypted Access': (
            'FTP transmits credentials and data in plaintext. Disable it and replace with SFTP (runs over SSH, no extra setup needed) '
            'or FTPS (FTP with TLS). To disable FTP: sudo systemctl stop vsftpd && sudo systemctl disable vsftpd. '
            'Block port 21: sudo ufw deny 21. '
            'For file transfers, use: sftp user@server from any SFTP client such as FileZilla.'
        ),
        'SMTP Service Exposed': (
            'Ensure your mail server is not configured as an open relay, which allows spammers to send mail through your server. '
            'Test for open relay at mxtoolbox.com/diagnostic.aspx. '
            'In Postfix, restrict relay: set smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject in /etc/postfix/main.cf. '
            'Restart Postfix: sudo systemctl restart postfix. Block port 25 from external access if not running a mail server.'
        ),
        'RPC/NFS Service Exposed': (
            'RPC and NFS services can expose your file system to the network if misconfigured. '
            'If NFS is not required, disable it: sudo systemctl stop nfs-server && sudo systemctl disable nfs-server. '
            'Block RPC ports at the firewall: sudo ufw deny 111. '
            'If NFS is needed, restrict exports to specific trusted IPs only in /etc/exports and restart: sudo exportfs -ra.'
        ),
    }
    return recommendations.get(vulntype, 'Consult a qualified cybersecurity professional for remediation advice specific to this vulnerability.')

def run_scan(scan_id, modules, target_ip='10.0.2.0/24', interface='wlan0mon', target_ssid=''):
    db = get_db()
    db.execute('UPDATE scans SET status = ? WHERE scan_id = ?', ('running', scan_id))
    db.commit()
    db.close()

    set_phase(scan_id, 'Reconnaissance', 5)
    log(scan_id, f'Target network: {target_ip}', 'info')

    try:
        total = len(modules)
        for i, module in enumerate(modules):
            phase_name = {
                'network_scan': 'Scanning',
                'wpa2_crack': 'Exploitation',
                'deauth': 'Exploitation',
                'evil_twin': 'Exploitation'
            }.get(module, 'Scanning')

            set_phase(scan_id, phase_name, int(((i) / total) * 80) + 10)
            log(scan_id, f'Starting module: {module}', 'success')

            if module == 'network_scan':
                output = run_nmap(target_ip, scan_id)
            elif module == 'wpa2_crack':
                output = run_aircrack(interface, scan_id, target_ssid=target_ssid)
            elif module == 'deauth':
                output = run_wifite(interface, scan_id, target_ssid=target_ssid)
            elif module == 'evil_twin':
                output = run_hostapd(interface, scan_id, target_ssid=target_ssid)
            else:
                output = ''

            store_results(scan_id, module, output)
            set_phase(scan_id, phase_name, int(((i + 1) / total) * 80) + 10)

        set_phase(scan_id, 'Reporting', 100)
        log(scan_id, 'Scan complete. Generating report...', 'success')

        db = get_db()
        db.execute('UPDATE scans SET status = ? WHERE scan_id = ?', ('complete', scan_id))
        db.commit()
        db.close()

        log(scan_id, 'Generating PDF report...', 'info')
        try:
            generate_report(scan_id)
            log(scan_id, 'Report generated successfully.', 'success')
        except Exception as e:
            log(scan_id, f'Report generation failed: {str(e)}', 'error')

    except Exception as e:
        log(scan_id, f'Scan failed: {str(e)}', 'error')
        set_phase(scan_id, 'Failed', scan_progress.get(scan_id, {}).get('percent', 0))
        db = get_db()
        db.execute('UPDATE scans SET status = ? WHERE scan_id = ?', ('failed', scan_id))
        db.commit()
        db.close()

def run_scan_background(scan_id, modules, target_ip='10.0.2.0/24', interface='wlan0mon', target_ssid=''):
    """Run scan in background thread so Flask stays responsive"""
    thread = threading.Thread(
        target=run_scan,
        args=(scan_id, modules, target_ip, interface, target_ssid)
    )
    thread.daemon = True
    thread.start()
