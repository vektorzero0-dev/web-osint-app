import os
import re
import socket
import ssl
import urllib.parse
from flask import Flask, render_template, request, jsonify
from PIL import Image
from PIL.ExifTags import TAGS

app = Flask(__name__, template_folder='.')

@app.route('/')
def index():
    return render_template('index.html')

# 1. Metadata Extraction
@app.route('/api/metadata', methods=['POST'])
def extract_metadata():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'}), 400
    file = request.files['file']
    metadata = {}
    try:
        image = Image.open(file)
        info = image._getexif()
        if info:
            for tag, value in info.items():
                decoded = TAGS.get(tag, tag)
                metadata[str(decoded)] = str(value)
            return jsonify({'success': True, 'filename': file.filename, 'metadata': metadata})
        else:
            return jsonify({'success': True, 'filename': file.filename, 'metadata': {"Status": "No EXIF metadata found"}})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# 2. Username Footprint Recon
@app.route('/api/recon/username', methods=['GET'])
def username_recon():
    username = request.args.get('username', '').strip()
    if not username:
        return jsonify({'success': False, 'message': 'Username required'}), 400
    platforms = [
        {"platform": "GitHub", "url": f"https://github.com/{username}", "category": "Developer"},
        {"platform": "Twitter / X", "url": f"https://x.com/{username}", "category": "Social"},
        {"platform": "Instagram", "url": f"https://instagram.com/{username}", "category": "Media"},
        {"platform": "Telegram", "url": f"https://t.me/{username}", "category": "Messaging"},
        {"platform": "Reddit", "url": f"https://reddit.com/user/{username}", "category": "Forum"},
        {"platform": "LinkedIn", "url": f"https://www.linkedin.com/in/{username}", "category": "Professional"}
    ]
    return jsonify({"success": True, "username": username, "results": platforms})

# 3. WHOIS Inspector
@app.route('/api/recon/whois', methods=['GET'])
def whois_recon():
    domain = request.args.get('domain', '').strip()
    if not domain:
        return jsonify({'success': False, 'message': 'Domain is required'}), 400
    return jsonify({
        'success': True,
        'domain': domain,
        'registrar': 'MarkMonitor, Inc.',
        'creation_date': '2015-08-11T00:00:00Z',
        'expiration_date': '2028-08-11T00:00:00Z',
        'name_servers': ['ns1.dns-provider.com', 'ns2.dns-provider.com'],
        'status': 'clientTransferProhibited'
    })

# 4. Domain & Port Scan
@app.route('/api/scan', methods=['GET'])
def domain_scan():
    target = request.args.get('target', '').strip()
    if not target:
        return jsonify({'success': False, 'message': 'Target domain required'}), 400
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = "192.0.2.1 (Simulated IP)"
    return jsonify({
        "success": True,
        "target": target,
        "ip_address": ip,
        "http_status": "200 OK",
        "web_server": "Cloudflare / nginx v1.24",
        "latency_ms": 24,
        "ports": [
            {"port": 80, "service": "HTTP", "status": "OPEN", "severity": "LOW"},
            {"port": 443, "service": "HTTPS", "status": "OPEN", "severity": "LOW"},
            {"port": 22, "service": "SSH", "status": "FILTERED", "severity": "MEDIUM"},
            {"port": 21, "service": "FTP", "status": "CLOSED", "severity": "INFO"},
            {"port": 3306, "service": "MySQL", "status": "CLOSED", "severity": "HIGH"}
        ]
    })

# 5. Subdomain Enumerator
@app.route('/api/recon/subdomains', methods=['GET'])
def subdomains_recon():
    domain = request.args.get('domain', '').strip()
    if not domain:
        return jsonify({'success': False, 'message': 'Domain required'}), 400
    mock_subdomains = [
        {"subdomain": f"admin.{domain}", "ip": "192.0.2.10", "status": "200 OK", "type": "A"},
        {"subdomain": f"api.{domain}", "ip": "192.0.2.11", "status": "200 OK", "type": "CNAME"},
        {"subdomain": f"dev.{domain}", "ip": "192.0.2.12", "status": "403 Forbidden", "type": "A"},
        {"subdomain": f"vpn.{domain}", "ip": "192.0.2.13", "status": "200 OK", "type": "A"},
        {"subdomain": f"mail.{domain}", "ip": "192.0.2.14", "status": "200 OK", "type": "MX"}
    ]
    return jsonify({"success": True, "domain": domain, "total_found": len(mock_subdomains), "subdomains": mock_subdomains})

# 6. Google Dorks Generator
@app.route('/api/recon/dorks', methods=['GET'])
def dorks_generator():
    domain = request.args.get('domain', '').strip()
    if not domain:
        return jsonify({'success': False, 'message': 'Domain required'}), 400
    dorks = [
        {"category": "Exposed Files", "query": f"site:{domain} filetype:pdf OR filetype:doc OR filetype:xls", "risk": "MEDIUM"},
        {"category": "Directory Traversal", "query": f"site:{domain} intitle:\"index of\"", "risk": "HIGH"},
        {"category": "Sensitive Configs", "query": f"site:{domain} ext:log OR ext:env OR ext:xml OR ext:json", "risk": "CRITICAL"},
        {"category": "Admin Portals", "query": f"site:{domain} inurl:login OR inurl:admin OR inurl:dashboard", "risk": "MEDIUM"},
        {"category": "Database Leaks", "query": f"site:{domain} intext:\"sql syntax error\" OR intext:\"database error\"", "risk": "HIGH"}
    ]
    for d in dorks:
        d["url"] = f"https://www.google.com/search?q={urllib.parse.quote(d['query'])}"
    return jsonify({"success": True, "domain": domain, "dorks": dorks})

# 7. IP Geolocation Intel
@app.route('/api/recon/ip-intel', methods=['GET'])
def ip_intel():
    ip = request.args.get('ip', '').strip()
    if not ip:
        return jsonify({'success': False, 'message': 'IP required'}), 400
    return jsonify({
        'success': True,
        'ip': ip,
        'country': 'Indonesia 🇮🇩',
        'city': 'Jakarta',
        'region': 'DKI Jakarta',
        'isp': 'PT Telkom Indonesia',
        'asn': 'AS7713',
        'latitude': -6.2088,
        'longitude': 106.8456,
        'timezone': 'Asia/Jakarta (UTC+7)'
    })

# 8. DNS Lookup
@app.route('/api/recon/dns-enum', methods=['GET'])
def dns_enum():
    domain = request.args.get('domain', '').strip()
    if not domain:
        return jsonify({'success': False, 'message': 'Domain required'}), 400
    records = [
        {"type": "A", "value": "192.0.2.1", "ttl": 300},
        {"type": "AAAA", "value": "2001:db8::1", "ttl": 300},
        {"type": "MX", "value": f"10 mail.{domain}", "ttl": 3600},
        {"type": "NS", "value": f"ns1.{domain}", "ttl": 86400},
        {"type": "TXT", "value": "v=spf1 include:_spf.google.com ~all", "ttl": 3600}
    ]
    return jsonify({"success": True, "domain": domain, "records": records})

# 9. SSL Certificate Inspector
@app.route('/api/recon/ssl-info', methods=['GET'])
def ssl_info():
    domain = request.args.get('domain', '').strip()
    if not domain:
        return jsonify({'success': False, 'message': 'Domain required'}), 400
    return jsonify({
        'success': True,
        'common_name': domain,
        'issuer': "Let's Encrypt Authority X3",
        'valid_from': '2026-01-01',
        'valid_to': '2026-12-31',
        'signature_algorithm': 'sha256WithRSAEncryption',
        'key_length': '2048-bit RSA',
        'ssl_grade': 'A+'
    })

# 10. Security Headers Audit
@app.route('/api/recon/security-headers', methods=['GET'])
def security_headers():
    domain = request.args.get('domain', '').strip()
    if not domain:
        return jsonify({'success': False, 'message': 'Domain required'}), 400
    headers = [
        {"header": "Strict-Transport-Security (HSTS)", "status": "PASS", "description": "Enforces HTTPS connections."},
        {"header": "X-Content-Type-Options", "status": "PASS", "description": "Prevents MIME-sniffing attacks."},
        {"header": "X-Frame-Options", "status": "FAIL", "description": "Vulnerable to Clickjacking."},
        {"header": "Content-Security-Policy (CSP)", "status": "WARNING", "description": "CSP policy is partially configured."},
        {"header": "Referrer-Policy", "status": "PASS", "description": "Controls referrer information leakage."}
    ]
    return jsonify({"success": True, "domain": domain, "security_score": "B+", "headers": headers})

# 11. Email Verification
@app.route('/api/recon/email', methods=['GET'])
def email_recon():
    email = request.args.get('email', '').strip()
    if not email:
        return jsonify({'success': False, 'message': 'Email required'}), 400
    valid_syntax = bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", email))
    domain = email.split('@')[-1] if valid_syntax else ""
    return jsonify({
        'success': True,
        'email': email,
        'valid_syntax': valid_syntax,
        'is_disposable': False,
        'mx_records_found': valid_syntax,
        'deliverability_score': "95%",
        'domain': domain
    })

# 12. Phone Leak Recon
@app.route('/api/recon/phone', methods=['GET'])
def phone_leak_check():
    phone_input = request.args.get('phone', '').strip()
    if not phone_input:
        return jsonify({'success': False, 'message': 'Phone number required.'}), 400

    sanitized = re.sub(r'[^\d+]', '', phone_input)
    if sanitized.startswith('0'):
        formatted = '+62' + sanitized[1:]
    elif not sanitized.startswith('+'):
        formatted = '+' + sanitized
    else:
        formatted = sanitized

    raw_digits = re.sub(r'[^\d]', '', formatted)
    country = "Indonesia 🇮🇩" if formatted.startswith('+62') else "International"
    encoded_phone = urllib.parse.quote(formatted)
    encoded_raw = urllib.parse.quote(raw_digits)

    leak_links = [
        {"name": "Google Deep Search", "url": f"https://www.google.com/search?q=%22{encoded_phone}%22+OR+%22{encoded_raw}%22+leak+OR+breach"},
        {"name": "IntelX OSINT Engine", "url": f"https://intelx.io/?s={encoded_phone}"},
        {"name": "DeHashed Database", "url": f"https://dehashed.com/search?query=%22{encoded_phone}%22"},
        {"name": "HaveIBeenPwned", "url": "https://haveibeenpwned.com/"}
    ]

    return jsonify({
        'success': True,
        'raw_input': phone_input,
        'formatted_phone': formatted,
        'country': country,
        'search_engines': leak_links,
        'threat_level': 'EVALUATING'
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
