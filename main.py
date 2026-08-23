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
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    metadata = {}
    
    try:
        image = Image.open(file)
        info = image._getexif()
        if info:
            for tag, value in info.items():
                decoded = TAGS.get(tag, tag)
                metadata[str(decoded)] = str(value)
        else:
            metadata = {"Status": "No EXIF metadata found in image"}
    except Exception as e:
        metadata = {"Error": str(e)}

    return jsonify({"filename": file.filename, "metadata": metadata})

# 2. Username Footprint Recon
@app.route('/api/recon/username', methods=['GET'])
def username_recon():
    username = request.args.get('username', '').strip()
    if not username:
        return jsonify({'error': 'Username is required'}), 400

    platforms = [
        {"platform": "GitHub", "url": f"https://github.com/{username}"},
        {"platform": "Twitter / X", "url": f"https://x.com/{username}"},
        {"platform": "Instagram", "url": f"https://instagram.com/{username}"},
        {"platform": "Telegram", "url": f"https://t.me/{username}"},
        {"platform": "Reddit", "url": f"https://reddit.com/user/{username}"}
    ]

    results = []
    for p in platforms:
        results.append({
            "platform": p["platform"],
            "url": p["url"],
            "status": "CHECK_LINK"
        })

    return jsonify({"username": username, "results": results})

# 3. WHOIS Inspector
@app.route('/api/recon/whois', methods=['GET'])
def whois_recon():
    domain = request.args.get('domain', '').strip()
    if not domain:
        return jsonify({'success': False, 'message': 'Domain is required'}), 400

    return jsonify({
        'success': True,
        'domain': domain,
        'registrar': 'Example Registrar Inc.',
        'creation_date': '2020-01-15',
        'expiration_date': '2027-01-15'
    })

# 4. Domain & Port Scan
@app.route('/api/scan', methods=['GET'])
def domain_scan():
    target = request.args.get('target', '').strip()
    if not target:
        return jsonify({'error': 'Target domain required'}), 400

    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = "Unable to resolve IP"

    return jsonify({
        "data": {
            "ip_address": ip,
            "status": "200 OK",
            "web_server": "nginx / cloudflare",
            "ports": {
                "80": "OPEN",
                "443": "OPEN",
                "22": "CLOSED",
                "21": "CLOSED"
            }
        }
    })

# 5. Subdomain Enumerator
@app.route('/api/recon/subdomains', methods=['GET'])
def subdomains_recon():
    domain = request.args.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain required'}), 400

    mock_subdomains = [
        {"subdomain": f"admin.{domain}", "ip": "192.0.2.1"},
        {"subdomain": f"mail.{domain}", "ip": "192.0.2.2"},
        {"subdomain": f"api.{domain}", "ip": "192.0.2.3"},
        {"subdomain": f"dev.{domain}", "ip": "192.0.2.4"}
    ]

    return jsonify({
        "domain": domain,
        "total_found": len(mock_subdomains),
        "subdomains": mock_subdomains
    })

# 6. Google Dorks Generator
@app.route('/api/recon/dorks', methods=['GET'])
def dorks_generator():
    domain = request.args.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain required'}), 400

    dorks = [
        {"name": "Exposed Files", "url": f"https://www.google.com/search?q=site:{domain}+filetype:pdf+OR+filetype:doc+OR+filetype:xls"},
        {"name": "Directory Listing", "url": f"https://www.google.com/search?q=site:{domain}+intitle:%22index+of%22"},
        {"name": "Config & Log Files", "url": f"https://www.google.com/search?q=site:{domain}+ext:log+OR+ext:env+OR+ext:xml"},
        {"name": "Login Pages", "url": f"https://www.google.com/search?q=site:{domain}+inurl:login+OR+inurl:admin"}
    ]

    return jsonify({"domain": domain, "dorks": dorks})

# 7. IP Geolocation Intel
@app.route('/api/recon/ip-intel', methods=['GET'])
def ip_intel():
    ip = request.args.get('ip', '').strip()
    if not ip:
        return jsonify({'success': False, 'message': 'IP required'}), 400

    return jsonify({
        'success': True,
        'ip_intel': {
            'query': ip,
            'country': 'Indonesia',
            'city': 'Jakarta',
            'isp': 'Telkom Indonesia',
            'org': 'PT Telkom',
            'lat': -6.2088,
            'lon': 106.8456
        }
    })

# 8. DNS Lookup
@app.route('/api/recon/dns-enum', methods=['GET'])
def dns_enum():
    domain = request.args.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain required'}), 400

    records = {
        "A": ["192.0.2.1"],
        "MX": [f"10 mail.{domain}"],
        "NS": [f"ns1.{domain}", f"ns2.{domain}"],
        "TXT": ["v=spf1 include:_spf.google.com ~all"]
    }

    return jsonify({"domain": domain, "records": records})

# 9. SSL Certificate Inspector
@app.route('/api/recon/ssl-info', methods=['GET'])
def ssl_info():
    domain = request.args.get('domain', '').strip()
    if not domain:
        return jsonify({'success': False, 'message': 'Domain required'}), 400

    return jsonify({
        'success': True,
        'common_name': domain,
        'issuer_organization': "Let's Encrypt / Cloudflare",
        'valid_to': '2027-12-31'
    })

# 10. Security Headers Audit
@app.route('/api/recon/security-headers', methods=['GET'])
def security_headers():
    domain = request.args.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain required'}), 400

    audit_results = {
        "Strict-Transport-Security": True,
        "X-Content-Type-Options": True,
        "X-Frame-Options": False,
        "Content-Security-Policy": False,
        "X-XSS-Protection": True
    }

    return jsonify({"domain": domain, "security_score": "B", "audit_results": audit_results})

# 11. Email Verification
@app.route('/api/recon/email', methods=['GET'])
def email_recon():
    email = request.args.get('email', '').strip()
    if not email:
        return jsonify({'success': False, 'message': 'Email required'}), 400

    valid_syntax = bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", email))

    return jsonify({
        'success': True,
        'email': email,
        'valid_syntax': valid_syntax,
        'is_disposable': False,
        'mx_records': [f"mx.{email.split('@')[-1]}"] if valid_syntax else []
    })

# 12. Phone Leak Recon (Fitur Cek Kebocoran HP)
@app.route('/api/recon/phone', methods=['GET'])
def phone_leak_check():
    phone_input = request.args.get('phone', '').strip()
    
    if not phone_input:
        return jsonify({
            'success': False, 
            'message': 'Nomor telepon tidak boleh kosong.'
        }), 400

    sanitized_phone = re.sub(r'[^\d+]', '', phone_input)
    
    if sanitized_phone.startswith('0'):
        formatted_phone = '+62' + sanitized_phone[1:]
    elif not sanitized_phone.startswith('+'):
        formatted_phone = '+' + sanitized_phone
    else:
        formatted_phone = sanitized_phone

    raw_digits = re.sub(r'[^\d]', '', formatted_phone)

    country = "Internasional"
    if formatted_phone.startswith('+62'):
        country = "Indonesia 🇮🇩"
    elif formatted_phone.startswith('+1'):
        country = "United States / Canada 🇺🇸🇨🇦"
    elif formatted_phone.startswith('+44'):
        country = "United Kingdom 🇬🇧"

    encoded_phone = urllib.parse.quote(formatted_phone)
    encoded_raw = urllib.parse.quote(raw_digits)

    leak_links = {
        "Google Leak Search": f"https://www.google.com/search?q=%22{encoded_phone}%22+OR+%22{encoded_raw}%22+leak+OR+breach+OR+database",
        "IntelX / Intelligence X": f"https://intelx.io/?s={encoded_phone}",
        "DeHashed Search": f"https://dehashed.com/search?query=%22{encoded_phone}%22",
        "HaveIBeenPwned": "https://haveibeenpwned.com/"
    }

    return jsonify({
        'success': True,
        'raw_phone': phone_input,
        'formatted_phone': formatted_phone,
        'country_detected': country,
        'leak_check_links': leak_links,
        'leak_status_recommendation': 'Periksa tautan investigasi di bawah untuk verifikasi kebocoran di database publik/darkweb.'
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
