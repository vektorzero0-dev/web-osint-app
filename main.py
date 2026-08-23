from fastapi import FastAPI, HTTPException, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import requests
import socket
import dns.resolver
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import os
import hashlib
import re
import ssl

try:
    import whois
except ImportError:
    whois = None

try:
    import pypdf
except ImportError:
    pypdf = None

app = FastAPI(title="ZEEO OSINT APP", version="10.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def convert_to_degrees(value):
    try:
        d, m, s = float(value[0]), float(value[1]), float(value[2])
        return d + (m / 60.0) + (s / 3600.0)
    except Exception:
        return 0.0

def calculate_hashes(file_bytes: bytes):
    return {
        "md5": hashlib.md5(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest()
    }

def check_username_platform(platform: str, url_template: str, username: str):
    url = url_template.format(username)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    try:
        res = requests.get(url, headers=headers, timeout=3)
        if res.status_code == 200:
            return platform, "FOUND", url
        elif res.status_code == 404:
            return platform, "NOT FOUND", url
        else:
            return platform, f"HTTP {res.status_code}", url
    except Exception:
        return platform, "TIMEOUT", url

@app.get("/", response_class=HTMLResponse)
def read_root():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    html_path = os.path.join(base_dir, "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1 style='color:red;'>File index.html tidak ditemukan!</h1>"

@app.post("/api/metadata")
async def extract_metadata(file: UploadFile = File(...)):
    file_bytes = await file.read()
    filename = file.filename
    ext = os.path.splitext(filename)[1].lower()
    hashes = calculate_hashes(file_bytes)
    metadata_results = {}
    lat_deg, lon_deg = None, None

    if ext in [".jpg", ".jpeg", ".png", ".webp", ".tiff"]:
        temp_file = f"temp_{filename}"
        with open(temp_file, "wb") as f: f.write(file_bytes)
        try:
            image = Image.open(temp_file)
            exifdata = image.getexif()
            if exifdata:
                for tag_id in exifdata:
                    tag = TAGS.get(tag_id, tag_id)
                    data = exifdata.get(tag_id)
                    if isinstance(data, bytes): data = data.decode(errors="ignore")
                    if tag != "GPSInfo": metadata_results[str(tag)] = str(data)
                try:
                    gps_info = exifdata.get_ifd(34853)
                    if gps_info:
                        gps_data = {GPSTAGS.get(t, t): gps_info[t] for t in gps_info}
                        lat, lat_ref = gps_data.get("GPSLatitude"), gps_data.get("GPSLatitudeRef")
                        lon, lon_ref = gps_data.get("GPSLongitude"), gps_data.get("GPSLongitudeRef")
                        if lat and lon and lat_ref and lon_ref:
                            lat_deg = convert_to_degrees(lat)
                            if str(lat_ref).upper() != "N": lat_deg = -lat_deg
                            lon_deg = convert_to_degrees(lon)
                            if str(lon_ref).upper() != "E": lon_deg = -lon_deg
                            metadata_results["Latitude"] = f"{lat_deg:.6f} ({lat_ref})"
                            metadata_results["Longitude"] = f"{lon_deg:.6f} ({lon_ref})"
                except Exception: pass
            metadata_results["Resolution"] = f"{image.width} x {image.height} px"
            metadata_results["Color Mode"] = image.mode
            image.close()
        except Exception as e: metadata_results["Error"] = str(e)
        if os.path.exists(temp_file): os.remove(temp_file)

    elif ext == ".pdf":
        temp_pdf = f"temp_{filename}"
        with open(temp_pdf, "wb") as f: f.write(file_bytes)
        try:
            if pypdf:
                reader = pypdf.PdfReader(temp_pdf)
                if reader.metadata:
                    for k, v in reader.metadata.items(): metadata_results[str(k).replace("/", "")] = str(v)
                metadata_results["Total Pages"] = str(len(reader.pages))
        except Exception as e: metadata_results["Error"] = str(e)
        if os.path.exists(temp_pdf): os.remove(temp_pdf)

    osint_links = {}
    if lat_deg is not None and lon_deg is not None:
        osint_links = {
            "Google Maps": f"https://www.google.com/maps?q={lat_deg},{lon_deg}",
            "SunCalc OSINT": f"https://www.suncalc.org/#/{lat_deg},{lon_deg},17/null/null/null/null",
            "OpenTopoMap": f"https://opentopomap.org/#map=15/{lat_deg}/{lon_deg}"
        }

    return {
        "success": True,
        "filename": filename,
        "file_size": f"{len(file_bytes) / 1024:.2f} KB",
        "hashes": hashes,
        "osint_links": osint_links,
        "metadata": metadata_results
    }

@app.get("/api/recon/username")
def recon_username(username: str):
    username = username.strip().replace("@", "")
    if not username: raise HTTPException(status_code=400, detail="Username kosong")
    platforms = {
        "GitHub": "https://github.com/{}",
        "Telegram": "https://t.me/{}",
        "Reddit": "https://www.reddit.com/user/{}",
        "Pinterest": "https://www.pinterest.com/{}",
        "TikTok": "https://www.tiktok.com/@{}",
        "Twitter / X": "https://x.com/{}",
        "Instagram": "https://instagram.com/{}",
        "Medium": "https://medium.com/@{}",
        "Dev.to": "https://dev.to/{}"
    }
    results = []
    with ThreadPoolExecutor(max_workers=9) as executor:
        futures = [executor.submit(check_username_platform, p, url, username) for p, url in platforms.items()]
        for f in futures:
            p, st, u = f.result()
            results.append({"platform": p, "status": st, "url": u})
    return {"success": True, "username": username, "results": results}

@app.get("/api/recon/whois")
def recon_whois(domain: str):
    domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0]
    if not whois: return {"success": False, "message": "Library whois tidak terinstall"}
    try:
        w = whois.whois(domain)
        creation_date = str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date)
        expiration_date = str(w.expiration_date[0]) if isinstance(w.expiration_date, list) else str(w.expiration_date)
        return {
            "success": True,
            "domain": domain,
            "registrar": str(w.registrar or "Protected"),
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "name_servers": w.name_servers if w.name_servers else ["N/A"]
        }
    except Exception as e:
        return {"success": False, "message": str(e)}

@app.get("/api/recon/ip-intel")
def recon_ip_intel(ip: str):
    try:
        ip = ip.strip()
        res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query", timeout=4)
        data = res.json()
        return {"success": data.get("status") == "success", "ip_intel": data}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/api/recon/dorks")
def generate_dorks(domain: str):
    domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0]
    dorks = [
        {"name": "Exposed Directory Listing", "query": f"site:{domain} intitle:index.of"},
        {"name": "Configuration Files", "query": f"site:{domain} ext:xml OR ext:conf OR ext:cnf OR ext:reg OR ext:inf OR ext:rdp OR ext:cfg OR ext:txt OR ext:ora OR ext:ini"},
        {"name": "Database & Backup Files", "query": f"site:{domain} ext:sql OR ext:dbf OR ext:mdb OR ext:bkp OR ext:bak OR ext:old"},
        {"name": "Publicly Exposed Documents", "query": f"site:{domain} ext:pdf OR ext:doc OR ext:docx OR ext:xls OR ext:xlsx OR ext:ppt"},
        {"name": "Login & Admin Interfaces", "query": f"site:{domain} inurl:login OR inurl:admin OR inurl:portal OR inurl:user"},
        {"name": "PHP Info & Server Logs", "query": f"site:{domain} ext:log OR inurl:phpinfo.php OR ext:php intitle:phpinfo"}
    ]
    for d in dorks:
        d["url"] = f"https://www.google.com/search?q={requests.utils.quote(d['query'])}"
    return {"success": True, "target": domain, "dorks": dorks}

@app.get("/api/recon/email")
def recon_email(email: str):
    email = email.strip()
    regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    is_valid_format = bool(re.match(regex, email))
    if not is_valid_format: return {"success": False, "message": "Format email tidak valid."}
    
    domain = email.split("@")[1]
    disposable_list = ["tempmail.com", "guerrillamail.com", "10minutemail.com", "mailinator.com", "trashmail.com"]
    is_disposable = domain.lower() in disposable_list
    
    mx_records = []
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers: mx_records.append(str(rdata.exchange))
    except Exception: pass

    return {
        "success": True,
        "email": email,
        "domain": domain,
        "valid_syntax": is_valid_format,
        "is_disposable": is_disposable,
        "mx_records": mx_records,
        "has_mail_server": len(mx_records) > 0
    }

@app.get("/api/recon/phone")
def recon_phone(phone: str):
    clean_phone = re.sub(r'[^\d+]', '', phone.strip())
    if not clean_phone or len(clean_phone) < 7:
        return {"success": False, "message": "Nomor telepon tidak valid (minimal 7 digit)."}
    
    country_info = "Unknown"
    if clean_phone.startswith("+62") or clean_phone.startswith("08"):
        country_info = "Indonesia (+62)"
    elif clean_phone.startswith("+1"):
        country_info = "United States / Canada (+1)"
    elif clean_phone.startswith("+44"):
        country_info = "United Kingdom (+44)"
    elif clean_phone.startswith("+61"):
        country_info = "Australia (+61)"
    elif clean_phone.startswith("+65"):
        country_info = "Singapore (+65)"
    elif clean_phone.startswith("+91"):
        country_info = "India (+91)"

    search_query = requests.utils.quote(clean_phone)
    leak_sources = {
        "Google OSINT Search": f"https://www.google.com/search?q=%22{search_query}%22",
        "HaveIBeenPwned Search": f"https://haveibeenpwned.com/search?q={search_query}",
        "DeHashed Lookup": f"https://www.dehashed.com/search?query=%22{search_query}%22",
        "Sync.me Directory": f"https://sync.me/search/?number={search_query}"
    }

    return {
        "success": True,
        "raw_phone": phone,
        "formatted_phone": clean_phone,
        "country_detected": country_info,
        "leak_check_links": leak_sources,
        "leak_status_recommendation": "Gunakan tautan OSINT di atas untuk memeriksa jejak nomor pada dump data breach publik."
    }

@app.get("/api/recon/dns-enum")
def recon_dns_enum(domain: str):
    domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0]
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    dns_data = {}
    for r_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, r_type)
            dns_data[r_type] = [str(rdata) for rdata in answers]
        except Exception:
            dns_data[r_type] = []
    return {"success": True, "domain": domain, "records": dns_data}

@app.get("/api/recon/ssl-info")
def recon_ssl(domain: str):
    domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0]
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))
                san = [item[1] for item in cert.get('subjectAltName', []) if item[0] == 'DNS']
                
                return {
                    "success": True,
                    "domain": domain,
                    "issuer_organization": issuer.get('organizationName', 'N/A'),
                    "common_name": subject.get('commonName', 'N/A'),
                    "valid_from": cert.get('notBefore'),
                    "valid_to": cert.get('notAfter'),
                    "serial_number": cert.get('serialNumber'),
                    "san_domains": san[:8]
                }
    except Exception as e:
        return {"success": False, "message": f"SSL Handshake gagal: {str(e)}"}

def check_subdomain(sub: str, target: str):
    full_domain = f"{sub}.{target}"
    try:
        ip = socket.gethostbyname(full_domain)
        return {"subdomain": full_domain, "ip": ip, "status": "ACTIVE"}
    except Exception:
        return None

@app.get("/api/recon/subdomains")
def recon_subdomains(domain: str):
    domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0]
    wordlist = ["www", "mail", "remote", "blog", "webmail", "server", "ns1", "smtp", "secure", "vpn", "api", "dev", "staging", "admin", "portal", "test", "demo", "m"]
    found = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_subdomain, sub, domain) for sub in wordlist]
        for f in futures:
            res = f.result()
            if res: found.append(res)
            
    return {"success": True, "target": domain, "total_found": len(found), "subdomains": found}

@app.get("/api/recon/security-headers")
def recon_sec_headers(domain: str):
    domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0]
    try:
        res = requests.get(f"https://{domain}", timeout=5)
        headers = res.headers
        sec_checks = {
            "Strict-Transport-Security (HSTS)": "Strict-Transport-Security" in headers,
            "Content-Security-Policy (CSP)": "Content-Security-Policy" in headers,
            "X-Frame-Options (Clickjacking)": "X-Frame-Options" in headers,
            "X-Content-Type-Options": "X-Content-Type-Options" in headers,
            "Referrer-Policy": "Referrer-Policy" in headers,
            "Permissions-Policy": "Permissions-Policy" in headers
        }
        score = sum(1 for v in sec_checks.values() if v)
        return {
            "success": True,
            "target": domain,
            "status_code": res.status_code,
            "security_score": f"{score}/6",
            "audit_results": sec_checks,
            "raw_server": headers.get("Server", "Protected/Hidden")
        }
    except Exception as e:
        return {"success": False, "message": str(e)}

def check_single_port(ip: str, port: int):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        res = s.connect_ex((ip, port))
        s.close()
        return port, "OPEN" if res == 0 else "CLOSED"
    except Exception:
        return port, "CLOSED"

@app.get("/api/scan")
def scan_target(target: str):
    target = target.strip().replace("https://", "").replace("http://", "").split("/")[0]
    if not target: raise HTTPException(status_code=400, detail="Target required")

    try: ip_address = socket.gethostbyname(target)
    except Exception: ip_address = "DNS Resolution Failed"

    try:
        res = requests.get(f"https://{target}", timeout=4)
        http_status, server_info = f"Online ({res.status_code})", res.headers.get("Server", "Cloudflare/Protected")
    except Exception:
        http_status, server_info = "Offline / Blocked", "N/A"

    ports = [21, 22, 80, 443, 3306, 8080, 8443]
    port_results = {}
    if "Failed" not in ip_address:
        with ThreadPoolExecutor(max_workers=7) as executor:
            futures = [executor.submit(check_single_port, ip_address, p) for p in ports]
            for f in futures:
                p, st = f.result()
                port_results[str(p)] = st

    return {
        "success": True,
        "data": {
            "target": target,
            "ip_address": ip_address,
            "status": http_status,
            "web_server": server_info,
            "ports": port_results,
            "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    }
