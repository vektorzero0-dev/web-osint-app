from fastapi import FastAPI, HTTPException, File, UploadFile, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import requests
import socket
import dns.resolver
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import sqlite3
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import os
import hashlib
import re

# Import WHOIS
try:
    import whois
except ImportError:
    whois = None

# Import Library Dokumen Opsional
try:
    import pypdf
except ImportError:
    pypdf = None

try:
    import docx
except ImportError:
    docx = None

app = FastAPI(title="VEKTOR ZERO - OSINT Cyber Engine", version="7.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def init_db():
    try:
        conn = sqlite3.connect("osint_history.db")
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                ip_address TEXT,
                status TEXT,
                checked_at TEXT
            )
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Warning: Gagal db init: {e}")

init_db()

def check_single_port(ip: str, port: int):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        res = s.connect_ex((ip, port))
        s.close()
        return port, "Open" if res == 0 else "Closed"
    except Exception:
        return port, "Closed"

def convert_to_degrees(value):
    try:
        d = float(value[0])
        m = float(value[1])
        s = float(value[2])
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
            return platform, "Found", url
        elif res.status_code == 404:
            return platform, "Not Found", url
        else:
            return platform, f"HTTP {res.status_code}", url
    except Exception:
        return platform, "Timeout", url

@app.get("/", response_class=HTMLResponse)
def read_root():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    html_path = os.path.join(base_dir, "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>File index.html tidak ditemukan!</h1>"

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
            metadata_results["Dimensions"] = f"{image.width} x {image.height} px"
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
    if not username: raise HTTPException(status_code=400, detail="Empty username")
    platforms = {
        "GitHub": "https://github.com/{}",
        "Telegram": "https://t.me/{}",
        "Reddit": "https://www.reddit.com/user/{}",
        "Pinterest": "https://www.pinterest.com/{}",
        "TikTok": "https://www.tiktok.com/@{}"
    }
    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(check_username_platform, p, url, username) for p, url in platforms.items()]
        for f in futures:
            p, st, u = f.result()
            results.append({"platform": p, "status": st, "url": u})
    return {"success": True, "username": username, "results": results}

@app.get("/api/recon/ip-intel")
def recon_ip_intel(ip: str):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip.strip()}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query", timeout=4)
        data = res.json()
        return {"success": data.get("status") == "success", "ip_intel": data}
    except Exception as e:
        return {"success": False, "error": str(e)}

# [FITUR BARU 1] Email OSINT & Domain Reputation Analyzer
@app.get("/api/recon/email")
def recon_email(email: str):
    email = email.strip()
    regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    is_valid_format = bool(re.match(regex, email))
    
    if not is_valid_format:
        return {"success": False, "message": "Format email tidak valid."}
    
    domain = email.split("@")[1]
    disposable_domains = ["tempmail.com", "guerrillamail.com", "10minutemail.com", "mailinator.com", "trashmail.com"]
    is_disposable = domain.lower() in disposable_domains
    
    mx_records = []
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            mx_records.append(str(rdata.exchange))
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

# [FITUR BARU 2] DNS Security & Record Enumeration
@app.get("/api/recon/dns-enum")
def recon_dns_enum(domain: str):
    domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0]
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    dns_data = {}
    
    for r_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, r_type)
            dns_data[r_type] = [str(rdata) for rdata in answers]
        except Exception:
            dns_data[r_type] = []

    return {"success": True, "domain": domain, "records": dns_data}

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

    registrar = "N/A"
    if whois:
        try:
            w = whois.whois(target)
            registrar = str(w.registrar) if w.registrar else "Private"
        except Exception: registrar = "Protected"

    ports = [21, 22, 80, 443, 3306, 8080]
    port_results = {}
    if "Failed" not in ip_address:
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [executor.submit(check_single_port, ip_address, p) for p in ports]
            for f in futures:
                p, st = f.result()
                port_results[str(p)] = st

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {
        "success": True,
        "data": {
            "target": target,
            "ip_address": ip_address,
            "status": http_status,
            "web_server": server_info,
            "registrar": registrar,
            "ports": port_results,
            "checked_at": current_time
        }
    }
