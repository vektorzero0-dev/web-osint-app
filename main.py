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

# Import WHOIS dengan penanganan eror ganda (menghindari kegagalan build Render)
try:
    import whois
except ImportError:
    try:
        import pythonwhois as whois
    except ImportError:
        whois = None

# Import Library Dokumen Opsional (Fitur 3)
try:
    import pypdf
except ImportError:
    pypdf = None

try:
    import docx
except ImportError:
    docx = None

try:
    import openpyxl
except ImportError:
    openpyxl = None


# --- 1. INISIALISASI APP ---
app = FastAPI(title="Enterprise OSINT Intelligence Suite", version="5.2")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 2. DATABASE INITIALIZATION ---
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
        print(f"Warning: Gagal inisialisasi database SQLite: {e}")

init_db()

# --- 3. UTILITIES ---
def check_single_port(ip: str, port: int):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        result = s.connect_ex((ip, port))
        s.close()
        return port, "Terbuka" if result == 0 else "Tertutup"
    except Exception:
        return port, "Tertutup"

def convert_to_degrees(value):
    try:
        d = float(value[0])
        m = float(value[1])
        s = float(value[2])
        return d + (m / 60.0) + (s / 3600.0)
    except Exception:
        return 0.0

def calculate_file_hashes(file_bytes: bytes):
    return {
        "md5": hashlib.md5(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest()
    }

# --- 4. ENDPOINTS / ROUTES ---

# Halaman Utama Dashboard (Menggunakan Absolute Path Anti-Crash)
@app.get("/", response_class=HTMLResponse)
def read_root():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    html_path = os.path.join(base_dir, "index.html")
    
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
            
    return """
    <html>
        <head><title>Enterprise OSINT Engine</title></head>
        <body style="background: #0f172a; color: #38bdf8; font-family: monospace; text-align: center; padding-top: 50px;">
            <h1>⚠️ File index.html tidak ditemukan!</h1>
            <p>Pastikan file index.html berada di folder yang sama (root) dengan main.py</p>
        </body>
    </html>
    """

@app.get("/api/developer")
def get_developer_info():
    return {
        "developer": "ZEEO",
        "signature": "VEKTOR ZERO",
        "email": "VektorZero0@gmail.com",
        "whatsapp": "082371729760",
        "links": {
            "email_url": "mailto:mishbachachmad07@gmail.com",
            "wa_url": "https://wa.me/6282371729760"
        }
    }

# Endpoint Metadata File & Ekstraksi GPS Presisi + Hashes
@app.post("/api/metadata")
async def extract_metadata(file: UploadFile = File(...)):
    file_bytes = await file.read()
    filename = file.filename
    ext = os.path.splitext(filename)[1].lower()
    
    hashes = calculate_file_hashes(file_bytes)
    metadata_results = {}
    lat_deg = None
    lon_deg = None

    # A. Gambar
    if ext in [".jpg", ".jpeg", ".png", ".webp", ".tiff"]:
        temp_file_path = f"temp_{filename}"
        with open(temp_file_path, "wb") as buffer:
            buffer.write(file_bytes)

        try:
            image = Image.open(temp_file_path)
            exifdata = image.getexif()
            
            if exifdata:
                for tag_id in exifdata:
                    tag = TAGS.get(tag_id, tag_id)
                    data = exifdata.get(tag_id)
                    if isinstance(data, bytes):
                        data = data.decode(errors="ignore")
                    if tag != "GPSInfo":
                        metadata_results[str(tag)] = str(data)

                try:
                    gps_info = exifdata.get_ifd(34853)
                    if gps_info:
                        gps_data = {GPSTAGS.get(t, t): gps_info[t] for t in gps_info}
                        lat = gps_data.get("GPSLatitude")
                        lat_ref = gps_data.get("GPSLatitudeRef")
                        lon = gps_data.get("GPSLongitude")
                        lon_ref = gps_data.get("GPSLongitudeRef")

                        if lat and lon and lat_ref and lon_ref:
                            lat_deg = convert_to_degrees(lat)
                            if str(lat_ref).upper() != "N":
                                lat_deg = -lat_deg

                            lon_deg = convert_to_degrees(lon)
                            if str(lon_ref).upper() != "E":
                                lon_deg = -lon_deg

                            metadata_results["Latitude"] = f"{lat_deg:.6f} ({lat_ref})"
                            metadata_results["Longitude"] = f"{lon_deg:.6f} ({lon_ref})"
                except Exception:
                    pass
            else:
                metadata_results["Info"] = "Tidak ditemukan data EXIF/Metadata pada gambar ini."
            
            metadata_results["Format File"] = image.format
            metadata_results["Ukuran Gambar"] = f"{image.width}x{image.height} pixels"
            metadata_results["Mode Warna"] = image.mode
            image.close()
        except Exception as e:
            metadata_results["Error"] = f"Gagal membaca metadata gambar: {str(e)}"
        
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

    # B. PDF
    elif ext == ".pdf":
        temp_pdf = f"temp_{filename}"
        with open(temp_pdf, "wb") as f:
            f.write(file_bytes)
        try:
            if pypdf:
                reader = pypdf.PdfReader(temp_pdf)
                doc_info = reader.metadata
                if doc_info:
                    for key, val in doc_info.items():
                        clean_key = str(key).replace("/", "")
                        metadata_results[clean_key] = str(val)
                metadata_results["Jumlah Halaman"] = str(len(reader.pages))
            else:
                metadata_results["Warning"] = "Library 'pypdf' belum terpasang."
        except Exception as e:
            metadata_results["Error"] = f"Gagal membaca metadata PDF: {str(e)}"
        if os.path.exists(temp_pdf):
            os.remove(temp_pdf)

    # C. DOCX
    elif ext == ".docx":
        temp_docx = f"temp_{filename}"
        with open(temp_docx, "wb") as f:
            f.write(file_bytes)
        try:
            if docx:
                doc = docx.Document(temp_docx)
                prop = doc.core_properties
                metadata_results["Author"] = str(prop.author)
                metadata_results["Created"] = str(prop.created)
                metadata_results["Last Modified By"] = str(prop.last_modified_by)
                metadata_results["Modified"] = str(prop.modified)
                metadata_results["Revision"] = str(prop.revision)
                metadata_results["Title"] = str(prop.title)
            else:
                metadata_results["Warning"] = "Library 'python-docx' belum terpasang."
        except Exception as e:
            metadata_results["Error"] = f"Gagal membaca metadata DOCX: {str(e)}"
        if os.path.exists(temp_docx):
            os.remove(temp_docx)

    else:
        metadata_results["Info"] = f"Ekstraksi spesifik untuk {ext} tidak didukung. Menampilkan hash file."

    # Link OSINT GPS
    osint_links = {}
    if lat_deg is not None and lon_deg is not None:
        osint_links = {
            "google_maps": f"https://www.google.com/maps?q={lat_deg},{lon_deg}",
            "suncalc": f"https://www.suncalc.org/#/{lat_deg},{lon_deg},17/null/null/null/null",
            "snapchat_map": f"https://map.snapchat.com/@{lat_deg},{lon_deg},15.00z",
            "opentopomap": f"https://opentopomap.org/#map=15/{lat_deg}/{lon_deg}"
        }

    return {
        "success": True,
        "filename": filename,
        "file_size_bytes": len(file_bytes),
        "hashes": hashes,
        "coordinates": {"latitude": lat_deg, "longitude": lon_deg} if lat_deg else None,
        "osint_links": osint_links,
        "metadata": metadata_results
    }

# Endpoint Header Generator
@app.get("/api/util/header-generator")
def generate_headers(preset: str = Query("desktop_chrome", enum=["desktop_chrome", "mobile_android", "mobile_ios", "googlebot"])):
    user_agents = {
        "desktop_chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "mobile_android": "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.64 Mobile Safari/537.36",
        "mobile_ios": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    }
    
    selected_ua = user_agents.get(preset, user_agents["desktop_chrome"])
    
    headers = {
        "User-Agent": selected_ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive"
    }
    
    return {
        "success": True,
        "preset": preset,
        "headers": headers,
        "curl_example": f"curl -H 'User-Agent: {selected_ua}' TARGET_URL"
    }

# Endpoint Scan Target OSINT
@app.get("/api/scan")
def scan_target(target: str):
    target = target.strip().replace("https://", "").replace("http://", "").split("/")[0]
    
    if not target:
        raise HTTPException(status_code=400, detail="Target tidak boleh kosong.")

    ip_address = "Tidak ditemukan"
    http_status = "Offline / Down"
    server_info = "Tidak diketahui"
    registrar = "Tidak diketahui"
    creation_date = "Tidak diketahui"
    dns_records = []

    try:
        ip_address = socket.gethostbyname(target)
    except socket.gaierror:
        ip_address = "Gagal meresolusi DNS"

    try:
        response = requests.get(f"https://{target}", timeout=4)
        http_status = f"Online ({response.status_code} OK)"
        server_info = response.headers.get("Server", "Cloudflare / Protected")
    except Exception:
        try:
            response = requests.get(f"http://{target}", timeout=4)
            http_status = f"Online HTTP ({response.status_code} OK)"
            server_info = response.headers.get("Server", "Tidak diketahui")
        except Exception:
            http_status = "Offline / Ports Blocked"

    if whois:
        try:
            w = whois.whois(target)
            registrar = str(w.registrar) if w.registrar else "Tidak diketahui"
            creation_date = str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date)
        except Exception:
            registrar = "Data Whois diproteksi / Privat"
            creation_date = "Tidak tersedia"
    else:
        registrar = "Modul WHOIS tidak terinstal"

    try:
        answers = dns.resolver.resolve(target, 'A')
        for rdata in answers:
            dns_records.append(str(rdata))
    except Exception:
        pass

    ports_to_check = [21, 22, 53, 80, 443, 3306, 8080]
    port_results = {}
    if ip_address not in ["Gagal meresolusi DNS", "Tidak ditemukan"]:
        with ThreadPoolExecutor(max_workers=7) as executor:
            futures = [executor.submit(check_single_port, ip_address, p) for p in ports_to_check]
            for future in futures:
                p, status = future.result()
                port_results[str(p)] = status

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn = sqlite3.connect("osint_history.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO scan_logs (target, ip_address, status, checked_at) VALUES (?, ?, ?, ?)",
                       (target, ip_address, http_status, current_time))
        conn.commit()
        conn.close()
    except Exception:
        pass

    return {
        "success": True,
        "data": {
            "target": target,
            "ip_address": ip_address,
            "status": http_status,
            "web_server": server_info,
            "registrar": registrar,
            "creation_date": creation_date,
            "dns_records": dns_records,
            "ports": port_results,
            "checked_at": current_time
        }
    }

@app.get("/api/history")
def get_history():
    try:
        conn = sqlite3.connect("osint_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT target, ip_address, status, checked_at FROM scan_logs ORDER BY id DESC LIMIT 10")
        rows = cursor.fetchall()
        conn.close()
        
        history = [{"target": r[0], "ip_address": r[1], "status": r[2], "checked_at": r[3]} for r in rows]
        return {"success": True, "history": history}
    except Exception:
        return {"success": True, "history": []}
