from fastapi import FastAPI, HTTPException, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import requests
import socket
import whois
import dns.resolver
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import sqlite3
from PIL import Image
from PIL.ExifTags import TAGS
import os

# --- 1. INISIALISASI APP ---
app = FastAPI(title="Enterprise OSINT Intelligence Suite", version="3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 2. DATABASE INITIALIZATION ---
def init_db():
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

init_db()

# --- 3. UTILITIES ---
def check_single_port(ip: str, port: int):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        result = s.connect_ex((ip, port))
        s.close()
        return port, "Terbuka" if result == 0 else "Tertutup"
    except:
        return port, "Tertutup"

# --- 4. ENDPOINTS / ROUTES ---

# Halaman Utama: Memuat Tampilan Dashboard (index.html)
@app.get("/", response_class=HTMLResponse)
def read_root():
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return """
    <html>
        <head><title>Enterprise OSINT Engine</title></head>
        <body style="background: #0f172a; color: #38bdf8; font-family: monospace; text-align: center; padding-top: 50px;">
            <h1>⚠️ File index.html tidak ditemukan!</h1>
            <p>Pastikan file index.html berada di folder yang sama dengan main.py</p>
            <p>Atau akses dokumentasi API di <a href="/docs" style="color: #f43f5e;">/docs</a></p>
        </body>
    </html>
    """

# Endpoint Informasi Developer
@app.get("/api/developer")
def get_developer_info():
    return {
        "developer": "ZEEO",
        "signature": "VEKTOR ZERO",
        "email": "mishbachachmad07@gmail.com",
        "whatsapp": "082371729760",
        "links": {
            "email_url": "mailto:mishbachachmad07@gmail.com",
            "wa_url": "https://wa.me/6282371729760"
        }
    }

# Endpoint Metadata File
@app.post("/api/metadata")
async def extract_metadata(file: UploadFile = File(...)):
    temp_file_path = f"temp_{file.filename}"
    with open(temp_file_path, "wb") as buffer:
        buffer.write(await file.read())
    
    metadata_results = {}
    try:
        image = Image.open(temp_file_path)
        exifdata = image.getexif()
        if exifdata:
            for tag_id in exifdata:
                tag = TAGS.get(tag_id, tag_id)
                data = exifdata.get(tag_id)
                if isinstance(data, bytes):
                    data = data.decode(errors="ignore")
                metadata_results[str(tag)] = str(data)
        else:
            metadata_results["Info"] = "Tidak ditemukan data EXIF/Metadata pada gambar ini."
        
        metadata_results["Format File"] = image.format
        metadata_results["Ukuran Gambar"] = f"{image.width}x{image.height} pixels"
        metadata_results["Mode Warna"] = image.mode
    except Exception as e:
        metadata_results["Error"] = f"Gagal membaca metadata file: {str(e)}"
    
    if os.path.exists(temp_file_path):
        os.remove(temp_file_path)
        
    return {"success": True, "filename": file.filename, "metadata": metadata_results}

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
    except:
        try:
            response = requests.get(f"http://{target}", timeout=4)
            http_status = f"Online HTTP ({response.status_code} OK)"
            server_info = response.headers.get("Server", "Tidak diketahui")
        except:
            http_status = "Offline / Ports Blocked"

    try:
        w = whois.whois(target)
        registrar = str(w.registrar) if w.registrar else "Tidak diketahui"
        creation_date = str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date)
    except:
        registrar = "Data Whois diproteksi / Privat"
        creation_date = "Tidak tersedia"

    try:
        answers = dns.resolver.resolve(target, 'A')
        for rdata in answers:
            dns_records.append(str(rdata))
    except:
        pass

    ports_to_check = [21, 22, 53, 80, 443, 3306, 8080]
    port_results = {}
    if ip_address != "Gagal meresolusi DNS" and ip_address != "Tidak ditemukan":
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
    except:
        pass

    result_data = {
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

    return {"success": True, "data": result_data}

# Endpoint Riwayat Scan
@app.get("/api/history")
def get_history():
    conn = sqlite3.connect("osint_history.db")
    cursor = conn.cursor()
    cursor.execute("SELECT target, ip_address, status, checked_at FROM scan_logs ORDER BY id DESC LIMIT 10")
    rows = cursor.fetchall()
    conn.close()
    
    history = []
    for row in rows:
        history.append({
            "target": row[0],
            "ip_address": row[1],
            "status": row[2],
            "checked_at": row[3]
        })
    return {"success": True, "history": history}