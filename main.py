from fastapi import FastAPI, File, UploadFile, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import os
import hashlib
import socket
import requests
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from PyPDF2 import PdfReader

app = FastAPI(title="ZEEO OSINT APP")

# 1. Route untuk Menampilkan Halaman Utama (index.html)
@app.get("/", response_class=HTMLResponse)
async def read_index():
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>File index.html tidak ditemukan di direktori utama!</h1>"

# 2. Helper Functions untuk EXIF GPS
def get_geotagging(exif):
    if not exif:
        return None
    geotagging = {}
    for tag_id, value in exif.items():
        tag = TAGS.get(tag_id, tag_id)
        if tag == 'GPSInfo':
            for key in value:
                sub_tag = GPSTAGS.get(key, key)
                geotagging[sub_tag] = value[key]
    return geotagging

def convert_to_degrees(value):
    d = float(value[0])
    m = float(value[1])
    s = float(value[2])
    return d + (m / 60.0) + (s / 3600.0)

# 3. Endpoint Metadata & Exif Analyzer
@app.post("/api/metadata")
async def extract_metadata(file: UploadFile = File(...)):
    contents = await file.read()
    
    # Hash calculation
    md5_hash = hashlib.md5(contents).hexdigest()
    sha256_hash = hashlib.sha256(contents).hexdigest()
    
    metadata = {}
    maps_data = {"has_gps": False}
    
    # Image Metadata & EXIF
    try:
        image = Image.open(file.file)
        metadata["Format"] = image.format
        metadata["Mode"] = image.mode
        metadata["Dimensions"] = f"{image.width}x{image.height} px"
        
        exif_data = image._getexif()
        if exif_data:
            gps_info = get_geotagging(exif_data)
            if gps_info and 'GPSLatitude' in gps_info and 'GPSLongitude' in gps_info:
                lat = convert_to_degrees(gps_info['GPSLatitude'])
                if gps_info.get('GPSLatitudeRef') == 'S':
                    lat = -lat
                
                lon = convert_to_degrees(gps_info['GPSLongitude'])
                if gps_info.get('GPSLongitudeRef') == 'W':
                    lon = -lon
                
                maps_data = {
                    "has_gps": True,
                    "latitude": lat,
                    "longitude": lon,
                    "google_maps": f"https://www.google.com/maps?q={lat},{lon}",
                    "google_earth": f"https://earth.google.com/web/search/{lat},{lon}",
                    "openstreetmap": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}",
                    "suncalc_osint": f"https://www.suncalc.org/#/{lat},{lon},16/null/null/1/0"
                }
            
            for tag_id, value in exif_data.items():
                tag_name = TAGS.get(tag_id, tag_id)
                if tag_name != 'GPSInfo':
                    metadata[str(tag_name)] = str(value)[:100]
    except Exception:
        # Fallback to PDF processing
        try:
            reader = PdfReader(file.file)
            doc_info = reader.metadata
            if doc_info:
                for k, v in doc_info.items():
                    metadata[str(k)] = str(v)
            metadata["Pages"] = str(len(reader.pages))
        except Exception:
            metadata["Note"] = "Tidak dapat mengoperasikan parsing EXIF/PDF khusus."

    return {
        "success": True,
        "filename": file.filename,
        "file_size": f"{len(contents) / 1024:.2f} KB",
        "hashes": {"md5": md5_hash, "sha256": sha256_hash},
        "metadata": metadata,
        "maps": maps_data
    }

# 4. Endpoint Recon Target (Port & Server Audit)
@app.get("/api/scan")
async def scan_target(target: str = Query(...)):
    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    try:
        ip_addr = socket.gethostbyname(clean_target)
    except socket.gaierror:
        return {"success": False, "message": "Gagal menyelesaikan domain ke IP."}

    # Port Check
    common_ports = [21, 22, 80, 443, 8080]
    port_status = {}
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        res = sock.connect_ex((ip_addr, port))
        port_status[port] = "OPEN" if res == 0 else "CLOSED"
        sock.close()

    # Web Server Info
    web_server = "Unknown"
    status_code = "N/A"
    try:
        resp = requests.get(f"http://{clean_target}", timeout=3)
        web_server = resp.headers.get("Server", "Undisclosed")
        status_code = f"{resp.status_code} {resp.reason}"
    except Exception:
        pass

    return {
        "success": True,
        "data": {
            "target": clean_target,
            "ip_address": ip_addr,
            "status": status_code,
            "web_server": web_server,
            "checked_at": "Just now",
            "ports": port_status
        }
    }

# 5. Endpoint Username Footprinting
@app.get("/api/recon/username")
async def recon_username(username: str = Query(...)):
    platforms = [
        {"name": "GitHub", "url": f"https://github.com/{username}"},
        {"name": "Twitter / X", "url": f"https://x.com/{username}"},
        {"name": "Instagram", "url": f"https://www.instagram.com/{username}/"},
        {"name": "DockerHub", "url": f"https://hub.docker.com/u/{username}"}
    ]
    
    results = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    for p in platforms:
        try:
            r = requests.get(p["url"], headers=headers, timeout=3)
            status = "FOUND" if r.status_code == 200 else "NOT_FOUND"
        except Exception:
            status = "ERROR"
            
        results.append({
            "platform": p["name"],
            "url": p["url"],
            "status": status
        })

    return {
        "success": True,
        "username": username,
        "results": results
    }
