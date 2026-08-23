import os
import re
import socket
import hashlib
import requests
from typing import Optional
from fastapi import FastAPI, File, UploadFile, Query, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

app = FastAPI(title="ZEEO Cyber Intel Suite API", version="3.0")

# Izinkan CORS agar frontend bisa dipanggil dari domain/port mana saja
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# HELPER FUNCTIONS
# ==========================================

def get_decimal_from_dms(dms, ref):
    """Konversi koordinat EXIF GPS (DMS) ke format Decimal Degrees"""
    try:
        degrees = float(dms[0])
        minutes = float(dms[1])
        seconds = float(dms[2])
        sub = degrees + (minutes / 60.0) + (seconds / 3600.0)
        return -sub if ref in ['S', 'W'] else sub
    except Exception:
        return None

# ==========================================
# ROUTES & ENDPOINTS
# ==========================================

@app.get("/", response_class=HTMLResponse)
async def read_root():
    """Melayani file index.html jika berada di direktori yang sama"""
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>ZEEO API Server Active</h1><p>index.html tidak ditemukan di direktori utama.</p>")


@app.get("/api/recon/phone")
async def recon_phone(phone: str = Query(..., description="Nomor telepon target")):
    """Audit provider & pengecekan kebocoran data terenkripsi"""
    clean_num = re.sub(r"\D", "", phone)
    
    if not clean_num:
        return JSONResponse(status_code=400, content={"success": False, "message": "Nomor telepon tidak valid"})

    # Format nomor ke format internasional Indonesia
    if clean_num.startswith("0"):
        formatted = "+62" + clean_num[1:]
    elif clean_num.startswith("62"):
        formatted = "+" + clean_num
    else:
        formatted = "+" + clean_num

    # Deteksi Sederhana Operator Indonesia
    operator = "Unknown Provider"
    prefix = clean_num[:4] if clean_num.startswith("08") else ("0" + clean_num[2:5] if clean_num.startswith("628") else "")

    if prefix in ["0811", "0812", "0813", "0821", "0822", "0823", "0851", "0852", "0853"]:
        operator = "Telkomsel"
    elif prefix in ["0814", "0815", "0816", "0855", "0856", "0857", "0858"]:
        operator = "Indosat Ooredoo"
    elif prefix in ["0817", "0818", "0819", "0859", "0877", "0878"]:
        operator = "XL Axiata"
    elif prefix in ["0831", "0832", "0833", "0838"]:
        operator = "Axis"
    elif prefix in ["0895", "0896", "0897", "0898", "0899"]:
        operator = "Tri (3)"
    elif prefix in ["0881", "0882", "0883", "0884", "0885", "0886", "0887", "0888", "0889"]:
        operator = "Smartfren"

    # Simulasi logika databreach
    breaches = []
    is_breached = False
    
    # Contoh sampel simulasi leak
    if "7172" in clean_num or "999" in clean_num:
        is_breached = True
        breaches = [
            {
                "name": "E-Commerce DB Breach (2023)",
                "date": "2023-11-14",
                "details": "Email, Hash Password, Nomor Telepon, Alamat Pengiriman terdeteksi bocor."
            },
            {
                "name": "Telecom Provider Log Leak",
                "date": "2022-08-02",
                "details": "NIK KTP, Nomor HP, Registrasi SIM Card terdeteksi di forum underground."
            }
        ]

    return {
        "success": True,
        "data": {
            "formatted_phone": formatted,
            "clean_phone": clean_num,
            "country": "Indonesia",
            "country_code": "+62",
            "operator": operator,
            "valid_format": True,
            "breached": is_breached,
            "breaches_count": len(breaches),
            "breaches": breaches
        }
    }


@app.post("/api/metadata")
async def extract_metadata(file: UploadFile = File(...)):
    """Ekstraksi metadata EXIF, GPS, dan Hash dari file gambar"""
    try:
        contents = await file.read()
        
        # Hitung Hash MD5 & SHA256
        md5_hash = hashlib.md5(contents).hexdigest()
        sha256_hash = hashlib.sha256(contents).hexdigest()
        
        # Hitung Ukuran File
        file_size_kb = f"{len(contents) / 1024:.2f} KB"
        
        metadata = {}
        gps_data = {"has_gps": False}
        
        try:
            # Buka gambar menggunakan PIL
            file.file.seek(0)
            img = Image.open(file.file)
            metadata["Dimensions"] = f"{img.width} x {img.height} px"
            metadata["Format"] = img.format
            metadata["Mode"] = img.mode

            exif_raw = img._getexif()
            if exif_raw:
                gps_info = {}
                for tag_id, value in exif_raw.items():
                    tag = TAGS.get(tag_id, tag_id)
                    if tag == 'GPSInfo':
                        for key in value:
                            sub_tag = GPSTAGS.get(key, key)
                            gps_info[sub_tag] = value[key]
                    else:
                        if isinstance(value, (str, int, float)):
                            metadata[str(tag)] = str(value)

                # Ekstraksi Koordinat GPS jika ada
                if gps_info and 'GPSLatitude' in gps_info and 'GPSLongitude' in gps_info:
                    lat = get_decimal_from_dms(gps_info['GPSLatitude'], gps_info.get('GPSLatitudeRef', 'N'))
                    lon = get_decimal_from_dms(gps_info['GPSLongitude'], gps_info.get('GPSLongitudeRef', 'E'))
                    
                    if lat is not None and lon is not None:
                        gps_data = {
                            "has_gps": True,
                            "latitude": round(lat, 6),
                            "longitude": round(lon, 6),
                            "google_maps": f"https://www.google.com/maps?q={lat},{lon}",
                            "openstreetmap": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}"
                        }
        except Exception:
            metadata["Parsing_Note"] = "Standard non-EXIF image format"

        return {
            "success": True,
            "filename": file.filename,
            "file_size": file_size_kb,
            "hashes": {
                "md5": md5_hash,
                "sha256": sha256_hash
            },
            "maps": gps_data,
            "metadata": metadata
        }

    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})


@app.get("/api/scan")
async def scan_target(target: str = Query(..., description="Domain atau IP Target")):
    """Simple Port & IP Reconnaissance"""
    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    try:
        ip_address = socket.gethostbyname(clean_target)
    except socket.gaierror:
        return JSONResponse(status_code=400, content={"success": False, "message": "Domain/Host tidak dapat ditemukan"})

    # Port umum yang diperiksa
    common_ports = [21, 22, 80, 443, 8080, 3306]
    port_results = {}

    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.6)
        result = sock.connect_ex((ip_address, port))
        port_results[str(port)] = "OPEN" if result == 0 else "CLOSED"
        sock.close()

    return {
        "success": True,
        "data": {
            "target": clean_target,
            "ip_address": ip_address,
            "status": "ONLINE",
            "ports": port_results
        }
    }


@app.get("/api/recon/username")
async def recon_username(username: str = Query(..., description="Username target")):
    """Pengecekan ketersediaan/keberadaan profil sosial media"""
    clean_user = username.strip().replace("@", "")
    
    platforms = [
        {"name": "GitHub", "url": f"https://github.com/{clean_user}"},
        {"name": "Instagram", "url": f"https://instagram.com/{clean_user}"},
        {"name": "Twitter / X", "url": f"https://x.com/{clean_user}"},
        {"name": "Telegram", "url": f"https://t.me/{clean_user}"},
        {"name": "TikTok", "url": f"https://tiktok.com/@{clean_user}"},
        {"name": "Pinterest", "url": f"https://pinterest.com/{clean_user}"}
    ]

    results = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    for p in platforms:
        try:
            r = requests.head(p["url"], headers=headers, timeout=2.5, allow_redirects=True)
            status = "FOUND" if r.status_code == 200 else "NOT_FOUND"
        except Exception:
            status = "CHECK_MANUALLY"

        results.append({
            "platform": p["name"],
            "url": p["url"],
            "status": status
        })

    return {
        "success": True,
        "username": clean_user,
        "results": results
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
