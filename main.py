from flask import Flask, render_template_string, request, jsonify
import os
import hashlib
import socket
import requests
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from PyPDF2 import PdfReader

app = Flask(__name__)

# 1. Route Halaman Utama (index.html)
@app.route("/")
def index():
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return "<h1 style='color:red;'>File index.html tidak ditemukan!</h1>"

# Helper Functions GPS
def convert_to_degrees(value):
    try:
        d, m, s = float(value[0]), float(value[1]), float(value[2])
        return d + (m / 60.0) + (s / 3600.0)
    except Exception:
        return 0.0

# 2. Endpoint Metadata & Exif Analyzer
@app.route("/api/metadata", methods=["POST"])
def extract_metadata():
    if 'file' not in request.files:
        return jsonify({"success": False, "message": "File tidak ditemukan"}), 400

    file = request.files['file']
    file_bytes = file.read()
    
    md5_hash = hashlib.md5(file_bytes).hexdigest()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    
    metadata_results = {}
    maps_data = {"has_gps": False}
    lat_deg, lon_deg = None, None

    ext = os.path.splitext(file.filename)[1].lower()

    if ext in [".jpg", ".jpeg", ".png", ".webp", ".tiff"]:
        try:
            file.seek(0)
            image = Image.open(file)
            exifdata = image._getexif()
            if exifdata:
                for tag_id, data in exifdata.items():
                    tag = TAGS.get(tag_id, tag_id)
                    if isinstance(data, bytes):
                        data = data.decode(errors="ignore")
                    if tag != "GPSInfo":
                        metadata_results[str(tag)] = str(data)[:100]
                
                # GPS Info
                gps_info = exifdata.get(34853)
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
        except Exception as e:
            metadata_results["Error"] = str(e)

    elif ext == ".pdf":
        try:
            file.seek(0)
            reader = PdfReader(file)
            if reader.metadata:
                for k, v in reader.metadata.items():
                    metadata_results[str(k).replace("/", "")] = str(v)
            metadata_results["Total Pages"] = str(len(reader.pages))
        except Exception as e:
            metadata_results["Error"] = str(e)

    if lat_deg is not None and lon_deg is not None:
        maps_data = {
            "has_gps": True,
            "latitude": lat_deg,
            "longitude": lon_deg,
            "google_maps": f"https://www.google.com/maps?q={lat_deg},{lon_deg}",
            "google_earth": f"https://earth.google.com/web/search/{lat_deg},{lon_deg}",
            "openstreetmap": f"https://www.openstreetmap.org/?mlat={lat_deg}&mlon={lon_deg}#map=16/{lat_deg}/{lon_deg}",
            "suncalc_osint": f"https://www.suncalc.org/#/{lat_deg},{lon_deg},17/null/null/null/null"
        }

    return jsonify({
        "success": True,
        "filename": file.filename,
        "file_size": f"{len(file_bytes) / 1024:.2f} KB",
        "hashes": {"md5": md5_hash, "sha256": sha256_hash},
        "maps": maps_data,
        "metadata": metadata_results
    })

# 3. Endpoint Recon Target
@app.route("/api/scan", methods=["GET"])
def scan_target():
    target = request.args.get("target", "").strip().replace("https://", "").replace("http://", "").split("/")[0]
    if not target:
        return jsonify({"success": False, "message": "Target dibutuhkan"}), 400

    try:
        ip_addr = socket.gethostbyname(target)
    except Exception:
        ip_addr = "DNS Resolution Failed"

    ports = [21, 22, 80, 443, 8080]
    port_results = {}
    if "Failed" not in ip_addr:
        for p in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            res = s.connect_ex((ip_addr, p))
            port_results[str(p)] = "OPEN" if res == 0 else "CLOSED"
            s.close()

    return jsonify({
        "success": True,
        "data": {
            "target": target,
            "ip_address": ip_addr,
            "status": "Online",
            "web_server": "Cloudflare/Protected",
            "checked_at": "Just now",
            "ports": port_results
        }
    })

# 4. Endpoint Username Recon
@app.route("/api/recon/username", methods=["GET"])
def recon_username():
    username = request.args.get("username", "").strip().replace("@", "")
    platforms = {
        "GitHub": "https://github.com/{}",
        "Telegram": "https://t.me/{}",
        "Twitter / X": "https://x.com/{}"
    }
    results = []
    headers = {"User-Agent": "Mozilla/5.0"}
    for p, url_template in platforms.items():
        url = url_template.format(username)
        try:
            res = requests.get(url, headers=headers, timeout=3)
            st = "FOUND" if res.status_code == 200 else "NOT FOUND"
        except Exception:
            st = "TIMEOUT"
        results.append({"platform": p, "status": st, "url": url})

    return jsonify({"success": True, "username": username, "results": results})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
