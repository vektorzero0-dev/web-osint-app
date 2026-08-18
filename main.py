from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import os

app = FastAPI(title="OSINT Metadata Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. RUTE UTAMA: Memuat Tampilan Web (index.html)
@app.get("/", response_class=HTMLResponse)
def read_root():
    if os.path.exists("index.html"):
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    return """
    <html>
        <head><title>OSINT Engine</title></head>
        <body style="background: #0f172a; color: #38bdf8; font-family: monospace; text-align: center; padding-top: 50px;">
            <h1>⚠️ File index.html tidak ditemukan!</h1>
            <p>Pastikan file index.html berada di folder yang sama dengan main.py</p>
        </body>
    </html>
    """

def get_gps_data(exif_data):
    """Fungsi ekstraksi GPS presisi tinggi (IFD 34853)"""
    if not exif_data: 
        return "-", "-", "-"
    
    try:
        gps_info = exif_data.get_ifd(34853)
        if not gps_info: 
            return "-", "-", "-"

        gps_map = {GPSTAGS.get(k, k): v for k, v in gps_info.items()}
        lat = gps_map.get("GPSLatitude")
        lat_ref = gps_map.get("GPSLatitudeRef")
        lon = gps_map.get("GPSLongitude")
        lon_ref = gps_map.get("GPSLongitudeRef")

        if lat and lat_ref and lon and lon_ref:
            lat_val = float(lat[0]) + float(lat[1])/60 + float(lat[2])/3600
            if lat_ref != 'N': lat_val = -lat_val
            
            lon_val = float(lon[0]) + float(lon[1])/60 + float(lon[2])/3600
            if lon_ref != 'E': lon_val = -lon_val
            
            return f"{lat_val:.6f}", f"{lon_val:.6f}", f"https://www.google.com/maps/place/{lat_val},{lon_val}"
    except Exception:
        pass
    
    return "-", "-", "-"

# 2. RUTE API METADATA
@app.post("/api/metadata")
async def extract_metadata(file: UploadFile = File(...)):
    temp_filename = f"upload_{file.filename}"
    with open(temp_filename, "wb") as f:
        f.write(await file.read())
    
    try:
        img = Image.open(temp_filename)
        exif = img.getexif()
        lat, lon, link = get_gps_data(exif)
        
        img.close()
        
        return {
            "success": True, 
            "data": {
                "Latitude": lat, 
                "Longitude": lon, 
                "Google Maps Link": link
            }
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Gagal memproses gambar: {str(e)}")
    finally:
        if os.path.exists(temp_filename):
            os.remove(temp_filename)