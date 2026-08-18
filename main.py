from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import os

app = FastAPI(title="OSINT Metadata Engine")

# Tambahkan CORS agar bisa diakses dari frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. Rute utama agar tidak 404
@app.get("/")
def read_root():
    return {"status": "Online", "message": "Metadata Engine siap menerima file."}

def get_gps_data(exif_data):
    """Fungsi ekstraksi GPS yang dipaksa membaca IFD 34853"""
    if not exif_data: 
        return "-", "-", "-"
    
    try:
        # ID 34853 adalah standar untuk GPSInfo
        gps_info = exif_data.get_ifd(34853)
        if not gps_info: 
            return "-", "-", "-"

        gps_map = {GPSTAGS.get(k, k): v for k, v in gps_info.items()}
        lat = gps_map.get("GPSLatitude")
        lat_ref = gps_map.get("GPSLatitudeRef")
        lon = gps_map.get("GPSLongitude")
        lon_ref = gps_map.get("GPSLongitudeRef")

        if lat and lat_ref and lon and lon_ref:
            # Kalkulasi derajat desimal
            lat_val = float(lat[0]) + float(lat[1])/60 + float(lat[2])/3600
            if lat_ref != 'N': lat_val = -lat_val
            
            lon_val = float(lon[0]) + float(lon[1])/60 + float(lon[2])/3600
            if lon_ref != 'E': lon_val = -lon_val
            
            return f"{lat_val:.6f}", f"{lon_val:.6f}", f"https://www.google.com/maps/place/{lat_val},{lon_val}"
    except Exception:
        pass
    
    return "-", "-", "-"

@app.post("/api/metadata")
async def extract_metadata(file: UploadFile = File(...)):
    # Simpan file ke sistem sementara
    temp_filename = f"upload_{file.filename}"
    with open(temp_filename, "wb") as f:
        f.write(await file.read())
    
    try:
        img = Image.open(temp_filename)
        exif = img.getexif()
        lat, lon, link = get_gps_data(exif)
        
        # Bersihkan file setelah dibaca
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