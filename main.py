from fastapi import FastAPI, HTTPException, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import os

app = FastAPI(title="Enterprise OSINT Intelligence Suite", version="4.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def convert_to_degrees(value):
    """Mengonversi format derajat EXIF (tuple) ke koordinat desimal."""
    d = float(value[0])
    m = float(value[1])
    s = float(value[2])
    return d + (m / 60.0) + (s / 3600.0)

@app.post("/api/metadata")
async def extract_metadata(file: UploadFile = File(...)):
    # Simpan file sementara
    temp_path = f"temp_{file.filename}"
    with open(temp_path, "wb") as buffer:
        buffer.write(await file.read())
    
    metadata = {}
    lat_val, lon_val, map_link = "-", "-", "-"

    try:
        img = Image.open(temp_path)
        exif = img.getexif()

        if exif:
            # 1. Ambil Metadata Dasar
            for tag_id, value in exif.items():
                tag_name = TAGS.get(tag_id, tag_id)
                if tag_name != "GPSInfo":
                    metadata[str(tag_name)] = str(value)

            # 2. EKSTRAKSI GPS PRESISI (Langsung ke IFD 34853)
            try:
                gps_info = exif.get_ifd(34853)
                if gps_info:
                    gps_map = {GPSTAGS.get(k, k): v for k, v in gps_info.items()}
                    
                    lat = gps_map.get("GPSLatitude")
                    lat_ref = gps_map.get("GPSLatitudeRef")
                    lon = gps_map.get("GPSLongitude")
                    lon_ref = gps_map.get("GPSLongitudeRef")

                    if lat and lon and lat_ref and lon_ref:
                        lat_deg = convert_to_degrees(lat)
                        if lat_ref != "N": lat_deg = -lat_deg
                        
                        lon_deg = convert_to_degrees(lon)
                        if lon_ref != "E": lon_deg = -lon_deg

                        lat_val = f"{lat_deg:.6f}"
                        lon_val = f"{lon_deg:.6f}"
                        map_link = f"https://www.google.com/maps/place/{lat_deg},{lon_deg}"
            except Exception:
                pass # Tetap bernilai '-' jika tidak ada GPS
        
        metadata["Latitude"] = lat_val
        metadata["Longitude"] = lon_val
        metadata["Google Maps Link"] = map_link
        metadata["Format"] = img.format

    except Exception as e:
        metadata["Error"] = str(e)
    
    if os.path.exists(temp_path):
        os.remove(temp_path)
        
    return {"success": True, "metadata": metadata}