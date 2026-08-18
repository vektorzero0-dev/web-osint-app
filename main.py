from fastapi import FastAPI, UploadFile, File
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import os

app = FastAPI()

def get_gps_data(exif_data):
    if not exif_data: return "-", "-", "-"
    
    # 34853 adalah ID untuk GPSInfo
    gps_info = exif_data.get_ifd(34853)
    if not gps_info: return "-", "-", "-"

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
    
    return "-", "-", "-"

@app.post("/api/metadata")
async def extract_metadata(file: UploadFile = File(...)):
    # Simpan file
    with open(file.filename, "wb") as f:
        f.write(await file.read())
    
    try:
        img = Image.open(file.filename)
        exif = img.getexif()
        lat, lon, link = get_gps_data(exif)
        
        result = {
            "Latitude": lat,
            "Longitude": lon,
            "Google Maps Link": link
        }
    finally:
        if os.path.exists(file.filename):
            os.remove(file.filename)
            
    return {"success": True, "data": result}