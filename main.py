import os
import io
import datetime
from flask import Flask, render_template, request, jsonify
from PIL import Image
import piexif

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # Max 32MB

def convert_to_degrees(value):
    try:
        d = float(value[0][0]) / float(value[0][1])
        m = float(value[1][0]) / float(value[1][1])
        s = float(value[2][0]) / float(value[2][1])
        return d + (m / 60.0) + (s / 3600.0)
    except Exception:
        return None

def extract_exif_data(image_bytes):
    data = {"metadata": {}, "gps": None, "has_gps": False}
    try:
        image = Image.open(io.BytesIO(image_bytes))
        data["metadata"]["Format"] = image.format
        data["metadata"]["Color Mode"] = image.mode
        data["metadata"]["Resolution"] = f"{image.width} x {image.height} px"

        exif_dict = piexif.load(image_bytes)
        
        for tag_category in ("0th", "Exif"):
            for tag, val in exif_dict.get(tag_category, {}).items():
                tag_name = piexif.TAGS[tag_category].get(tag, {}).get("name", str(tag))
                if isinstance(val, bytes):
                    try:
                        val = val.decode('utf-8', errors='ignore').strip('\x00')
                    except Exception:
                        val = str(val)
                data["metadata"][tag_name] = str(val)

        gps_info = exif_dict.get("GPS", {})
        if gps_info:
            lat_data = gps_info.get(piexif.GPSIFD.GPSLatitude)
            lat_ref = gps_info.get(piexif.GPSIFD.GPSLatitudeRef)
            lon_data = gps_info.get(piexif.GPSIFD.GPSLongitude)
            lon_ref = gps_info.get(piexif.GPSIFD.GPSLongitudeRef)

            if lat_data and lat_ref and lon_data and lon_ref:
                lat = convert_to_degrees(lat_data)
                lon = convert_to_degrees(lon_data)

                if isinstance(lat_ref, bytes): lat_ref = lat_ref.decode()
                if isinstance(lon_ref, bytes): lon_ref = lon_ref.decode()

                if lat_ref == 'S': lat = -lat
                if lon_ref == 'W': lon = -lon

                altitude = None
                alt_data = gps_info.get(piexif.GPSIFD.GPSAltitude)
                if alt_data:
                    try:
                        altitude = round(float(alt_data[0]) / float(alt_data[1]), 2)
                    except Exception:
                        pass

                data["gps"] = {
                    "latitude": lat,
                    "longitude": lon,
                    "altitude": altitude
                }
                data["has_gps"] = True

    except Exception as e:
        data["error"] = f"Failed to extract EXIF: {str(e)}"

    return data

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/metadata', methods=['POST'])
def api_metadata():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    results = extract_exif_data(file.read())
    return jsonify(results)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
