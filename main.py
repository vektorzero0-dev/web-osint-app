import os
import io
import json
from flask import Flask, render_template_string, request, jsonify
from PIL import Image
import piexif

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max 16MB upload

def convert_to_degrees(value):
    """Konversi koordinat EXIF GPS (Degree, Minute, Second) ke Decimal Degrees"""
    try:
        d = float(value[0][0]) / float(value[0][1])
        m = float(value[1][0]) / float(value[1][1])
        s = float(value[2][0]) / float(value[2][1])
        return d + (m / 60.0) + (s / 3600.0)
    except Exception:
        return None

def extract_exif_data(image_bytes):
    data = {
        "summary": {},
        "exif_details": {},
        "gps": None,
        "has_gps": False,
        "device_info": {}
    }
    try:
        image = Image.open(io.BytesIO(image_bytes))
        data["summary"]["Nama Format"] = image.format
        data["summary"]["Mode Warna"] = image.mode
        data["summary"]["Resolusi"] = f"{image.width} x {image.height} px"
        data["summary"]["Jumlah Megapixel"] = f"{round((image.width * image.height) / 1000000, 2)} MP"

        exif_dict = piexif.load(image_bytes)
        
        # Iterasi kategori EXIF
        for tag_category in ("0th", "Exif", "1st"):
            for tag, val in exif_dict.get(tag_category, {}).items():
                tag_name = piexif.TAGS[tag_category].get(tag, {}).get("name", str(tag))
                if isinstance(val, bytes):
                    try:
                        val = val.decode('utf-8', errors='ignore').strip('\x00')
                    except Exception:
                        val = str(val)
                elif isinstance(val, tuple) and len(val) == 2 and isinstance(val[0], int) and isinstance(val[1], int) and val[1] != 0:
                    val = f"{val[0]}/{val[1]} ({round(val[0]/val[1], 4)})"
                data["exif_details"][tag_name] = str(val)

        # Informasi Perangkat
        make = data["exif_details"].get("Make", "Tidak Diketahui").strip()
        model = data["exif_details"].get("Model", "Tidak Diketahui").strip()
        date_taken = data["exif_details"].get("DateTimeOriginal", data["exif_details"].get("DateTime", "Tidak Ada")).strip()
        software = data["exif_details"].get("Software", "-").strip()

        data["device_info"] = {
            "Merek Perangkat": make,
            "Model HP / Kamera": model,
            "Tanggal Waktu Pengambilan": date_taken,
            "Software / OS Editor": software
        }

        # Ekstraksi GPS Data
        gps_info = exif_dict.get("GPS", {})
        if gps_info:
            lat_data = gps_info.get(piexif.GPSIFD.GPSLatitude)
            lat_ref = gps_info.get(piexif.GPSIFD.GPSLatitudeRef)
            lon_data = gps_info.get(piexif.GPSIFD.GPSLongitude)
            lon_ref = gps_info.get(piexif.GPSIFD.GPSLongitudeRef)

            if lat_data and lat_ref and lon_data and lon_ref:
                lat = convert_to_degrees(lat_data)
                lon = convert_to_degrees(lon_data)

                if isinstance(lat_ref, bytes): lat_ref = lat_ref.decode('utf-8', errors='ignore')
                if isinstance(lon_ref, bytes): lon_ref = lon_ref.decode('utf-8', errors='ignore')

                if str(lat_ref).strip().upper() == 'S': lat = -lat
                if str(lon_ref).strip().upper() == 'W': lon = -lon

                altitude = None
                alt_data = gps_info.get(piexif.GPSIFD.GPSAltitude)
                if alt_data and alt_data[1] != 0:
                    try:
                        altitude = round(float(alt_data[0]) / float(alt_data[1]), 2)
                    except Exception:
                        pass

                data["gps"] = {
                    "latitude": lat,
                    "longitude": lon,
                    "altitude": altitude,
                    "lat_ref": lat_ref,
                    "lon_ref": lon_ref
                }
                data["has_gps"] = True

    except Exception as e:
        data["error"] = f"Error ekstraksi: {str(e)}"

    return data

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="id" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NEXUS OSINT - Geolocation & EXIF Recon</title>
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        emerald: {
                            400: '#34d399',
                            500: '#10b981',
                            950: '#022c22',
                        },
                        darkbg: '#090d16',
                        cardbg: '#111827'
                    }
                }
            }
        }
    </script>
    <!-- Leaflet CSS & JS -->
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <!-- Font Awesome Icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { background-color: #090d16; color: #f3f4f6; font-family: 'Inter', system-ui, -apple-system, sans-serif; }
        #map { height: 480px; width: 100%; border-radius: 1rem; border: 1px solid #1f2937; }
        .glass-panel { background: rgba(17, 24, 39, 0.85); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.08); }
        .custom-scrollbar::-webkit-scrollbar { width: 6px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: #111827; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #374151; border-radius: 9999px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #10b981; }
    </style>
</head>
<body class="min-h-screen flex flex-col justify-between antialiased">

    <!-- Navbar Minimalis Cyber -->
    <header class="border-b border-gray-800/80 bg-gray-900/90 sticky top-0 z-50 backdrop-blur-md">
        <div class="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <div class="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                    <i class="fa-solid fa-crosshairs text-xl"></i>
                </div>
                <div>
                    <h1 class="text-lg font-bold tracking-wide text-white flex items-center gap-2">
                        NEXUS <span class="text-xs bg-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded font-mono border border-emerald-500/30">EXIF RECON</span>
                    </h1>
                    <p class="text-xs text-gray-400">Spatial Intelligence & Geospatial Metadata Extraction</p>
                </div>
            </div>
            <div class="hidden md:flex items-center space-x-4 text-xs font-mono">
                <span class="flex items-center gap-2 text-emerald-400 bg-emerald-950/40 px-3 py-1.5 rounded-lg border border-emerald-800/50">
                    <span class="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span> SYSTEM READY
                </span>
            </div>
        </div>
    </header>

    <!-- Main Container -->
    <main class="max-w-7xl mx-auto px-6 py-8 w-full space-y-8 flex-grow">
        
        <!-- Upload Section -->
        <section class="glass-panel p-8 rounded-2xl text-center relative overflow-hidden">
            <div class="absolute -right-10 -top-10 w-40 h-40 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none"></div>
            
            <form id="uploadForm" class="max-w-xl mx-auto">
                <div class="border-2 border-dashed border-gray-700 hover:border-emerald-500/70 transition-all rounded-2xl p-8 cursor-pointer bg-gray-900/40 group" onclick="document.getElementById('fileInput').click()">
                    <div class="w-16 h-16 bg-gray-800 rounded-full flex items-center justify-center mx-auto mb-4 group-hover:scale-110 transition-transform border border-gray-700 group-hover:border-emerald-500/40">
                        <i class="fa-solid fa-cloud-arrow-up text-2xl text-emerald-400"></i>
                    </div>
                    <h3 class="text-base font-semibold text-gray-200">Upload Foto Target Analisis</h3>
                    <p class="text-xs text-gray-400 mt-1">Pilih foto format JPG, JPEG, TIFF (Maksimal 16 MB)</p>
                    <input type="file" id="fileInput" name="file" accept="image/*" class="hidden" onchange="processImage(event)">
                </div>
            </form>

            <div id="loadingIndicator" class="hidden mt-6 flex items-center justify-center space-x-3 text-emerald-400 text-sm font-mono">
                <i class="fa-solid fa-circle-notch animate-spin text-lg"></i>
                <span>Memproses Metadata & Koordinat Spatial...</span>
            </div>

            <p id="selectedFileName" class="mt-4 text-xs text-emerald-400 font-mono hidden bg-emerald-950/50 py-2 px-4 rounded-lg inline-block border border-emerald-800/40"></p>
        </section>

        <!-- Dynamic Results Section -->
        <div id="resultsWrapper" class="hidden grid grid-cols-1 lg:grid-cols-12 gap-8">
            
            <!-- LEFT COLUMN: Maps & Location Data (7 cols) -->
            <div class="lg:col-span-7 space-y-6">
                
                <!-- Map Card -->
                <div class="glass-panel p-6 rounded-2xl space-y-4">
                    <div class="flex items-center justify-between border-b border-gray-800 pb-4">
                        <div class="flex items-center space-x-2">
                            <i class="fa-solid fa-map-location-dot text-emerald-400"></i>
                            <h2 class="text-base font-semibold text-white">Visualisasi Peta Lokasi (GPS)</h2>
                        </div>
                        <div id="gpsBadge"></div>
                    </div>

                    <!-- Map Container -->
                    <div id="map"></div>

                    <!-- Coordinates Display Box -->
                    <div id="coordBox" class="hidden bg-gray-900/90 border border-gray-800 p-4 rounded-xl font-mono text-xs space-y-2">
                        <div class="flex justify-between items-center text-gray-400">
                            <span>LATITUDE / LONGITUDE:</span>
                            <span id="latLonVal" class="text-emerald-400 font-bold select-all"></span>
                        </div>
                        <div class="flex justify-between items-center text-gray-400">
                            <span>KETINGGIAN (ALTITUDE):</span>
                            <span id="altVal" class="text-gray-200"></span>
                        </div>
                    </div>

                    <!-- Quick Action / Share Location Buttons (Sherlok) -->
                    <div id="sherlokBar" class="hidden space-y-3 pt-2">
                        <label class="text-xs text-gray-400 font-semibold uppercase tracking-wider block">Akses Langsung & Share Lokasi (Sherlok):</label>
                        
                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                            <!-- WhatsApp Sherlok -->
                            <a id="btnWaSherlok" target="_blank" class="bg-emerald-600 hover:bg-emerald-500 text-white text-xs py-2.5 px-4 rounded-xl flex items-center justify-center gap-2 font-medium transition-colors shadow-lg shadow-emerald-900/20">
                                <i class="fa-brands fa-whatsapp text-lg"></i> Bagikan Lokasi (WhatsApp)
                            </a>

                            <!-- Google Maps -->
                            <a id="btnGoogleMaps" target="_blank" class="bg-gray-800 hover:bg-gray-700 text-white text-xs py-2.5 px-4 rounded-xl border border-gray-700 flex items-center justify-center gap-2 font-medium transition-colors">
                                <i class="fa-solid fa-map-pin text-red-400"></i> Buka Google Maps
                            </a>

                            <!-- Google Street View -->
                            <a id="btnStreetView" target="_blank" class="bg-gray-800 hover:bg-gray-700 text-white text-xs py-2.5 px-4 rounded-xl border border-gray-700 flex items-center justify-center gap-2 font-medium transition-colors">
                                <i class="fa-solid fa-street-view text-yellow-400"></i> Google Street View
                            </a>

                            <!-- OpenStreetMap -->
                            <a id="btnOSM" target="_blank" class="bg-gray-800 hover:bg-gray-700 text-white text-xs py-2.5 px-4 rounded-xl border border-gray-700 flex items-center justify-center gap-2 font-medium transition-colors">
                                <i class="fa-solid fa-earth-americas text-blue-400"></i> OpenStreetMap
                            </a>
                        </div>
                    </div>
                </div>

            </div>

            <!-- RIGHT COLUMN: Device Info & Complete Metadata (5 cols) -->
            <div class="lg:col-span-5 space-y-6">
                
                <!-- Device & Capture Summary Card -->
                <div class="glass-panel p-6 rounded-2xl space-y-4">
                    <div class="flex items-center space-x-2 border-b border-gray-800 pb-3">
                        <i class="fa-solid fa-mobile-screen-button text-emerald-400"></i>
                        <h2 class="text-base font-semibold text-white">Informasi Perangkat Target</h2>
                    </div>
                    
                    <div class="space-y-3 text-xs">
                        <div class="flex justify-between py-1.5 border-b border-gray-800/60">
                            <span class="text-gray-400">Merek Kamera / HP</span>
                            <span id="devMake" class="text-white font-semibold"></span>
                        </div>
                        <div class="flex justify-between py-1.5 border-b border-gray-800/60">
                            <span class="text-gray-400">Tipe / Model HP</span>
                            <span id="devModel" class="text-white font-semibold"></span>
                        </div>
                        <div class="flex justify-between py-1.5 border-b border-gray-800/60">
                            <span class="text-gray-400">Waktu Foto Diambil</span>
                            <span id="devDate" class="text-emerald-400 font-mono font-semibold"></span>
                        </div>
                        <div class="flex justify-between py-1.5">
                            <span class="text-gray-400">Software / Aplikasi</span>
                            <span id="devSoftware" class="text-gray-300"></span>
                        </div>
                    </div>
                </div>

                <!-- Complete EXIF Table Card -->
                <div class="glass-panel p-6 rounded-2xl space-y-4">
                    <div class="flex items-center justify-between border-b border-gray-800 pb-3">
                        <div class="flex items-center space-x-2">
                            <i class="fa-solid fa-list text-emerald-400"></i>
                            <h2 class="text-base font-semibold text-white">Detail EXIF Raw Data</h2>
                        </div>
                        <span id="exifCount" class="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded font-mono"></span>
                    </div>

                    <div class="overflow-y-auto max-h-[350px] custom-scrollbar pr-1">
                        <table class="w-full text-left text-xs">
                            <thead>
                                <tr class="text-gray-400 border-b border-gray-800">
                                    <th class="pb-2 font-medium">Tag Attribute</th>
                                    <th class="pb-2 font-medium">Raw Value</th>
                                </tr>
                            </thead>
                            <tbody id="exifTableBody" class="divide-y divide-gray-800/50"></tbody>
                        </table>
                    </div>
                </div>

            </div>

        </div>

    </main>

    <!-- Footer -->
    <footer class="border-t border-gray-800/80 bg-gray-900/60 py-4 text-center text-xs text-gray-500">
        NEXUS Spatial OSINT Tools &bull; Forensic Metadata Platform
    </footer>

    <!-- JavaScript Logic -->
    <script>
        let map = null;
        let marker = null;

        function processImage(e) {
            const file = e.target.files[0];
            if (!file) return;

            document.getElementById('selectedFileName').innerText = "File: " + file.name;
            document.getElementById('selectedFileName').classList.remove('hidden');
            document.getElementById('loadingIndicator').classList.remove('hidden');
            document.getElementById('resultsWrapper').classList.add('hidden');

            const formData = new FormData();
            formData.append('file', file);

            fetch('/analyze', { method: 'POST', body: formData })
                .then(res => res.json())
                .then(data => {
                    document.getElementById('loadingIndicator').classList.add('hidden');
                    renderUI(data);
                })
                .catch(err => {
                    document.getElementById('loadingIndicator').classList.add('hidden');
                    alert("Gagal memproses file gambar.");
                });
        }

        function renderUI(data) {
            document.getElementById('resultsWrapper').classList.remove('hidden');

            // 1. Render Informasi Perangkat
            document.getElementById('devMake').innerText = data.device_info["Merek Perangkat"] || "-";
            document.getElementById('devModel').innerText = data.device_info["Model HP / Kamera"] || "-";
            document.getElementById('devDate').innerText = data.device_info["Tanggal Waktu Pengambilan"] || "-";
            document.getElementById('devSoftware').innerText = data.device_info["Software / OS Editor"] || "-";

            // 2. Render Tabel EXIF Raw
            const tbody = document.getElementById('exifTableBody');
            tbody.innerHTML = '';
            const entries = Object.entries(data.exif_details);
            document.getElementById('exifCount').innerText = entries.length + " tags";

            entries.forEach(([key, val]) => {
                const tr = document.createElement('tr');
                tr.className = "hover:bg-gray-800/30 transition-colors";
                tr.innerHTML = `
                    <td class="py-2 pr-2 font-mono text-emerald-400 font-medium">${key}</td>
                    <td class="py-2 text-gray-300 break-all">${val}</td>
                `;
                tbody.appendChild(tr);
            });

            // 3. Render Peta & Fitur Sherlok (Share Lokasi)
            const gpsBadge = document.getElementById('gpsBadge');
            const coordBox = document.getElementById('coordBox');
            const sherlokBar = document.getElementById('sherlokBar');

            if (data.has_gps && data.gps) {
                const lat = data.gps.latitude;
                const lon = data.gps.longitude;
                const alt = data.gps.altitude ? data.gps.altitude + " meter" : "Tidak Terdeteksi";

                // Update Status Badge
                gpsBadge.innerHTML = `<span class="bg-emerald-500/20 text-emerald-400 text-xs px-2.5 py-1 rounded-md font-mono border border-emerald-500/30 flex items-center gap-1.5"><i class="fa-solid fa-circle text-[8px] text-emerald-400 animate-ping"></i> GPS TERKUNCI</span>`;

                // Show Display Box & Values
                coordBox.classList.remove('hidden');
                document.getElementById('latLonVal').innerText = `${lat.toFixed(6)}, ${lon.toFixed(6)}`;
                document.getElementById('altVal').innerText = alt;

                // Configure Sherlok Buttons
                sherlokBar.classList.remove('hidden');

                const gmapsUrl = `https://www.google.com/maps?q=${lat},${lon}`;
                const streetViewUrl = `https://www.google.com/maps?layer=c&cbll=${lat},${lon}`;
                const osmUrl = `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=16/${lat}/${lon}`;
                
                // Format Pesan WhatsApp Sherlok
                const waText = encodeURIComponent(`📍 *LOKASI HASIL METADATA RECON*\n\n` +
                    `Latitude: ${lat.toFixed(6)}\n` +
                    `Longitude: ${lon.toFixed(6)}\n\n` +
                    `Buka di Google Maps:\n${gmapsUrl}`);
                
                document.getElementById('btnWaSherlok').href = `https://api.whatsapp.com/send?text=${waText}`;
                document.getElementById('btnGoogleMaps').href = gmapsUrl;
                document.getElementById('btnStreetView').href = streetViewUrl;
                document.getElementById('btnOSM').href = osmUrl;

                // Init Leaflet Map
                initMap(lat, lon, 16);
            } else {
                gpsBadge.innerHTML = `<span class="bg-red-500/20 text-red-400 text-xs px-2.5 py-1 rounded-md font-mono border border-red-500/30"><i class="fa-solid fa-triangle-exclamation"></i> TIDAK ADA GPS</span>`;
                coordBox.classList.add('hidden');
                sherlokBar.classList.add('hidden');
                initMap(-6.175392, 106.827153, 3); // Default Indonesia view
            }
        }

        function initMap(lat, lon, zoom = 15) {
            if (!map) {
                map = L.map('map').setView([lat, lon], zoom);
                L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                    maxZoom: 19,
                    attribution: '&copy; OpenStreetMap'
                }).addTo(map);
            } else {
                map.setView([lat, lon], zoom);
            }

            if (marker) map.removeLayer(marker);

            if (lat !== -6.175392 || lon !== 106.827153) {
                marker = L.marker([lat, lon]).addTo(map)
                    .bindPopup(`<div class="font-mono text-xs"><b>Target Koordinat:</b><br>${lat.toFixed(6)}, ${lon.toFixed(6)}</div>`)
                    .openPopup();
            }
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'File tidak ditemukan'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'File belum dipilih'}), 400

    image_bytes = file.read()
    results = extract_exif_data(image_bytes)
    return jsonify(results)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
