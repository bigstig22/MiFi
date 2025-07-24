import os
import sqlite3
from flask import Flask, jsonify, request, send_from_directory, render_template_string

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), 'networks.db')

print("Using database at:", DB_PATH)

# --- API Endpoints ---

@app.route('/api/databases')
def list_databases():
    # For now, just return networks.db
    return jsonify(["networks.db"])

@app.route('/api/sessions')
def list_sessions():
    db = DB_PATH  # Always use absolute path
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute('SELECT DISTINCT session_id FROM signal_tracking ORDER BY session_id')
    sessions = [row[0] for row in c.fetchall() if row[0]]
    conn.close()
    return jsonify(sessions)

@app.route('/api/essids')
def list_essids():
    db = DB_PATH  # Always use absolute path
    session_id = request.args.get('session_id')
    conn = sqlite3.connect(db)
    c = conn.cursor()
    if session_id:
        c.execute('SELECT DISTINCT essid FROM signal_tracking WHERE session_id = ? ORDER BY essid', (session_id,))
    else:
        c.execute('SELECT DISTINCT essid FROM signal_tracking ORDER BY essid')
    essids = [row[0] for row in c.fetchall() if row[0]]
    conn.close()
    return jsonify(essids)

@app.route('/api/data')
def get_data():
    db = DB_PATH  # Always use absolute path
    session_id = request.args.get('session_id')
    essid = request.args.get('essid')
    conn = sqlite3.connect(db)
    c = conn.cursor()
    query = 'SELECT essid, bssid, channel, signal_strength, latitude, longitude, altitude, timestamp, session_id FROM signal_tracking WHERE 1=1'
    params = []
    if session_id:
        query += ' AND session_id = ?'
        params.append(session_id)
    if essid:
        query += ' AND essid = ?'
        params.append(essid)
    c.execute(query, params)
    rows = c.fetchall()
    conn.close()
    # Convert to dicts
    data = [
        {
            'essid': row[0],
            'bssid': row[1],
            'channel': row[2],
            'signal': float(row[3]) if row[3] is not None else None,
            'lat': float(row[4]) if row[4] is not None else None,
            'lon': float(row[5]) if row[5] is not None else None,
            'altitude': row[6],
            'timestamp': row[7],
            'session_id': row[8],
        }
        for row in rows if row[4] is not None and row[5] is not None
    ]
    return jsonify(data)

# --- Frontend ---

@app.route('/')
def index():
    # Serve a single-page app with embedded JS/HTML
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>WiFi Mapping Dashboard</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.7.1/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.7.1/dist/leaflet.js"></script>
    <script src="https://unpkg.com/leaflet.heat/dist/leaflet-heat.js"></script>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #f4f6fa; }
        #toolbar {
            background: #fff;
            color: #222;
            padding: 16px 24px;
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 18px;
            box-shadow: 0 2px 12px rgba(0,0,0,0.07);
            border-radius: 0 0 18px 18px;
            margin-bottom: 8px;
            position: relative;
            z-index: 1001;
        }
        #toolbar label {
            font-weight: 500;
            margin-right: 4px;
        }
        #toolbar select, #toolbar input[type=number], #toolbar input[type=text] {
            padding: 6px 10px;
            border-radius: 6px;
            border: 1px solid #ccc;
            font-size: 1em;
            background: #f9f9f9;
            margin-right: 8px;
        }
        #toolbar select:disabled, #toolbar input:disabled {
            background: #eee;
            color: #aaa;
        }
        #toolbar button {
            background: #0066ff;
            color: #fff;
            border: none;
            border-radius: 6px;
            padding: 7px 18px;
            font-size: 1em;
            cursor: pointer;
            transition: background 0.2s;
        }
        #toolbar button:hover {
            background: #0052cc;
        }
        #status {
            margin-left: auto;
            font-size: 0.98em;
            color: #555;
        }
        #map { height: 90vh; width: 100vw; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.08); }
        @media (max-width: 900px) {
            #toolbar { flex-direction: column; align-items: flex-start; gap: 10px; }
            #status { margin-left: 0; }
        }
    </style>
</head>
<body>
    <div id="toolbar">
        <label for="displayMode" title="Choose how to visualize data">Display:</label>
        <select id="displayMode" title="Choose how to visualize data">
            <option value="markers">Markers</option>
            <option value="heatmap">Heatmap</option>
            <option value="gradient">Gradient</option>
        </select>
        <label for="mapStyle" title="Choose map background">Map Style:</label>
        <select id="mapStyle" title="Choose map background">
            <option value="osm">OpenStreetMap</option>
            <option value="satellite">Satellite</option>
        </select>
        <div id="filterSubtab" style="position:relative;">
            <button id="filterToggle" type="button" style="background:#eee;color:#222;border:1px solid #ccc;padding:6px 14px;border-radius:6px;cursor:pointer;font-weight:500;">Filters ▾</button>
            <div id="filterPanel" style="display:none;position:absolute;left:0;top:40px;background:#fff;border:1px solid #ccc;box-shadow:0 2px 12px rgba(0,0,0,0.08);border-radius:10px;padding:16px 18px;z-index:1002;min-width:340px;">
                <div style="display:flex;flex-wrap:wrap;gap:12px;align-items:center;">
        <label for="sessionSelect" title="Filter by session">Session:</label>
        <select id="sessionSelect" title="Filter by session"></select>
        <label for="essidSelect" title="Filter by ESSID">ESSID:</label>
        <select id="essidSelect" title="Filter by ESSID"></select>
                </div>
                <div style="display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin-top:10px;">
        <label for="minSignal" title="Minimum signal strength (dBm)">Min Signal:</label>
        <input id="minSignal" type="number" min="-100" max="0" step="1" value="-100" style="width:70px;" title="Minimum signal strength (dBm)">
        <label for="maxSignal" title="Maximum signal strength (dBm)">Max Signal:</label>
        <input id="maxSignal" type="number" min="-100" max="0" step="1" value="0" style="width:70px;" title="Maximum signal strength (dBm)">
        <label for="channelFilter" title="Filter by channel">Channel:</label>
        <input id="channelFilter" type="text" placeholder="e.g. 1,6,11" style="width:80px;" title="Comma-separated channels">
                </div>
                <div style="margin-top:10px;text-align:right;">
                    <button onclick="refreshData()" title="Reload data with current filters" style="background:#0066ff;color:#fff;">Refresh</button>
                </div>
            </div>
        </div>
        <span id="status"></span>
    </div>
    <div id="map"></div>
    <script>
        let map = L.map('map').setView([0,0], 2);
        let osmLayer = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors'
        });
        let satLayer = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
            attribution: 'Tiles © Esri &mdash; Source: Esri, i-cubed, USDA, USGS, AEX, GeoEye, Getmapping, Aerogrid, IGN, IGP, UPR-EGP, and the GIS User Community'
        });
        osmLayer.addTo(map);
        let currentBaseLayer = osmLayer;
        let markers = [];
        let heatLayer = null;
        function clearMarkers() {
            markers.forEach(m => map.removeLayer(m));
            markers = [];
            if (heatLayer) { map.removeLayer(heatLayer); heatLayer = null; }
        }
        function plotData(data) {
            clearMarkers();
            // Value filtering
            let minSignal = parseInt(document.getElementById('minSignal').value) || -100;
            let maxSignal = parseInt(document.getElementById('maxSignal').value) || 0;
            let channelFilter = document.getElementById('channelFilter').value.trim();
            let allowedChannels = channelFilter ? channelFilter.split(',').map(s => s.trim()) : null;
            let filtered = data.filter(point => {
                let s = point.signal;
                let ch = point.channel ? String(point.channel).trim() : '';
                let inSignal = (s >= minSignal && s <= maxSignal);
                let inChannel = !allowedChannels || allowedChannels.includes(ch);
                return inSignal && inChannel;
            });
            if (filtered.length === 0) {
                document.getElementById('status').textContent = 'No data.';
                return;
            }
            let mode = document.getElementById('displayMode').value;
            let bounds = [];
            if (mode === 'markers') {
                filtered.forEach(point => {
                    let color = getSignalColor(point.signal);
                    let marker = L.circleMarker([point.lat, point.lon], {
                        radius: 8,
                        fillColor: color,
                        color: '#000',
                        weight: 1,
                        opacity: 1,
                        fillOpacity: 0.8
                    }).addTo(map);
                    marker.bindPopup(`<b>${point.essid}</b><br>Signal: ${point.signal} dBm<br>BSSID: ${point.bssid}<br>Channel: ${point.channel}<br>Time: ${point.timestamp}`);
                    markers.push(marker);
                    bounds.push([point.lat, point.lon]);
                });
            } else if (mode === 'heatmap') {
                let heatData = filtered.map(point => [point.lat, point.lon, signalToHeat(point.signal)]);
                heatLayer = L.heatLayer(heatData, {radius: 25, blur: 18, maxZoom: 18, minOpacity: 0.4}).addTo(map);
                bounds = filtered.map(point => [point.lat, point.lon]);
            } else if (mode === 'gradient') {
                let minSignalVal = Math.min(...filtered.map(p => p.signal));
                let maxSignalVal = Math.max(...filtered.map(p => p.signal));
                filtered.forEach(point => {
                    let color = getGradientColor(point.signal, minSignalVal, maxSignalVal);
                    let marker = L.circleMarker([point.lat, point.lon], {
                        radius: 8,
                        fillColor: color,
                        color: '#000',
                        weight: 1,
                        opacity: 1,
                        fillOpacity: 0.8
                    }).addTo(map);
                    marker.bindPopup(`<b>${point.essid}</b><br>Signal: ${point.signal} dBm<br>BSSID: ${point.bssid}<br>Channel: ${point.channel}<br>Time: ${point.timestamp}`);
                    markers.push(marker);
                    bounds.push([point.lat, point.lon]);
                });
            }
            if (bounds.length > 0) {
                map.fitBounds(bounds, {padding: [30,30]});
            }
            document.getElementById('status').textContent = `Showing ${filtered.length} points.`;
        }
        function getSignalColor(signal) {
            if (signal >= -20) return '#0066ff';
            if (signal >= -40) return '#00ff00';
            if (signal >= -60) return '#ffff00';
            if (signal >= -80) return '#ff6600';
            return '#ff0000';
        }
        function signalToHeat(signal) {
            let norm = (signal + 100) / 80;
            return Math.max(0.05, Math.min(1, norm));
        }
        function getGradientColor(signal, min, max) {
            let t = (signal - min) / (max - min || 1);
            let colors = [
                [0, 102, 255],
                [0, 255, 0],
                [255, 255, 0],
                [255, 0, 0]
            ];
            let idx = Math.floor(t * (colors.length - 1));
            let frac = (t * (colors.length - 1)) - idx;
            let c1 = colors[idx], c2 = colors[Math.min(idx+1, colors.length-1)];
            let r = Math.round(c1[0] + frac * (c2[0] - c1[0]));
            let g = Math.round(c1[1] + frac * (c2[1] - c1[1]));
            let b = Math.round(c1[2] + frac * (c2[2] - c1[2]));
            return `rgb(${r},${g},${b})`;
        }
        async function loadSessions() {
            let res = await fetch(`/api/sessions`);
            let sessions = await res.json();
            let sessionSelect = document.getElementById('sessionSelect');
            sessionSelect.innerHTML = '<option value="">All</option>';
            sessions.forEach(s => {
                let opt = document.createElement('option');
                opt.value = s;
                opt.textContent = s;
                sessionSelect.appendChild(opt);
            });
        }
        async function loadEssids() {
            let session_id = document.getElementById('sessionSelect').value;
            let url = `/api/essids`;
            if (session_id) url += `?session_id=${session_id}`;
            let res = await fetch(url);
            let essids = await res.json();
            let essidSelect = document.getElementById('essidSelect');
            essidSelect.innerHTML = '<option value="">All</option>';
            essids.forEach(e => {
                let opt = document.createElement('option');
                opt.value = e;
                opt.textContent = e;
                essidSelect.appendChild(opt);
            });
            // Enable/disable ESSID filter based on display mode
            let displayMode = document.getElementById('displayMode').value;
            essidSelect.disabled = (displayMode === 'heatmap');
        }
        async function refreshData() {
            let session_id = document.getElementById('sessionSelect').value;
            let essid = document.getElementById('essidSelect').value;
            let url = `/api/data`;
            let params = [];
            if (session_id) params.push(`session_id=${session_id}`);
            if (essid && !document.getElementById('essidSelect').disabled) params.push(`essid=${encodeURIComponent(essid)}`);
            if (params.length > 0) url += '?' + params.join('&');
            document.getElementById('status').textContent = 'Loading...';
            let res = await fetch(url);
            let data = await res.json();
            plotData(data);
        }
        document.getElementById('displayMode').addEventListener('change', async () => {
            // Enable/disable ESSID filter based on mode
            let displayMode = document.getElementById('displayMode').value;
            let essidSelect = document.getElementById('essidSelect');
            essidSelect.disabled = (displayMode === 'heatmap');
            await refreshData();
        });
        document.getElementById('sessionSelect').addEventListener('change', async () => {
            await loadEssids();
            await refreshData();
        });
        document.getElementById('essidSelect').addEventListener('change', refreshData);
        document.getElementById('minSignal').addEventListener('change', refreshData);
        document.getElementById('maxSignal').addEventListener('change', refreshData);
        document.getElementById('channelFilter').addEventListener('change', refreshData);
        document.getElementById('mapStyle').addEventListener('change', function() {
            if (currentBaseLayer) map.removeLayer(currentBaseLayer);
            if (this.value === 'osm') {
                currentBaseLayer = osmLayer;
            } else {
                currentBaseLayer = satLayer;
            }
            currentBaseLayer.addTo(map);
        });
        // Filter subtab toggle logic
        const filterToggle = document.getElementById('filterToggle');
        const filterPanel = document.getElementById('filterPanel');
        let filterPanelOpen = false;
        filterToggle.addEventListener('click', function(e) {
            filterPanelOpen = !filterPanelOpen;
            filterPanel.style.display = filterPanelOpen ? 'block' : 'none';
            filterToggle.textContent = filterPanelOpen ? 'Filters ▴' : 'Filters ▾';
        });
        // Close filter panel if click outside
        document.addEventListener('mousedown', function(e) {
            if (filterPanelOpen && !filterPanel.contains(e.target) && !filterToggle.contains(e.target)) {
                filterPanel.style.display = 'none';
                filterPanelOpen = false;
                filterToggle.textContent = 'Filters ▾';
            }
        });
        // Try to get current location
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(function(pos) {
                let lat = pos.coords.latitude;
                let lon = pos.coords.longitude;
                let marker = L.marker([lat, lon], {icon: L.icon({iconUrl: 'https://cdn-icons-png.flaticon.com/512/684/684908.png', iconSize: [32,32]})}).addTo(map);
                marker.bindPopup('Your current location').openPopup();
            });
        }
        // Initial load
        (async function() {
            await loadSessions();
            await loadEssids();
            await refreshData();
        })();
    </script>
</body>
</html>
    ''')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 