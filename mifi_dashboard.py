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

@app.route('/api/bssids')
def list_bssids():
    db = DB_PATH
    session_id = request.args.get('session_id')
    essid = request.args.get('essid')
    conn = sqlite3.connect(db)
    c = conn.cursor()
    if session_id and essid:
        c.execute('SELECT DISTINCT bssid FROM signal_tracking WHERE session_id = ? AND essid = ? ORDER BY bssid', (session_id, essid))
    elif session_id:
        c.execute('SELECT DISTINCT bssid FROM signal_tracking WHERE session_id = ? ORDER BY bssid', (session_id,))
    elif essid:
        c.execute('SELECT DISTINCT bssid FROM signal_tracking WHERE essid = ? ORDER BY bssid', (essid,))
    else:
        c.execute('SELECT DISTINCT bssid FROM signal_tracking ORDER BY bssid')
    bssids = [row[0] for row in c.fetchall() if row[0]]
    conn.close()
    return jsonify(bssids)

@app.route('/api/data')
def get_data():
    db = DB_PATH  # Always use absolute path
    session_id = request.args.get('session_id')
    essid = request.args.get('essid')
    bssid = request.args.get('bssid')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    min_alt = request.args.get('min_alt')
    max_alt = request.args.get('max_alt')
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
    if bssid:
        query += ' AND bssid = ?'
        params.append(bssid)
    if date_from:
        query += ' AND timestamp >= ?'
        params.append(date_from)
    if date_to:
        query += ' AND timestamp <= ?'
        params.append(date_to)
    if min_alt:
        query += ' AND altitude >= ?'
        params.append(float(min_alt))
    if max_alt:
        query += ' AND altitude <= ?'
        params.append(float(max_alt))
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

@app.route('/api/delete', methods=['POST'])
def delete_tracks():
    db = DB_PATH
    data = request.json
    session_id = data.get('session_id')
    essid = data.get('essid')
    bssid = data.get('bssid')
    date_from = data.get('date_from')
    date_to = data.get('date_to')
    
    conn = sqlite3.connect(db)
    c = conn.cursor()
    query = 'DELETE FROM signal_tracking WHERE 1=1'
    params = []
    if session_id:
        query += ' AND session_id = ?'
        params.append(session_id)
    if essid:
        query += ' AND essid = ?'
        params.append(essid)
    if bssid:
        query += ' AND bssid = ?'
        params.append(bssid)
    if date_from:
        query += ' AND timestamp >= ?'
        params.append(date_from)
    if date_to:
        query += ' AND timestamp <= ?'
        params.append(date_to)
    
    c.execute(query, params)
    deleted_count = c.rowcount
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'deleted': deleted_count})

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
            background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
            color: #222;
            padding: 0;
            box-shadow: 0 2px 12px rgba(0,0,0,0.07);
            border-radius: 0 0 12px 12px;
            margin-bottom: 8px;
            position: relative;
            z-index: 1001;
        }
        .toolbar-main {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 16px;
            padding: 14px 20px;
            border-bottom: 1px solid #e9ecef;
        }
        .toolbar-advanced {
            display: none;
            padding: 16px 20px;
            background: #f8f9fa;
            border-top: 1px solid #e9ecef;
            border-radius: 0 0 12px 12px;
        }
        .toolbar-advanced.expanded {
            display: block;
        }
        .filter-item {
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .filter-item label {
            font-weight: 500;
            font-size: 0.9em;
            color: #495057;
            white-space: nowrap;
        }
        .filter-item select, .filter-item input[type=number], .filter-item input[type=text], .filter-item input[type=date] {
            padding: 6px 10px;
            border-radius: 6px;
            border: 1px solid #ced4da;
            font-size: 0.9em;
            background: #fff;
            transition: all 0.2s;
            min-width: 120px;
        }
        .filter-item select:focus, .filter-item input:focus {
            outline: none;
            border-color: #0066ff;
            box-shadow: 0 0 0 3px rgba(0, 102, 255, 0.1);
        }
        .filter-item select:disabled, .filter-item input:disabled {
            background: #e9ecef;
            color: #6c757d;
            cursor: not-allowed;
        }
        .filter-item input[type=number] {
            width: 75px;
        }
        .filter-item input[type=text] {
            width: 100px;
        }
        .filter-item input[type=date] {
            width: 140px;
        }
        button {
            background: #0066ff;
            color: #fff;
            border: none;
            border-radius: 6px;
            padding: 7px 16px;
            font-size: 0.9em;
            cursor: pointer;
            transition: all 0.2s;
            font-weight: 500;
            white-space: nowrap;
        }
        button:hover {
            background: #0052cc;
            transform: translateY(-1px);
            box-shadow: 0 2px 6px rgba(0,0,0,0.15);
        }
        button:active {
            transform: translateY(0);
        }
        button.danger {
            background: #dc3545;
        }
        button.danger:hover {
            background: #c82333;
        }
        button.secondary {
            background: #6c757d;
        }
        button.secondary:hover {
            background: #5a6268;
        }
        button.expand-toggle {
            background: #e9ecef;
            color: #495057;
            border: 1px solid #ced4da;
            padding: 6px 12px;
            font-size: 0.85em;
        }
        button.expand-toggle:hover {
            background: #dee2e6;
        }
        #status {
            margin-left: auto;
            font-size: 0.9em;
            color: #6c757d;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 10px;
            background: #e7f3ff;
            color: #0066ff;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }
        #map { height: calc(100vh - 120px); min-height: 500px; width: 100vw; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.08); }
        .legend {
            position: absolute;
            bottom: 30px;
            right: 30px;
            background: rgba(255, 255, 255, 0.95);
            padding: 12px 16px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
            z-index: 1000;
            min-width: 200px;
            display: none;
        }
        .legend.visible {
            display: block;
        }
        .legend-title {
            font-weight: 600;
            margin-bottom: 8px;
            color: #212529;
            font-size: 0.9em;
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 6px;
            font-size: 0.85em;
        }
        .legend-color {
            width: 20px;
            height: 20px;
            border-radius: 4px;
            border: 1px solid #000;
            flex-shrink: 0;
        }
        .legend-label {
            color: #495057;
        }
        .color-editor {
            background: rgba(255, 255, 255, 0.95);
            padding: 16px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
            margin-top: 12px;
            border-top: 1px solid #dee2e6;
        }
        .color-editor-title {
            font-weight: 600;
            margin-bottom: 12px;
            color: #212529;
            font-size: 0.9em;
        }
        .color-threshold {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 8px;
        }
        .color-threshold input[type="number"] {
            width: 70px;
            padding: 4px 8px;
            border: 1px solid #ced4da;
            border-radius: 4px;
        }
        .color-threshold input[type="color"] {
            width: 40px;
            height: 30px;
            border: 1px solid #ced4da;
            border-radius: 4px;
            cursor: pointer;
        }
        .color-threshold button {
            padding: 4px 8px;
            font-size: 0.8em;
            background: #dc3545;
        }
        .color-threshold button:hover {
            background: #c82333;
        }
        .add-threshold-btn {
            margin-top: 8px;
            padding: 6px 12px;
            font-size: 0.85em;
        }
        .advanced-filters {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 16px;
            margin-bottom: 12px;
        }
        .advanced-filter-group {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        .advanced-filter-group label {
            font-size: 0.85em;
            color: #6c757d;
            font-weight: 500;
        }
        .advanced-filter-group .filter-item {
            flex-direction: column;
            align-items: flex-start;
            gap: 4px;
        }
        .advanced-filter-group .filter-item input,
        .advanced-filter-group .filter-item select {
            width: 100%;
            min-width: auto;
        }
        .toolbar-actions {
            display: flex;
            gap: 8px;
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid #dee2e6;
        }
        .toolbar-actions button {
            flex: 1;
        }
        .divider {
            width: 1px;
            height: 24px;
            background: #dee2e6;
            margin: 0 4px;
        }
        .modal {
            display: none;
            position: fixed;
            z-index: 2000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
            backdrop-filter: blur(2px);
        }
        .modal-content {
            background-color: #fff;
            margin: 15% auto;
            padding: 28px;
            border-radius: 12px;
            width: 90%;
            max-width: 500px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
            animation: modalSlideIn 0.3s ease;
        }
        @keyframes modalSlideIn {
            from { transform: translateY(-20px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        .modal-header {
            font-size: 1.4em;
            font-weight: 600;
            margin-bottom: 16px;
            color: #222;
        }
        .modal-body {
            margin-bottom: 24px;
            color: #555;
            line-height: 1.6;
        }
        .modal-footer {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
        }
        .keyboard-hint {
            font-size: 0.75em;
            color: #adb5bd;
            margin-left: 6px;
            font-weight: normal;
        }
        .marker-label {
            background: rgba(255, 255, 255, 0.9);
            border: 1px solid #000;
            border-radius: 4px;
            padding: 2px 6px;
            font-size: 0.75em;
            font-weight: 500;
            pointer-events: none;
            text-shadow: 1px 1px 1px rgba(255,255,255,0.8);
        }
        .stats-panel {
            display: flex;
            gap: 16px;
            padding: 8px 12px;
            background: #f8f9fa;
            border-radius: 6px;
            font-size: 0.85em;
        }
        .stat-item {
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        .stat-label {
            color: #6c757d;
            font-size: 0.85em;
        }
        .stat-value {
            color: #212529;
            font-weight: 600;
        }
        @media (max-width: 1200px) {
            .toolbar-main { flex-wrap: wrap; }
            .advanced-filters { grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }
        }
        @media (max-width: 768px) {
            .toolbar-main { flex-direction: column; align-items: stretch; gap: 12px; }
            .filter-item { width: 100%; }
            .filter-item select, .filter-item input { width: 100%; min-width: auto; }
            #status { margin-left: 0; justify-content: space-between; width: 100%; }
            .toolbar-actions { flex-direction: column; }
            #map { height: calc(100vh - 300px); }
        }
    </style>
</head>
<body>
    <div id="toolbar">
        <div class="toolbar-main">
            <div class="filter-item">
                <label for="displayMode" title="Choose visualization mode (M)">Display:</label>
                <select id="displayMode" title="Choose visualization mode (M)">
                    <option value="markers">Markers</option>
                    <option value="heatmap">Heatmap</option>
                    <option value="gradient">Gradient</option>
                </select>
            </div>
            <div class="filter-item">
                <label for="mapStyle" title="Choose map background">Map:</label>
                <select id="mapStyle" title="Choose map background">
                    <option value="osm">OpenStreetMap</option>
                    <option value="satellite">Satellite</option>
                </select>
            </div>
            <div class="divider"></div>
            <button onclick="toggleLabels()" id="labelToggle" title="Toggle plot labels (L)" class="secondary">
                <span id="labelToggleText">Show Labels</span><span class="keyboard-hint">(L)</span>
            </button>
            <button onclick="toggleLegend()" id="legendToggle" title="Toggle color legend" class="secondary">
                <span id="legendToggleText">Show Legend</span>
            </button>
            <div class="divider"></div>
            <button onclick="refreshData()" title="Refresh data (R)">Refresh<span class="keyboard-hint">(R)</span></button>
            <button id="expandToggle" class="expand-toggle" onclick="toggleAdvanced()" title="Toggle filters (F)">
                <span id="expandText">Filters</span> <span id="expandIcon">▾</span><span class="keyboard-hint">(F)</span>
            </button>
            <div id="status">
                <span class="status-badge" id="statusBadge">Loading...</span>
            </div>
        </div>
        <div id="toolbarAdvanced" class="toolbar-advanced">
            <div class="advanced-filters">
                <div class="advanced-filter-group">
                    <label>Session Filter</label>
                    <div class="filter-item">
                        <select id="sessionSelect" title="Filter by session"></select>
                    </div>
                </div>
                <div class="advanced-filter-group">
                    <label>ESSID Filter</label>
                    <div class="filter-item">
                        <select id="essidSelect" title="Filter by ESSID"></select>
                    </div>
                </div>
                <div class="advanced-filter-group">
                    <label>BSSID Filter</label>
                    <div class="filter-item">
                        <select id="bssidSelect" title="Filter by BSSID">
                            <option value="">All BSSIDs</option>
                        </select>
                    </div>
                </div>
                <div class="advanced-filter-group">
                    <label>Signal Range (dBm)</label>
                    <div class="filter-item">
                        <input id="minSignal" type="number" min="-100" max="0" step="1" value="-100" title="Min signal (dBm)" placeholder="Min">
                    </div>
                    <div class="filter-item">
                        <input id="maxSignal" type="number" min="-100" max="0" step="1" value="0" title="Max signal (dBm)" placeholder="Max">
                    </div>
                </div>
                <div class="advanced-filter-group">
                    <label>Channel Filter</label>
                    <div class="filter-item">
                        <input id="channelFilter" type="text" placeholder="1,6,11" title="Channels (comma-separated)">
                    </div>
                </div>
                <div class="advanced-filter-group">
                    <label>Date Range</label>
                    <div class="filter-item">
                        <input id="dateFrom" type="date" title="Filter from date" placeholder="From date">
                    </div>
                    <div class="filter-item">
                        <input id="dateTo" type="date" title="Filter to date" placeholder="To date">
                    </div>
                </div>
                <div class="advanced-filter-group">
                    <label>Altitude Range (meters)</label>
                    <div class="filter-item">
                        <input id="minAlt" type="number" step="0.1" placeholder="Min altitude" title="Minimum altitude">
                    </div>
                    <div class="filter-item">
                        <input id="maxAlt" type="number" step="0.1" placeholder="Max altitude" title="Maximum altitude">
                    </div>
                </div>
            </div>
            <div class="toolbar-actions">
                <button onclick="clearFilters()" class="secondary" title="Clear all filters">Clear All Filters</button>
                <button onclick="showDeleteDialog()" class="danger" title="Delete matching tracks (Del)">Delete Tracks<span class="keyboard-hint">(Del)</span></button>
            </div>
        </div>
    </div>
    <div id="deleteModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">Confirm Deletion</div>
            <div class="modal-body" id="deleteModalBody">
                Are you sure you want to delete the selected tracks? This action cannot be undone.
            </div>
            <div class="modal-footer">
                <button onclick="closeDeleteDialog()" class="secondary">Cancel</button>
                <button onclick="confirmDelete()" class="danger">Delete</button>
            </div>
        </div>
    </div>
    <div id="map"></div>
    <div id="legend" class="legend">
        <div class="legend-title">Signal Strength (dBm)</div>
        <div id="legendContent"></div>
        <div class="color-editor" id="colorEditor" style="display:none;">
            <div class="color-editor-title">Custom Color Thresholds</div>
            <div id="colorThresholds"></div>
            <button class="add-threshold-btn secondary" onclick="addColorThreshold()">+ Add Threshold</button>
        </div>
        <button onclick="toggleColorEditor()" class="secondary" style="margin-top:8px;width:100%;font-size:0.85em;">Edit Colors</button>
    </div>
    <script>
        let map = L.map('map', {maxZoom: 20}).setView([0,0], 2);
        let labelsEnabled = false;
        let legendVisible = false;
        let colorThresholds = [
            {threshold: -20, color: '#0066ff'},
            {threshold: -40, color: '#00ff00'},
            {threshold: -60, color: '#ffff00'},
            {threshold: -80, color: '#ff6600'},
            {threshold: -100, color: '#ff0000'}
        ];
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
                document.getElementById('statusBadge').textContent = 'No data';
                document.getElementById('status').title = 'No data matches current filters';
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
                    let altText = point.altitude ? `<br>Altitude: ${point.altitude.toFixed(1)}m` : '';
                    marker.bindPopup(`<b>${point.essid}</b><br>Signal: ${point.signal} dBm<br>BSSID: ${point.bssid}<br>Channel: ${point.channel}${altText}<br>Time: ${point.timestamp}`);
                    if (labelsEnabled) {
                        marker.bindTooltip(point.essid, {
                            permanent: true,
                            direction: 'center',
                            className: 'marker-label'
                        });
                    }
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
                    let altText = point.altitude ? `<br>Altitude: ${point.altitude.toFixed(1)}m` : '';
                    marker.bindPopup(`<b>${point.essid}</b><br>Signal: ${point.signal} dBm<br>BSSID: ${point.bssid}<br>Channel: ${point.channel}${altText}<br>Time: ${point.timestamp}`);
                    if (labelsEnabled) {
                        marker.bindTooltip(point.essid, {
                            permanent: true,
                            direction: 'center',
                            className: 'marker-label'
                        });
                    }
                    markers.push(marker);
                    bounds.push([point.lat, point.lon]);
                });
            }
            if (bounds.length > 0) {
                map.fitBounds(bounds, {padding: [30,30]});
            }
            document.getElementById('statusBadge').textContent = `${filtered.length} points`;
            document.getElementById('status').title = `Showing ${filtered.length} of ${data.length} total points`;
        }
        function getSignalColor(signal) {
            // Sort thresholds descending
            let sorted = [...colorThresholds].sort((a, b) => b.threshold - a.threshold);
            for (let threshold of sorted) {
                if (signal >= threshold.threshold) {
                    return threshold.color;
                }
            }
            return sorted[sorted.length - 1].color;
        }
        function updateLegend() {
            let legendContent = document.getElementById('legendContent');
            legendContent.innerHTML = '';
            let sorted = [...colorThresholds].sort((a, b) => b.threshold - a.threshold);
            for (let i = 0; i < sorted.length; i++) {
                let threshold = sorted[i];
                let nextThreshold = i < sorted.length - 1 ? sorted[i + 1].threshold : -100;
                let range = nextThreshold === -100 ? `${threshold.threshold}+` : `${threshold.threshold} to ${nextThreshold}`;
                let item = document.createElement('div');
                item.className = 'legend-item';
                item.innerHTML = `
                    <div class="legend-color" style="background-color: ${threshold.color};"></div>
                    <span class="legend-label">${range} dBm</span>
                `;
                legendContent.appendChild(item);
            }
        }
        function toggleLegend() {
            legendVisible = !legendVisible;
            let legend = document.getElementById('legend');
            let toggleText = document.getElementById('legendToggleText');
            if (legendVisible) {
                legend.classList.add('visible');
                toggleText.textContent = 'Hide Legend';
                updateLegend();
            } else {
                legend.classList.remove('visible');
                toggleText.textContent = 'Show Legend';
            }
        }
        function toggleLabels() {
            labelsEnabled = !labelsEnabled;
            let toggleText = document.getElementById('labelToggleText');
            toggleText.textContent = labelsEnabled ? 'Hide Labels' : 'Show Labels';
            refreshData();
        }
        function toggleColorEditor() {
            let editor = document.getElementById('colorEditor');
            editor.style.display = editor.style.display === 'none' ? 'block' : 'none';
            if (editor.style.display === 'block') {
                renderColorThresholds();
            }
        }
        function renderColorThresholds() {
            let container = document.getElementById('colorThresholds');
            container.innerHTML = '';
            let sorted = [...colorThresholds].sort((a, b) => b.threshold - a.threshold);
            sorted.forEach((threshold, index) => {
                let div = document.createElement('div');
                div.className = 'color-threshold';
                div.innerHTML = `
                    <input type="number" value="${threshold.threshold}" min="-100" max="0" step="1" 
                           onchange="updateThreshold(${index}, this.value)" style="width:70px;">
                    <span>dBm:</span>
                    <input type="color" value="${threshold.color}" 
                           onchange="updateThresholdColor(${index}, this.value)">
                    ${colorThresholds.length > 1 ? `<button onclick="removeThreshold(${index})">×</button>` : ''}
                `;
                container.appendChild(div);
            });
        }
        function updateThreshold(index, value) {
            let sorted = [...colorThresholds].sort((a, b) => b.threshold - a.threshold);
            let threshold = sorted[index];
            // Find and update in original array
            let originalIndex = colorThresholds.findIndex(t => t.threshold === threshold.threshold && t.color === threshold.color);
            if (originalIndex !== -1) {
                colorThresholds[originalIndex].threshold = parseInt(value);
            }
            updateLegend();
            refreshData();
        }
        function updateThresholdColor(index, color) {
            let sorted = [...colorThresholds].sort((a, b) => b.threshold - a.threshold);
            let threshold = sorted[index];
            // Find and update in original array
            let originalIndex = colorThresholds.findIndex(t => t.threshold === threshold.threshold && t.color === threshold.color);
            if (originalIndex !== -1) {
                colorThresholds[originalIndex].color = color;
            }
            updateLegend();
            refreshData();
        }
        function removeThreshold(index) {
            if (colorThresholds.length <= 1) return;
            let sorted = [...colorThresholds].sort((a, b) => b.threshold - a.threshold);
            let threshold = sorted[index];
            // Find and remove from original array
            let originalIndex = colorThresholds.findIndex(t => t.threshold === threshold.threshold && t.color === threshold.color);
            if (originalIndex !== -1) {
                colorThresholds.splice(originalIndex, 1);
            }
            renderColorThresholds();
            updateLegend();
            refreshData();
        }
        function addColorThreshold() {
            let newThreshold = prompt('Enter threshold value (dBm, e.g., -50):');
            if (newThreshold === null) return;
            let value = parseInt(newThreshold);
            if (isNaN(value) || value < -100 || value > 0) {
                alert('Invalid threshold. Must be between -100 and 0.');
                return;
            }
            if (colorThresholds.find(t => t.threshold === value)) {
                alert('Threshold already exists.');
                return;
            }
            colorThresholds.push({threshold: value, color: '#888888'});
            renderColorThresholds();
            updateLegend();
            refreshData();
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
            await loadBssids();
            // Enable/disable ESSID filter based on display mode
            let displayMode = document.getElementById('displayMode').value;
            essidSelect.disabled = (displayMode === 'heatmap');
        }
        async function loadBssids() {
            let session_id = document.getElementById('sessionSelect').value;
            let essid = document.getElementById('essidSelect').value;
            let url = `/api/bssids`;
            let params = [];
            if (session_id) params.push(`session_id=${session_id}`);
            if (essid) params.push(`essid=${encodeURIComponent(essid)}`);
            if (params.length > 0) url += '?' + params.join('&');
            let res = await fetch(url);
            let bssids = await res.json();
            let bssidSelect = document.getElementById('bssidSelect');
            bssidSelect.innerHTML = '<option value="">All</option>';
            bssids.forEach(b => {
                let opt = document.createElement('option');
                opt.value = b;
                opt.textContent = b;
                bssidSelect.appendChild(opt);
            });
        }
        async function refreshData() {
            let session_id = document.getElementById('sessionSelect').value;
            let essid = document.getElementById('essidSelect').value;
            let bssid = document.getElementById('bssidSelect').value;
            let dateFrom = document.getElementById('dateFrom').value;
            let dateTo = document.getElementById('dateTo').value;
            let minAlt = document.getElementById('minAlt').value;
            let maxAlt = document.getElementById('maxAlt').value;
            let url = `/api/data`;
            let params = [];
            if (session_id) params.push(`session_id=${session_id}`);
            if (essid && !document.getElementById('essidSelect').disabled) params.push(`essid=${encodeURIComponent(essid)}`);
            if (bssid) params.push(`bssid=${encodeURIComponent(bssid)}`);
            if (dateFrom) params.push(`date_from=${dateFrom}`);
            if (dateTo) params.push(`date_to=${dateTo}`);
            if (minAlt) params.push(`min_alt=${minAlt}`);
            if (maxAlt) params.push(`max_alt=${maxAlt}`);
            if (params.length > 0) url += '?' + params.join('&');
            document.getElementById('statusBadge').textContent = 'Loading...';
            try {
                let res = await fetch(url);
                let data = await res.json();
                plotData(data);
            } catch (e) {
                document.getElementById('statusBadge').textContent = 'Error';
                document.getElementById('status').title = 'Error loading data: ' + e.message;
                console.error(e);
            }
        }
        function clearFilters() {
            document.getElementById('sessionSelect').value = '';
            document.getElementById('essidSelect').value = '';
            document.getElementById('bssidSelect').value = '';
            document.getElementById('minSignal').value = '-100';
            document.getElementById('maxSignal').value = '0';
            document.getElementById('channelFilter').value = '';
            document.getElementById('dateFrom').value = '';
            document.getElementById('dateTo').value = '';
            document.getElementById('minAlt').value = '';
            document.getElementById('maxAlt').value = '';
            refreshData();
        }
        function showDeleteDialog() {
            let session_id = document.getElementById('sessionSelect').value;
            let essid = document.getElementById('essidSelect').value;
            let bssid = document.getElementById('bssidSelect').value;
            let dateFrom = document.getElementById('dateFrom').value;
            let dateTo = document.getElementById('dateTo').value;
            let filters = [];
            if (session_id) filters.push(`Session: ${session_id}`);
            if (essid) filters.push(`ESSID: ${essid}`);
            if (bssid) filters.push(`BSSID: ${bssid}`);
            if (dateFrom) filters.push(`From: ${dateFrom}`);
            if (dateTo) filters.push(`To: ${dateTo}`);
            let filterText = filters.length > 0 ? filters.join(', ') : 'all tracks';
            document.getElementById('deleteModalBody').innerHTML = 
                `Are you sure you want to delete tracks matching: <strong>${filterText}</strong>?<br><br>This action cannot be undone.`;
            document.getElementById('deleteModal').style.display = 'block';
        }
        function closeDeleteDialog() {
            document.getElementById('deleteModal').style.display = 'none';
        }
        async function confirmDelete() {
            let session_id = document.getElementById('sessionSelect').value;
            let essid = document.getElementById('essidSelect').value;
            let bssid = document.getElementById('bssidSelect').value;
            let dateFrom = document.getElementById('dateFrom').value;
            let dateTo = document.getElementById('dateTo').value;
            let deleteData = {};
            if (session_id) deleteData.session_id = session_id;
            if (essid) deleteData.essid = essid;
            if (bssid) deleteData.bssid = bssid;
            if (dateFrom) deleteData.date_from = dateFrom;
            if (dateTo) deleteData.date_to = dateTo;
            try {
                let res = await fetch('/api/delete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(deleteData)
                });
                let result = await res.json();
                if (result.success) {
                    document.getElementById('statusBadge').textContent = `Deleted ${result.deleted}`;
                    document.getElementById('status').title = `Successfully deleted ${result.deleted} tracks`;
                    closeDeleteDialog();
                    await refreshData();
                    await loadSessions();
                    await loadEssids();
                } else {
                    alert('Error deleting tracks.');
                }
            } catch (e) {
                alert('Error deleting tracks: ' + e.message);
            }
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
        document.getElementById('essidSelect').addEventListener('change', async () => {
            await loadBssids();
            await refreshData();
        });
        document.getElementById('bssidSelect').addEventListener('change', refreshData);
        document.getElementById('minSignal').addEventListener('change', refreshData);
        document.getElementById('maxSignal').addEventListener('change', refreshData);
        document.getElementById('channelFilter').addEventListener('change', refreshData);
        document.getElementById('dateFrom').addEventListener('change', refreshData);
        document.getElementById('dateTo').addEventListener('change', refreshData);
        document.getElementById('minAlt').addEventListener('change', refreshData);
        document.getElementById('maxAlt').addEventListener('change', refreshData);
        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') {
                if (e.key === 'Enter' && e.ctrlKey) {
                    e.preventDefault();
                    refreshData();
                }
                return;
            }
            if (e.key === 'f' || e.key === 'F') {
                e.preventDefault();
                toggleAdvanced();
            } else if (e.key === 'r' || e.key === 'R') {
                e.preventDefault();
                refreshData();
            } else if (e.key === 'm' || e.key === 'M') {
                e.preventDefault();
                document.getElementById('displayMode').focus();
            } else if (e.key === 'l' || e.key === 'L') {
                e.preventDefault();
                toggleLabels();
            } else if (e.key === 'Delete' || e.key === 'Del') {
                e.preventDefault();
                showDeleteDialog();
            } else if (e.key === 'Escape') {
                closeDeleteDialog();
            }
        });
        // Close modal when clicking outside
        window.onclick = function(event) {
            let modal = document.getElementById('deleteModal');
            if (event.target === modal) {
                closeDeleteDialog();
            }
        }
        document.getElementById('mapStyle').addEventListener('change', function() {
            if (currentBaseLayer) map.removeLayer(currentBaseLayer);
            if (this.value === 'osm') {
                currentBaseLayer = osmLayer;
            } else {
                currentBaseLayer = satLayer;
            }
            currentBaseLayer.addTo(map);
        });
        // Advanced filters expand/collapse
        function toggleAdvanced() {
            const advancedPanel = document.getElementById('toolbarAdvanced');
            const expandIcon = document.getElementById('expandIcon');
            const expandText = document.getElementById('expandText');
            const isExpanded = advancedPanel.classList.contains('expanded');
            if (isExpanded) {
                advancedPanel.classList.remove('expanded');
                expandIcon.textContent = '▾';
                expandText.textContent = 'Advanced';
            } else {
                advancedPanel.classList.add('expanded');
                expandIcon.textContent = '▴';
                expandText.textContent = 'Hide';
            }
        }
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
            await loadBssids();
            updateLegend();
            await refreshData();
        })();
    </script>
</body>
</html>
    ''')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 