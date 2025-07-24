# MiFi: WiFi Signal Tracking & Cracking Toolkit

This toolkit provides advanced WiFi handshake collection, signal mapping, and web-based visualization for site surveys and security testing. It consists of a CLI tool (`mifi`), a persistent web dashboard (`wifi_dashboard.py`), and helper scripts for WPA cracking (`john/`, `hc/`).

---

## Features
- **WiFi handshake collection and processing** (with aircrack-ng, John the Ripper, Hashcat)
- **Signal mapping with GPS** for site surveys and heatmaps
- **Persistent web dashboard** for interactive map visualization, filtering, and analysis
- **Modern, filterable UI** with satellite/OSM map options, session/ESSID filtering, and value filters
- **Helper scripts for advanced WPA cracking** (John the Ripper, Hashcat)

---

## Requirements

### Hardware
- WiFi card capable of monitor mode
- USB GPS module (optional, for mapping)
- Computer with USB ports

### Software (Linux/Debian/Ubuntu)
```bash
sudo apt update
sudo apt install aircrack-ng john hashcat python3 python3-pip
```

### Python Dependencies
```bash
pip3 install -r requirements.txt
```

---

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/MiFi.git
   cd MiFi
   ```
2. **Install system dependencies** (see above)
3. **Install Python dependencies**
4. **(Optional) Build the executable:**
   ```bash
   pip3 install pyinstaller
   pyinstaller --onefile --name mifi mifi.py
   # The executable will be in dist/mifi
   ```

---

## Usage

### 1. **Collecting Data (CLI)**

#### **Basic Scan/Collection**
```bash
sudo ./mifi --mode collect-manual
```

#### **Automated Collection**
```bash
sudo ./mifi --mode collect-auto
```

#### **Targeted Handshake Capture**
```bash
sudo ./mifi --mode target --TID "MyNetwork"
```

#### **Mapping Mode (Signal Survey with GPS)**
```bash
sudo ./mifi --mode map -MS 10 -MSD 5 --gps-port /dev/ttyUSB0
```

#### **Full Pipeline (Collect + Process)**
```bash
sudo ./mifi --mode full-auto
```

#### **Start the Web Dashboard**
```bash
./mifi --mode dashboard
# or
python3 wifi_dashboard.py
```

#### **Access the Dashboard**
- Open a browser and go to: `http://localhost:5000`
- Or, from another computer on the network: `http://<your-server-ip>:5000`

---

## WPA Cracking Helpers

### **John the Ripper (john/ directory)**

- **Purpose:** Crack WPA handshakes using John the Ripper.
- **Files:**
  - `john/*.john`, `john/*_eapol.john`: WPA handshake hashes for John.
  - `john/results/`: Cracked password outputs.
  - `john/archive/`: For archiving processed files.
  - `john/jtr.py`: Automates brute-force and dictionary attacks on `.john` files.

#### **Usage**
```bash
cd /MiFi/john
python3 jtr.py
```
- Finds all `.john` files, runs John the Ripper, and outputs results to `results/`.

### **Hashcat (hc/ directory)**

- **Purpose:** Crack WPA handshakes using Hashcat.
- **Files:**
  - `hc/*.22000`: WPA handshake hashes for Hashcat.
  - `hc/archive/`: For archiving processed files.
  - `hc/hash_cat.py`: Automates a series of Hashcat attacks on `.22000` files.

#### **Usage**
```bash
cd /MiFi/hc
python3 hash_cat.py
```
- Finds the first `.22000` file, downloads `rockyou.txt` if missing, runs a series of Hashcat attacks, and archives processed files.

---

## File Structure
```
/MiFi/
├── mifi.py              # Main CLI tool (builds to ./mifi)
├── wifi_dashboard.py    # Persistent web dashboard (Flask)
├── requirements.txt     # Python dependencies
├── networks.db          # SQLite database (auto-created)
├── tracking/            # Output directory for exports
├── logs/                # Application logs
├── john/                # John the Ripper WPA cracking helpers
│   ├── jtr.py           # John automation script
│   ├── *.john           # WPA handshake hashes
│   ├── results/         # Cracked password outputs
│   └── archive/         # Archive for processed files
├── hc/                  # Hashcat WPA cracking helpers
│   ├── hash_cat.py      # Hashcat automation script
│   ├── *.22000          # WPA handshake hashes
│   └── archive/         # Archive for processed files
```

---

## Troubleshooting

- **Database permissions:** If you run `mifi` with `sudo`, the database (`networks.db`) will be owned by root. After running, fix permissions so the web dashboard can access it:
  ```bash
  sudo chown $USER:$USER /MiFi/networks.db
  ```
- **No data in dashboard:** Make sure you have run mapping mode at least once and the database is not empty.
- **GPS not detected:** Check your USB port and permissions. Try adding your user to the `dialout` group.
- **Monitor mode issues:** Ensure your WiFi card supports monitor mode and is not blocked by rfkill.

---

## Legal Disclaimer
This tool is provided for educational and authorized security testing purposes only. Unauthorized use to access networks or data without permission is illegal and punishable by law. The author assumes no responsibility for any misuse or damage caused by this software. Use responsibly and ethically.

---

## Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

## License
This software is provided as-is for educational purposes. Please ensure compliance with local laws and regulations when using this tool. 