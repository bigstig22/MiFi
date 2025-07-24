# WiFi Handshake Collector and Processor Tool

> Developed for educational and ethical use in RF analysis and cyber projects.

---

## Overview

This tool is designed to assist in the **collection and analysis of WPA2 WiFi handshakes**. It supports both **manual and automated workflows** and is ideal for research or academic demonstrations involving wireless network security.

The tool separates collection and processing into modular stages to improve usability and performance—especially on systems with limited resources.

---

## Modes of Operation

| Mode         | Description                                                                 |
|--------------|-----------------------------------------------------------------------------|
| `collect-*`  | Scans for nearby access points (APs) and can optionally target specific networks for a deauthentication capture. |
| `process-*`  | Processes stored EAPOL PCAPs to isolate hashes and analyze handshake data.  |
| `full-*`     | Runs both `collect` and `process` phases in sequence.                       |
| `*-manual`   | Manual selection of targets and input files. Requires terminal interaction. |
| `*-auto`     | Automatically captures and processes all WPA2 networks and PCAPs found.     |
| `target`     | Waits for a specific ESSID to appear and captures its handshake.            |
| `config`     | Prepares interface for **headless** operation (non-interactive). 

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

#### **Full Pipeline (Collect + Process)**
```bash
sudo ./mifi --mode full-auto
```

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