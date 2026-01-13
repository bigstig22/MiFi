# MiFi: WiFi Signal Tracking & Cracking Toolkit

A comprehensive toolkit for WiFi handshake collection, signal mapping with GPS, and web-based visualization. MiFi provides both CLI tools for automated handshake capture and a modern web dashboard for interactive analysis of WiFi signal data.

---

## 🚀 Quick Start

### Automated Setup (Recommended)

```bash
git clone https://github.com/bigstig22/MiFi.git
cd MiFi
./start.sh
```

The setup script will:
- Create all necessary directories (logs, collection, archive, tracking, john, hc, tak, config)
- Create database file (`config/networks.db`)
- Install all system dependencies (aircrack-ng, john, hashcat, gpsd, etc.)
- Install Python dependencies from `config/requirements.txt`
- Download `config/rockyou.txt` wordlist
- Create default `config/config.ini` configuration file
- Configure GPS services
- Verify installation

**Note:** The script will prompt for sudo when needed for system package installation.

**Git Repository:** This repository tracks only source code and documentation. Runtime files (databases, captured handshakes, certificates, etc.) are excluded via `.gitignore` and will be created automatically by `start.sh`.

### Manual Setup

If you prefer manual installation, see the [Manual Installation](#manual-installation) section below.

---

## 📋 Features

- **WiFi Handshake Collection**: Automated WPA2 handshake capture with deauth attacks
- **Signal Mapping with GPS**: Real-time WiFi signal strength mapping with GPS coordinates
- **Web Dashboard**: Interactive map visualization with filtering, color coding, and analysis tools
- **TAK Server Integration**: Native CoT message support for TAK Server 5.6 (no plugin required)
- **Hash Processing**: Automatic conversion to Hashcat (.22000) and John the Ripper (.john) formats
- **Wordlist Cracking**: Integrated aircrack-ng wordlist attacks
- **Helper Scripts**: Automated cracking workflows for Hashcat and John the Ripper

---

## 🎯 Modes Overview

MiFi operates in several distinct modes, each designed for specific use cases:

### Collection Modes
- **`collect-manual`**: Interactive mode for selecting and capturing specific networks
- **`collect-auto`**: Automated capture of all detected WPA2 networks
- **`target`**: Persistent scanning and capture for a specific ESSID

### Processing Modes
- **`process-manual`**: Interactive processing of captured handshakes
- **`process-auto`**: Batch processing of all captured handshakes

### Combined Modes
- **`full-manual`**: Collection followed by manual processing
- **`full-auto`**: Fully automated collection and processing pipeline

### Utility Modes
- **`config`**: Configure WiFi interface for headless operation
- **`map`**: GPS-enabled signal mapping for site surveys
- **`dashboard`**: Start the web visualization dashboard

---

## 📖 Detailed Usage

### Collection Modes

#### Manual Collection (`collect-manual`)
Interactive mode where you select networks to target:

```bash
sudo python3 mifi.py --mode collect-manual
```

**Features:**
- Scans for nearby networks
- Displays network table with ESSID, BSSID, Channel, Power, Encryption
- Prompts for network selection
- Allows rescanning with `rs` command
- Quit with `q` command

**Options:**
- `-IS, --initial-scan <seconds>`: Initial scan duration (default: 30)
- `-TS, --target-scan <seconds>`: Handshake monitoring time (default: 60)
- `-p, --packets <count>`: Number of deauth packets (default: 100)

**Example:**
```bash
sudo python3 mifi.py --mode collect-manual -IS 45 -TS 90 -p 150
```

#### Automated Collection (`collect-auto`)
Automatically captures handshakes from all detected WPA2 networks:

```bash
sudo python3 mifi.py --mode collect-auto
```

**Features:**
- Scans once, then attempts capture on all WPA2 networks
- No user interaction required
- Can be combined with `-H` for headless background operation

**Options:** Same as manual mode

**Example with headless:**
```bash
sudo python3 mifi.py --mode collect-auto -H -IS 10 -TS 30
```

#### Targeted Collection (`target`)
Continuously scans until a specific network is found, then captures its handshake:

```bash
sudo python3 mifi.py --mode target --TID "[TARGET ID]"
```

**Features:**
- Persistent scanning until target network appears
- Multiple capture attempts if handshake fails
- Ideal for networks that appear intermittently

**Options:**
- `--TID, --target-id <ESSID>`: **Required** - Target network ESSID
- `-TSA, --target-search-attempts <count>`: Scan attempts before giving up (default: 25)
- `-TA, --target-attempts <count>`: Capture attempts per detection (default: 10)
- `-IS, --initial-scan <seconds>`: Scan duration per attempt (default: 30)
- `-TS, --target-scan <seconds>`: Handshake monitoring time (default: 60)
- `-p, --packets <count>`: Deauth packets per attempt (default: 100)

**Example:**
```bash
sudo python3 mifi.py --mode target --TID "CorporateWiFi" -TSA 50 -TA 15
```

### Processing Modes

#### Manual Processing (`process-manual`)
Interactive processing of captured handshakes:

```bash
python3 mifi.py --mode process-manual
```

**Features:**
- Lists all .cap files in collection directory
- Prompts for file selection
- Choose processing method (Aircrack, JTR, Hashcat, or All)
- Archives processed files automatically

**Options:**
- `-WL, --word-list <path>`: Custom wordlist path (default: config/rockyou.txt)

**Example:**
```bash
python3 mifi.py --mode process-manual -WL /path/to/custom_wordlist.txt
```

#### Automated Processing (`process-auto`)
Batch processes all captured handshakes:

```bash
python3 mifi.py --mode process-auto
```

**Features:**
- Processes all .cap files in collection directory
- Runs all processing methods (JTR, Hashcat, Aircrack)
- Archives files after processing
- No user interaction required

**Options:** Same as manual processing

### Combined Modes

#### Full Manual (`full-manual`)
Runs collection in manual mode, then processing in manual mode:

```bash
sudo python3 mifi.py --mode full-manual
```

#### Full Auto (`full-auto`)
Fully automated collection and processing:

```bash
sudo python3 mifi.py --mode full-auto
```

**Options:** Combines all collection and processing options

### Mapping Mode (`map`)
GPS-enabled signal strength mapping for site surveys:

```bash
sudo python3 mifi.py --mode map
```

**Features:**
- Scans for networks at multiple GPS locations
- Records signal strength with GPS coordinates
- **TAK Server Integration**: Sends CoT messages to TAK Server 5.6 (use `-tak` flag or enable in `config/config.ini`)
- Stores data in database for dashboard visualization
- Waits for new GPS fixes between scans

**Options:**
- `-MS, --map-scans <count>`: Total number of scans (default: 25)
- `-MSD, --map-scan-duration <seconds>`: Duration per scan (default: 1)
- `-GPS, --gps-port <path>`: GPS device path (default: /dev/ttyUSB0)
- `-GLA, --gps-lock-attempts <count>`: GPS fix attempts before exit (default: 20)
- `-GLW, --gps-lock-wait <seconds>`: Wait time between GPS attempts (default: 5)

**Example:**
```bash
sudo python3 mifi.py --mode map -MS 50 -MSD 3 -GPS /dev/ttyUSB1
```

**GPS Setup:**
Before using map mode, ensure gpsd is running:
```bash
sudo gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock
# Or configure /etc/default/gpsd and start service:
sudo systemctl start gpsd
```

### Configuration Mode (`config`)
Configures WiFi interface for headless operation:

```bash
sudo python3 mifi.py --mode config
```

**Features:**
- Detects available wireless interfaces
- Enables monitor mode automatically
- Saves interface to config/config.ini
- Required before using `-H` headless mode

### Dashboard Mode (`dashboard`)
Starts the web visualization dashboard:

```bash
python3 mifi.py --mode dashboard
```

**Features:**
- Interactive map visualization
- Filter by session, ESSID, BSSID, signal strength, channel, date, altitude
- Multiple visualization modes: Markers, Heatmap, Gradient
- Color legend and customizable color thresholds
- Toggleable labels
- Delete tracks functionality

**Access:**
- Local: http://localhost:5000
- Network: http://<your-ip>:5000

---

## 🔧 Command-Line Options

### Global Options

- `--mode <mode>`: **Required** - Operation mode (see modes above)
- `-v, --verbose`: Enable verbose output (creates large log files)
- `-H, --headless`: Run in background (only with `*-auto` modes)
- `-h, --help`: Show help message
- `--version`: Show version information

### Shared Variables (Collection & Target Modes)

- `-IS, --initial-scan <seconds>`: Initial spectrum sweep time (default: 30)
- `-TS, --target-scan <seconds>`: Handshake monitoring time (default: 60)
- `-p, --packets <count>`: Deauth packet count (default: 100)

### Process Mode Options

- `-WL, --word-list <path>`: Custom wordlist path (default: config/rockyou.txt)

### Target Mode Options

- `--TID, --target-id <ESSID>`: **Required** - Target ESSID
- `-TSA, --target-search-attempts <count>`: Scan attempts (default: 25)
- `-TA, --target-attempts <count>`: Capture attempts (default: 10)

### Map Mode Options

- `-MS, --map-scans <count>`: Total scans (default: 25)
- `-MSD, --map-scan-duration <seconds>`: Scan duration (default: 1)
- `-GPS, --gps-port <path>`: GPS device path (default: /dev/ttyUSB0)
- `-GLA, --gps-lock-attempts <count>`: GPS fix attempts (default: 20)
- `-tak`: Enable TAK Server integration (or configure in `config/config.ini`)
- `--tak-host <host>`: TAK Server hostname/IP (overrides `config/config.ini`)
- `--tak-port <port>`: TAK Server port (default: 8087)
- `--tak-protocol <tcp|udp>`: Protocol (default: tcp)
- `--tak-cert <path>`: Client certificate file
- `--tak-key <path>`: Private key file
- `--tak-ca <path>`: CA certificate file
- `-GLW, --gps-lock-wait <seconds>`: Wait between attempts (default: 5)

---

## 📁 File Structure

```
MiFi/
├── mifi.py                 # Main CLI tool
├── mifi_dashboard.py       # Web dashboard server
├── start.sh                # Automated setup script
├── README.md               # This file
│
├── config/                 # Configuration and data files
│   ├── requirements.txt    # Python dependencies (tracked in git)
│   ├── config.ini          # Interface configuration (auto-created, not in git)
│   ├── networks.db         # SQLite database (auto-created, not in git)
│   └── rockyou.txt        # Wordlist (downloaded by start.sh, not in git)
│
├── logs/                   # Application logs (not in git)
│   └── YYYY-MM-DD_HH-MM-SS.log
│
├── collection/             # Captured handshakes (.cap files, not in git)
│   └── ESSID--BSSID--CH--TIMESTAMP-01.cap
│
├── archive/                # Processed files archive (not in git)
│   └── pcap/               # Archived .cap files
│
├── tracking/               # Exported tracking data (not in git, created by start.sh)
│   ├── tracking_data_*.json
│   └── tracking_data_*.csv
│
├── john/                   # John the Ripper processing
│   ├── jtr.py              # John automation script (tracked in git)
│   ├── *.john              # WPA handshake hashes (not in git)
│   ├── *_eapol.john        # EAPOL-specific hashes (not in git)
│   ├── *_pmkid.john        # PMKID-specific hashes (not in git)
│   ├── results/            # Cracked password outputs (not in git)
│   └── archive/            # Processed file archive (not in git)
│
├── hc/                     # Hashcat processing
│   ├── hash_cat.py         # Hashcat automation script (tracked in git)
│   ├── *.22000             # Hashcat format hashes (not in git)
│   └── archive/            # Processed file archive (not in git)
│
└── tak/                    # TAK Server integration
    ├── nginx_tak_stream.conf  # Nginx config (tracked in git)
    ├── TAK_SERVER_SETUP.md    # Setup documentation (tracked in git)
    ├── *.p12, *.pem        # Certificates (not in git - user-specific)
    └── *.crt, *.key        # Additional certs (not in git)
```

### Files Tracked in Git

The repository tracks only source code and documentation:
- Python scripts: `mifi.py`, `mifi_dashboard.py`
- Helper scripts: `hc/hash_cat.py`, `john/jtr.py`
- Configuration template: `config/requirements.txt`
- Documentation: `README.md`, `tak/TAK_SERVER_SETUP.md`
- Setup script: `start.sh`
- Nginx config: `tak/nginx_tak_stream.conf`

### Files NOT Tracked in Git

Runtime files and user-specific data are excluded:
- `__pycache__/` - Python cache files
- `collection/` - Captured handshake files (.cap)
- `*.john` - John the Ripper hash files
- `config/networks.db` - SQLite database
- `config/config.ini` - User configuration
- `config/rockyou.txt` - Wordlist (large file)
- `config/.mifi_dashboard_state.json` - Dashboard state
- `tak/*.pem`, `tak/*.p12` - TAK certificates (user-specific)
- `logs/`, `archive/`, `tracking/` - Runtime directories

All excluded files are automatically created by `start.sh` when setting up the environment.

---

## 🛠️ Manual Installation

### System Requirements

**Hardware:**
- WiFi adapter capable of monitor mode
- USB GPS module (optional, for mapping mode)
- Linux system (Debian/Ubuntu recommended)

**Software:**
- Python 3.6+
- aircrack-ng suite
- John the Ripper (Jumbo version for wpapcap2john)
- Hashcat
- gpsd and gpsd-clients (for GPS mapping)

### Installation - ./start.sh or Step-by-Step Below 

#### 1. Install System Packages

**Debian/Ubuntu:**
```bash
sudo apt update
sudo apt install -y aircrack-ng john hashcat python3 python3-pip gpsd gpsd-clients iw wireless-tools
```

**Fedora/RHEL/CentOS:**
```bash
sudo dnf install -y aircrack-ng john hashcat python3 python3-pip gpsd gpsd-clients iw wireless-tools
```

**Arch Linux:**
```bash
sudo pacman -S aircrack-ng john hashcat python python-pip gpsd iw wireless_tools
```

#### 2. Install Python Dependencies

```bash
pip3 install --user -r config/requirements.txt
```

Or system-wide:
```bash
sudo pip3 install -r config/requirements.txt
```

#### 3. Download Wordlist

```bash
# Option 1: Download from GitHub
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O config/rockyou.txt

# Option 2: Extract from system location
gunzip -c /usr/share/wordlists/rockyou.txt.gz > config/rockyou.txt
```

#### 4. Create Directories

```bash
mkdir -p logs collection archive/pcap tracking john/results john/archive hc/archive tak config
```

**Note:** The `tracking/` folder is required for exporting tracking data. It is automatically created by `start.sh`.

#### 5. Configure GPS (Optional)

```bash
# Start gpsd with your GPS device
sudo gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock

# Or configure service
sudo nano /etc/default/gpsd
# Add: DEVICES="/dev/ttyUSB0"
# Add: GPSD_OPTIONS="-n"
sudo systemctl start gpsd
sudo systemctl enable gpsd
```

---

## 🎮 Usage Examples

### Basic Workflow

1. **Configure interface:**
   ```bash
   sudo python3 mifi.py --mode config
   ```

2. **Collect handshakes:**
   ```bash
   sudo python3 mifi.py --mode collect-manual
   ```

3. **Process handshakes:**
   ```bash
   python3 mifi.py --mode process-auto
   ```

4. **View results:**
   - Check `john/results/` for John the Ripper outputs
   - Check `hc/` for Hashcat outputs
   - Review logs in `logs/`

### Advanced Workflows

**Automated collection and processing:**
```bash
sudo python3 mifi.py --mode full-auto -H -IS 30 -TS 60 -WL /path/to/wordlist.txt
```

**Targeted network capture:**
```bash
sudo python3 mifi.py --mode target --TID "TargetNetwork" -TSA 50 -TA 20
```

**GPS signal mapping:**
```bash
sudo python3 mifi.py --mode map -MS 100 -MSD 2 -GPS /dev/ttyUSB0
```

**Start dashboard:**
```bash
python3 mifi.py --mode dashboard
# Access at http://localhost:5000
```

---

## 🌐 Web Dashboard

The web dashboard provides interactive visualization of collected WiFi signal data.

### Features

- **Interactive Maps**: OpenStreetMap and Satellite views
- **Visualization Modes**: Markers, Heatmap, and Gradient
- **Advanced Filtering**: Session, ESSID, BSSID, Signal, Channel, Date, Altitude
- **Color Customization**: Edit color thresholds for signal strength
- **Toggleable Labels**: Show/hide ESSID labels on markers
- **Color Legend**: Visual reference for signal strength colors
- **Track Management**: Delete tracks matching filters

### Keyboard Shortcuts

- `F` - Toggle filters panel
- `R` - Refresh data
- `M` - Focus display mode selector
- `L` - Toggle labels
- `Del` - Open delete dialog
- `Esc` - Close modal

### Access

```bash
python3 mifi.py --mode dashboard
```

Then open: http://localhost:5000

---

## 🔨 Helper Scripts

### John the Ripper Automation (`john/jtr.py`)

Automates John the Ripper attacks on processed handshakes:

```bash
cd john
python3 jtr.py
```

**Features:**
- Finds all `.john` files (not tracked in git)
- Runs dictionary and brute-force attacks
- Outputs results to `results/` directory
- Archives processed files

### Hashcat Automation (`hc/hash_cat.py`)

Automates Hashcat attacks on processed handshakes:

```bash
cd hc
python3 hash_cat.py
```

**Features:**
- Finds `.22000` files (not tracked in git)
- Downloads config/rockyou.txt if missing
- Runs multiple attack modes
- Archives processed files

---

## 🐛 Troubleshooting

### Common Issues

#### Database Permissions
If you run `mifi` with `sudo`, the database may be owned by root:
```bash
sudo chown $USER:$USER config/networks.db
```

#### GPS Not Detected
1. Check USB connection
2. Verify device path: `ls -l /dev/ttyUSB*`
3. Check permissions: `sudo usermod -aG dialout $USER` (logout/login)
4. Ensure gpsd is running: `sudo systemctl status gpsd`
5. Test GPS: `cgps -s` or `gpsmon`

#### Monitor Mode Issues
1. Check interface: `iwconfig` or `iw dev`
2. Check rfkill: `sudo rfkill unblock wifi`
3. Verify driver support: `iw phy`
4. Try manual monitor mode: `sudo airmon-ng start wlan0`

#### No Data in Dashboard
1. Ensure you've run map mode at least once
2. Check database exists and has data: `sqlite3 config/networks.db "SELECT COUNT(*) FROM signal_tracking;"`
3. Verify database permissions

#### Missing Dependencies
Run the setup script again:
```bash
./start.sh
```

Or manually install missing packages based on error messages.

#### Interface Not Found
1. Run config mode: `sudo python3 mifi.py --mode config`
2. Manually edit `config/config.ini` with your interface name
3. Ensure interface is in monitor mode

---

## ⚖️ Legal Disclaimer

**IMPORTANT:** This tool is provided for **educational and authorized security testing purposes only**. 

- Unauthorized access to networks or data is **illegal** and punishable by law
- Only use this tool on networks you own or have explicit written permission to test
- The authors assume **no responsibility** for misuse or damage caused by this software
- Users are solely responsible for compliance with local laws and regulations
- Use responsibly and ethically

---

## 📝 Requirements Summary

### System Packages
- `aircrack-ng` (airodump-ng, aireplay-ng, aircrack-ng)
- `john` (John the Ripper Jumbo)
- `hashcat`
- `python3` and `python3-pip`
- `gpsd` and `gpsd-clients` (for GPS mapping)
- `iw` and `wireless-tools`

### Python Packages
- `tabulate>=0.9.0`
- `pyserial>=3.5`
- `gps3>=0.33.3`
- `flask>=2.0.0`
- `flask-cors>=4.0.0`

### Files
- `config/rockyou.txt` wordlist (auto-downloaded by start.sh)

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This software is provided as-is for educational purposes. Please ensure compliance with local laws and regulations when using this tool.

---

## 🔗 Additional Resources

- [Aircrack-ng Documentation](https://www.aircrack-ng.org/)
- [John the Ripper Documentation](https://www.openwall.com/john/)
- [Hashcat Documentation](https://hashcat.net/hashcat/)
- [GPSD Documentation](https://gpsd.gitlab.io/gpsd/)

---

## 📧 Support

For issues, questions, or contributions, please open an issue on the GitHub repository.

---

**Version:** 0.1.1  
**Last Updated:** 2025
