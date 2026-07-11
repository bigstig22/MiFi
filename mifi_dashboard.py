#!/usr/bin/env python3
"""
MiFi Dashboard & Control Panel - Consolidated web-based GUI
Provides real-time status monitoring, log streaming, operation controls, and data visualization
"""

import os
import sys
import subprocess
import threading
import queue
import json
import time
import signal
import re
import glob
import configparser
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, render_template_string, jsonify, request, Response, stream_with_context, send_from_directory
from flask_cors import CORS

# Import platform-specific modules
if sys.platform != 'win32':
    import fcntl
    import pty
    import termios
    import struct
    import socket

app = Flask(__name__)
CORS(app)

DB_PATH = os.path.join(os.path.dirname(__file__), 'config', 'networks.db')
DASHBOARD_DB_PATH = DB_PATH

print("Using database at:", DB_PATH)

# Global debug flag (can be set via environment variable or config)
DEBUG_MODE = os.getenv('MIFI_DEBUG', 'false').lower() == 'true'

def debug_print(msg, prefix='[DEBUG]', indent=0):
    """
    Print debug message only if debug mode is enabled.
    This is for detailed debugging output that should not appear in normal operation.
    """
    if DEBUG_MODE:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        indent_str = "    " * indent
        prefix_str = f"{prefix} " if prefix else ""
        final_msg = f"{timestamp} {indent_str}{prefix_str}{msg}"
        print(final_msg, flush=True)

# Global state for control panel
mifi_process = None
mifi_log_queue = queue.Queue(maxsize=500)
prompt_queue = queue.Queue()  # For interactive prompts
prompt_responses = {}  # Store responses to prompts
tak_password_queue = queue.Queue()  # For TAK certificate password
interface_prompt_queue = queue.Queue()  # For interface name prompt
interface_prompt_responses = {}  # Store interface prompt responses
mifi_status = {
    'running': False,
    'mode': None,
    'pid': None,
    'start_time': None,
    'gps_status': 'disabled',  # Always start as disabled
    'gps_enabled': False,  # GPS toggle state
    'interface_status': 'unknown',
    'tak_status': 'disabled',  # Always start as disabled
    'tak_connected': False
}

# Shared MiFi service instance (uses mifi.py's native services)
# All GPS and TAK state is managed in mifi_service - dashboard only visualizes
mifi_service = None
mifi_service_lock = threading.Lock()

# Mode mapping
MODE_MAP = {
    'collect-manual': 'collect-manual',
    'collect-auto': 'collect-auto',
    'process-manual': 'process-manual',
    'process-auto': 'process-auto',
    'full-manual': 'full-manual',
    'full-auto': 'full-auto',
    'target': 'target',
    'map': 'map',
    'config': 'config'
}

LOG_DIR = os.path.join(os.path.dirname(__file__), 'logs')
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# State persistence file to survive Flask reloads
STATE_FILE = os.path.join(os.path.dirname(__file__), 'config', '.mifi_dashboard_state.json')

def check_directories():
    """Check if all required directories exist"""
    required_dirs = [
        "logs",
        "collection",
        "archive/pcap",
        "tracking",
        "john/results",
        "john/archive",
        "hc/archive",
        "tak"
    ]
    
    base_dirs = ["archive", "john", "hc"]
    missing_dirs = []
    
    # Check base directories
    for base_dir in base_dirs:
        if not os.path.exists(base_dir):
            missing_dirs.append(base_dir)
    
    # Check all required directories
    for dir_path in required_dirs:
        if not os.path.exists(dir_path):
            missing_dirs.append(dir_path)
    
    return {
        'all_exist': len(missing_dirs) == 0,
        'missing': missing_dirs
    }

def save_state():
    """Save current state to file for persistence across Flask reloads"""
    try:
        state_to_save = {
            'gps_status': mifi_status.get('gps_status', 'disabled'),
            'gps_enabled': mifi_status.get('gps_enabled', False),
            'tak_status': mifi_status.get('tak_status', 'disabled'),
            'tak_connected': mifi_status.get('tak_connected', False),
        }
        with open(STATE_FILE, 'w') as f:
            json.dump(state_to_save, f)
        # State saved (debug output removed)
    except Exception as e:
        print(f"[WARNING] Failed to save state: {e}")

def load_state():
    """Load state from file to restore after Flask reloads and page refreshes"""
    global mifi_status
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, 'r') as f:
                saved_state = json.load(f)
            # Restore GPS status
            if 'gps_status' in saved_state:
                mifi_status['gps_status'] = saved_state['gps_status']
            if 'gps_enabled' in saved_state:
                mifi_status['gps_enabled'] = saved_state['gps_enabled']
            # Restore TAK status (persist across page refreshes)
            # But we'll verify the actual connection in initialize_system()
            if 'tak_status' in saved_state:
                mifi_status['tak_status'] = saved_state['tak_status']
            if 'tak_connected' in saved_state:
                mifi_status['tak_connected'] = saved_state['tak_connected']
            # State loaded (debug output removed)
    except Exception as e:
        print(f"[WARNING] Failed to load state: {e}")

def initialize_system():
    """Initialize system and check directories"""
    global mifi_service
    
    # Initialize shared MiFi service instance (config is loaded in __init__)
    if mifi_service is None:
        try:
            from mifi import wifi_cracker
            mifi_service = wifi_cracker()
            mifi_service.initial_config()
            mifi_service.debug = DEBUG_MODE
            
            # Set up GPS status callback for dashboard visualization
            def gps_status_update(status):
                """Callback from mifi.py GPS polling to update dashboard status"""
                global mifi_status
                mifi_status['gps_status'] = status
                mifi_status['gps_enabled'] = (status != 'disabled')
                save_state()
            
            mifi_service.gps_status_callback = gps_status_update
        except Exception as e:
            print(f"[ERROR] Failed to initialize MiFi service: {e}")
            import traceback
            traceback.print_exc()
    
    # Load persisted state first - restore status indicators on page refresh
    load_state()
    
    # Only reset to disabled on FIRST startup (when state file doesn't exist)
    if not os.path.exists(STATE_FILE):
        # First startup - reset to disabled
        mifi_status['gps_enabled'] = False
        mifi_status['gps_status'] = 'disabled'
        mifi_status['tak_status'] = 'disabled'
        mifi_status['tak_connected'] = False
        save_state()
    else:
        # State file exists - check if services are still active and restore state
        # GPS: Check if GPS polling thread is still running
        if mifi_service and mifi_service.gps_thread and mifi_service.gps_thread.is_alive():
            # GPS is still running - restore enabled state
            if hasattr(mifi_service, 'gps_status'):
                mifi_status['gps_status'] = mifi_service.gps_status
                mifi_status['gps_enabled'] = True
        # TAK: Check if TAK connection is still active
        if mifi_service and mifi_service.tak_connected:
            try:
                # Check if socket is actually connected
                socket_alive = (mifi_service.tak_socket and 
                               hasattr(mifi_service.tak_socket, 'fileno') and 
                               mifi_service.tak_socket.fileno() != -1)
                if socket_alive:
                    mifi_status['tak_status'] = 'connected'
                    mifi_status['tak_connected'] = True
                else:
                    mifi_status['tak_status'] = 'disabled'
                    mifi_status['tak_connected'] = False
            except:
                # Socket check failed - not connected
                mifi_status['tak_status'] = 'disabled'
                mifi_status['tak_connected'] = False
    
    # Save the state
    save_state()
    
    dir_check = check_directories()
    
    if dir_check['all_exist']:
        mifi_status['initialization_status'] = 'ready'
        mifi_status['initialization_message'] = 'System ready for operations'
        return True
    else:
        mifi_status['initialization_status'] = 'error'
        missing_str = ', '.join(dir_check['missing'])
        mifi_status['initialization_message'] = f'Missing directories: {missing_str}. Run start.sh to create them.'
        return False

def parse_log_line(line):
    """Parse log line to extract timestamp, prefix, and message"""
    timestamp_match = re.match(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
    if timestamp_match:
        timestamp = timestamp_match.group(1)
        rest = line[len(timestamp):].strip()
        
        prefix_match = re.match(r'^(\[.*?\])', rest)
        if prefix_match:
            prefix = prefix_match.group(1)
            message = rest[len(prefix):].strip()
            
            level_map = {
                '[!]': 'error', '[X]': 'error', '[✓]': 'success', '[+]': 'success',
                '[•]': 'info', '[*]': 'info', '[→]': 'info', '[←]': 'info',
                '[▲]': 'info', '[-]': 'warning'
            }
            level = level_map.get(prefix, 'info')
            
            return {
                'timestamp': timestamp,
                'prefix': prefix,
                'message': message,
                'level': level,
                'raw': line
            }
    
    return {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'prefix': '',
        'message': line.strip(),
        'level': 'info',
        'raw': line
    }

def check_gps_status():
    """Check GPS status - returns detailed status from mifi_service"""
    if mifi_service:
        if mifi_service.gps_lock.acquire(blocking=True, timeout=0.1):
            try:
                if mifi_service.gps_thread and mifi_service.gps_thread.is_alive():
                    return getattr(mifi_service, 'gps_status', 'disabled')
            finally:
                mifi_service.gps_lock.release()
    return 'disabled'
    
    try:
        try:
            # Import gps3 the same way as mifi.py does
            from gps3 import gps3
        except ImportError:
            return 'no_modules'
        
        # Check for USB GPS devices using glob (more reliable than ls with wildcards)
        usb_devices = []
        try:
            # Use glob to find USB serial devices
            usb_devices = glob.glob('/dev/ttyUSB*') + glob.glob('/dev/ttyACM*')
            # Filter out empty strings
            usb_devices = [d for d in usb_devices if d and os.path.exists(d)]
        except Exception as e:
            pass
        
        if not usb_devices:
            # No USB GPS devices found (debug output removed)
            return 'no_device'
        
        # Found USB GPS devices (debug output removed)
        
        result = subprocess.run(['pgrep', '-f', 'gpsd'], capture_output=True, timeout=2)
        if result.returncode != 0:
            # gpsd is not running (debug output removed)
            return 'no_device'
        
        # gpsd is running (debug output removed)
        
        try:
            # For status check, just verify gpsd is accessible
            # The continuous polling thread will do the actual GPS data reading
            # This is a quick non-blocking check
            gps_socket = gps3.GPSDSocket()
            
            try:
                # Try to connect to gpsd (quick check)
                gps_socket.connect()
                gps_socket.watch()
                # If we can connect, GPS is at least searching
                # The polling thread will update to 'locked' when it gets a fix
                gps_socket.close()
                # GPS connection successful (debug output removed)
                return 'searching'  # Return searching - polling thread will update to locked/no_data
            except Exception as e:
                # GPS connection error (debug output removed)
                try:
                    gps_socket.close()
                except:
                    pass
                return 'no_data'  # Can't connect to gpsd
        except Exception as e:
            # GPS check exception (debug output removed)
            import traceback
            traceback.print_exc()
            return 'no_data'
    except Exception as e:
        # GPS check outer exception (debug output removed)
        import traceback
        traceback.print_exc()
        return 'unknown'

def start_gps_polling_thread():
    """Start continuous GPS polling thread - similar to mifi.py's start_gps_polling"""
    global gps_service_thread, gps_polling_stop
    
    def gps_polling_loop():
        """Continuous GPS polling loop - reads GPS data continuously like mifi.py"""
        # GPS polling thread started (debug output removed)
        
        try:
            from gps3 import gps3
        except ImportError:
            print("[ERROR] gps3 module not available")
            return
        
        gps_socket = None
        data_stream = None
        
        try:
            # Connect to gpsd
            gps_socket = gps3.GPSDSocket()
            gps_socket.connect()
            gps_socket.watch()
            data_stream = gps3.DataStream()
            # Connected to gpsd successfully (debug output removed)
            time.sleep(0.5)  # Give gpsd a moment to start sending data
            
            # Continuously read GPS data as it arrives (like mifi.py)
            # Use a while loop with timeout instead of for loop to handle blocking better
            last_status_update = time.time()
            no_data_count = 0
            max_no_data = 20  # Update status after 20 failed reads
            
            # Set socket to non-blocking with timeout
            if hasattr(gps_socket, 'socket') and gps_socket.socket:
                gps_socket.socket.settimeout(2.0)  # 2 second timeout
            
            while not gps_polling_stop.is_set():
                with gps_service_lock:
                    if not gps_service or not gps_service.get('enabled', False):
                        # GPS polling thread stopping (debug output removed)
                        break
                
                try:
                    # Try to read data - use next() with timeout handling
                    new_data = None
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
                        # Update status to searching if we haven't gotten data in a while
                        if no_data_count >= max_no_data and time.time() - last_status_update > 5:
                            with gps_service_lock:
                                if gps_service and gps_service.get('enabled', False):
                                    old_status = mifi_status.get('gps_status', 'disabled')
                                    if old_status != 'searching':
                                        mifi_status['gps_status'] = 'searching'
                                        mifi_status['gps_enabled'] = True
                                        # GPS status: searching (debug output removed)
                                        save_state()
                                        last_status_update = time.time()
                        time.sleep(0.5)  # Wait a bit before trying again
                        continue
                    
                    no_data_count = 0  # Reset counter on successful read
                    
                    # Process the GPS data
                    try:
                        data_stream.unpack(new_data)
                        
                        # Check if we have TPV data
                        if hasattr(data_stream, 'TPV') and data_stream.TPV:
                            tpv = data_stream.TPV
                            if tpv:  # TPV exists and is not empty
                                # Try to get mode and coordinates
                                mode = tpv.get('mode', 0) if hasattr(tpv, 'get') else getattr(tpv, 'mode', 0)
                                lat = tpv.get('lat', None) if hasattr(tpv, 'get') else getattr(tpv, 'lat', None)
                                lon = tpv.get('lon', None) if hasattr(tpv, 'get') else getattr(tpv, 'lon', None)
                                
                                # Update status based on GPS lock
                                with gps_service_lock:
                                    if gps_service and gps_service.get('enabled', False):
                                        old_status = mifi_status.get('gps_status', 'disabled')
                                        
                                        if mode is not None and mode >= 2 and lat is not None and lon is not None:
                                            # GPS has a lock (mode 2 = 2D fix, mode 3 = 3D fix)
                                            mifi_status['gps_status'] = 'locked'
                                            mifi_status['gps_enabled'] = True
                                            if old_status != 'locked':
                                                # GPS status changed to locked (debug output removed)
                                                save_state()
                                        elif mode is not None and mode >= 1:
                                            # GPS has data but no fix yet (mode 1 = no fix)
                                            if old_status not in ['locked', 'searching']:
                                                mifi_status['gps_status'] = 'searching'
                                                mifi_status['gps_enabled'] = True
                                                save_state()
                                        else:
                                            # No GPS data at all
                                            if old_status not in ['locked', 'searching', 'no_data']:
                                                mifi_status['gps_status'] = 'no_data'
                                                mifi_status['gps_enabled'] = True
                                                save_state()
                    except Exception as e:
                        # Log errors occasionally, not every time
                        if time.time() - last_status_update > 10:
                            last_status_update = time.time()
                        time.sleep(0.5)  # Wait before retrying
                        continue
                except Exception as e:
                    # Log errors from reading GPS data
                    if time.time() - last_status_update > 10:
                        last_status_update = time.time()
                    time.sleep(0.5)  # Wait before retrying
                    
        except Exception as e:
            print(f"[ERROR] GPS polling thread connection error: {e}")
            import traceback
            traceback.print_exc()
            # Set status to no_data if we can't connect
            with gps_service_lock:
                if gps_service and gps_service.get('enabled', False):
                    mifi_status['gps_status'] = 'no_data'
                    save_state()
        finally:
            if gps_socket:
                try:
                    gps_socket.close()
                except:
                    pass
            # GPS polling thread stopped (debug output removed)
    
    # Stop existing thread if running
    if gps_service_thread and gps_service_thread.is_alive():
        # Stopping existing GPS polling thread (debug output removed)
        gps_polling_stop.set()
        gps_service_thread.join(timeout=2)
    
    # Start new polling thread
    gps_polling_stop.clear()
    gps_service_thread = threading.Thread(target=gps_polling_loop, daemon=True)
    gps_service_thread.start()
    # GPS polling thread created and started (debug output removed)

def stop_gps_polling_thread():
    """Stop GPS polling thread"""
    global gps_service_thread, gps_polling_stop
    gps_polling_stop.set()
    if gps_service_thread and gps_service_thread.is_alive():
        gps_service_thread.join(timeout=2)
    gps_service_thread = None

def check_interface_status():
    """Check monitor mode interface status"""
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=2)
        if 'Mode:Monitor' in result.stdout:
            return 'monitor_mode'
        elif 'IEEE 802.11' in result.stdout:
            return 'managed_mode'
        return 'no_interface'
    except:
        return 'unknown'

def check_tak_status():
    """Check TAK connection status from mifi_service"""
    if mifi_service:
        if getattr(mifi_service, 'tak_connected', False):
            return 'connected'
    return 'disabled'

def update_status():
    """Update all status indicators - non-blocking version - PRESERVES values set by toggle handlers"""
    # GPS and TAK status are managed by mifi_service - no need to update here
    # Status will be read directly from mifi_service in api_status()
    mifi_status['interface_status'] = check_interface_status()

def init_tak_service():
    """Initialize TAK connection service"""
    global tak_service, tak_service_thread
    
    # init_tak_service() called (debug output removed)
    
    with tak_service_lock:
        if tak_service and tak_service.get('connected', False):
            # TAK service already connected (debug output removed)
            return
        
        try:
            sys.path.insert(0, os.path.dirname(__file__))
            from mifi import wifi_cracker
            suite = wifi_cracker()
            
            # Loading TAK config (debug output removed)
            suite.load_tak_config()
            
            # TAK enabled check (debug output removed)
            if not suite.tak_enabled:
                error_msg = 'TAK not enabled in config'
                if DEBUG_MODE:
                    print(f"[ERROR] {error_msg}")
                tak_service = {'connected': False, 'error': error_msg}
                return
            
            def get_tak_password():
                try:
                    # Send password prompt to log queue for UI display
                    # Use a unique ID for this prompt
                    prompt_id = f'tak_password_{int(time.time() * 1000)}'
                    prompt_data = {
                        'id': prompt_id,
                        'message': 'Enter PKCS#12 certificate password:',
                        'type': 'password',
                        'tak_password': True
                    }
                    log_entry = {
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'message': 'Enter PKCS#12 certificate password:',
                        'level': 'info',
                        'prefix': '[*]',
                        'prompt': prompt_data,
                        'tak_password_prompt': True  # Explicit flag for frontend
                    }
                    # TAK password prompt log entry (debug output removed)
                    mifi_log_queue.put(log_entry)
                    # TAK password prompt sent to log queue (debug output removed)
                    
                    # Also print to stdout so it shows in server logs (only if DEBUG)
                    if DEBUG_MODE:
                        print(f"[*] Enter PKCS#12 certificate password:")
                    
                    # Waiting for TAK password from queue (debug output removed)
                    password = tak_password_queue.get(timeout=30)
                    # TAK password received from queue (debug output removed)
                    return password
                except queue.Empty:
                    error_msg = "Password not provided within timeout"
                    if DEBUG_MODE:
                        print(f"[ERROR] {error_msg}")
                    # Send error to log queue
                    error_log = {
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'message': error_msg,
                        'level': 'error',
                        'prefix': '[!]'
                    }
                    mifi_log_queue.put(error_log)
                    raise Exception(error_msg)
            
            suite.tak_password_callback = get_tak_password
            
            # Initializing TAK connection (debug output removed)
            
            success = suite.init_tak_connection(
                host=suite.tak_host,
                port=suite.tak_port,
                protocol=suite.tak_protocol,
                cert_file=suite.tak_cert_file,
                key_file=suite.tak_key_file,
                ca_file=suite.tak_ca_file,
                api_token=suite.tak_api_token
            )
            
            # TAK connection result (debug output removed)
            
            if success:
                tak_service = {
                    'connected': True,
                    'suite': suite,
                    'host': suite.tak_host,
                    'port': suite.tak_port
                }
                # TAK service connected successfully (debug output removed)
                
                def keepalive_loop():
                                # TAK keepalive loop started (debug output removed)
                    while True:
                        with tak_service_lock:
                            if not tak_service or not tak_service.get('connected'):
                                # TAK keepalive loop stopping (debug output removed)
                                break
                            try:
                                suite._send_tak_presence()
                            except Exception as e:
                                # Error sending TAK keepalive (debug output removed)
                                pass
                        time.sleep(30)
                
                tak_service_thread = threading.Thread(target=keepalive_loop, daemon=True)
                tak_service_thread.start()
                # TAK keepalive thread started (debug output removed)
            else:
                error_msg = 'Connection failed'
                if DEBUG_MODE:
                    print(f"[ERROR] TAK connection failed: {error_msg}")
                tak_service = {'connected': False, 'error': error_msg}
        except Exception as e:
            error_msg = str(e)
            if DEBUG_MODE:
                print(f"[ERROR] Exception in init_tak_service: {error_msg}")
                import traceback
                traceback.print_exc()
            tak_service = {'connected': False, 'error': error_msg}

def stop_tak_service():
    """Stop TAK connection service"""
    global tak_service, tak_service_thread
    
    with tak_service_lock:
        if tak_service and tak_service.get('connected'):
            try:
                suite = tak_service.get('suite')
                if suite:
                    suite.close_tak_connection()
            except:
                pass
        
        tak_service = {'connected': False}
        tak_service_thread = None

# --- API Endpoints ---

# ===== CONTROL PANEL API ROUTES =====

@app.route('/api/status')
def api_status():
    """Get current status - reads directly from mifi_service (authoritative source)"""
    global mifi_service
    
    # Update non-blocking status (interface, etc.)
    mifi_status['interface_status'] = check_interface_status()
    
    # Read GPS status directly from mifi_service (authoritative source)
    current_gps_status = 'disabled'
    current_gps_enabled = False
    
    if mifi_service:
        # Try to acquire lock with timeout to avoid blocking
        if mifi_service.gps_lock.acquire(blocking=True, timeout=0.1):
            try:
                if mifi_service.gps_thread and mifi_service.gps_thread.is_alive():
                    # GPS polling is active - get status from mifi_service
                    current_gps_status = getattr(mifi_service, 'gps_status', 'disabled')
                    current_gps_enabled = True
                else:
                    # GPS thread not running
                    current_gps_status = 'disabled'
                    current_gps_enabled = False
            finally:
                mifi_service.gps_lock.release()
        else:
            # Lock timeout - use saved status as fallback
            current_gps_status = mifi_status.get('gps_status', 'disabled')
            current_gps_enabled = mifi_status.get('gps_enabled', False)
    else:
        # No mifi_service - use saved status
        current_gps_status = mifi_status.get('gps_status', 'disabled')
        current_gps_enabled = mifi_status.get('gps_enabled', False)
    
    # Read TAK status directly from mifi_service (authoritative source)
    current_tak_status = 'disabled'
    current_tak_connected = False
    
    if mifi_service:
        current_tak_connected = getattr(mifi_service, 'tak_connected', False)
        if current_tak_connected:
            current_tak_status = 'connected'
        else:
            current_tak_status = 'disabled'
    else:
        # No mifi_service - use saved status
        current_tak_status = mifi_status.get('tak_status', 'disabled')
        current_tak_connected = mifi_status.get('tak_connected', False)
    
    # Update mifi_status for persistence (used as fallback when mifi_service unavailable)
    mifi_status['gps_status'] = current_gps_status
    mifi_status['gps_enabled'] = current_gps_enabled
    mifi_status['tak_status'] = current_tak_status
    mifi_status['tak_connected'] = current_tak_connected
    
    debug_print(f"Status API: GPS={current_gps_status} (enabled={current_gps_enabled}), TAK={current_tak_status} (connected={current_tak_connected})")
    
    return jsonify(mifi_status)

@app.route('/api/initialize', methods=['POST'])
def api_initialize():
    """Initialize system and check directories"""
    success = initialize_system()
    return jsonify({
        'success': success,
        'status': mifi_status['initialization_status'],
        'message': mifi_status['initialization_message']
    })

@app.route('/api/config', methods=['GET', 'POST'])
def api_config():
    """Get or update configuration"""
    if request.method == 'GET':
        try:
            config = configparser.ConfigParser()
            config.read('config/config.ini')
            
            result = {}
            if 'TAK' in config:
                result['tak'] = {
                    'enabled': config['TAK'].getboolean('enabled', False),
                    'host': config['TAK'].get('host', ''),
                    'port': config['TAK'].getint('port', 8087),
                    'protocol': config['TAK'].get('protocol', 'tcp'),
                    'cert_file': config['TAK'].get('cert_file', ''),
                    'ca_file': config['TAK'].get('ca_file', '')
                }
            if 'DEFAULT' in config:
                result['interface'] = {
                    'candidates': config['DEFAULT'].get('monitor_candidates', '')
                }
            if 'GPS' in config:
                result['gps'] = {
                    'host': config['GPS'].get('host', '10.0.0.2'),
                    'port': config['GPS'].getint('port', 2947)
                }
            
            return jsonify(result)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    else:  # POST
        try:
            data = request.json
            config = configparser.ConfigParser()
            config.read('config/config.ini')
            
            if 'tak' in data:
                if 'TAK' not in config:
                    config.add_section('TAK')
                tak = data['tak']
                config['TAK']['enabled'] = str(tak.get('enabled', False))
                if 'host' in tak:
                    config['TAK']['host'] = tak['host']
                if 'port' in tak:
                    config['TAK']['port'] = str(tak['port'])
                if 'protocol' in tak:
                    config['TAK']['protocol'] = tak['protocol']
                if 'cert_file' in tak:
                    config['TAK']['cert_file'] = tak['cert_file']
                if 'ca_file' in tak:
                    config['TAK']['ca_file'] = tak['ca_file']
            
            if 'interface' in data:
                if 'DEFAULT' not in config:
                    config.add_section('DEFAULT')
                if 'candidates' in data['interface']:
                    config['DEFAULT']['monitor_candidates'] = data['interface']['candidates']
            
            with open('config/config.ini', 'w') as f:
                config.write(f)
            
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/tak/upload-cert', methods=['POST'])
def api_tak_upload_cert():
    """Upload certificate file to tak/ folder"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        cert_type = request.form.get('type', 'cert')
        
        if not file or file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        tak_dir = os.path.join(os.path.dirname(__file__), 'tak')
        if not os.path.exists(tak_dir):
            os.makedirs(tak_dir)
        
        filename = os.path.basename(file.filename)
        filepath = os.path.join(tak_dir, filename)
        file.save(filepath)
        
        return jsonify({'success': True, 'filename': filename})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/tak/toggle-connection', methods=['POST'])
def api_tak_toggle_connection():
    """Toggle TAK connection on/off - uses mifi_service"""
    global mifi_service
    
    # Initialize mifi_service if needed
    if mifi_service is None:
        try:
            from mifi import wifi_cracker
            mifi_service = wifi_cracker()
            mifi_service.initial_config()
            mifi_service.debug = DEBUG_MODE
        except Exception as e:
            print(f"[ERROR] Failed to initialize mifi_service: {e}")
            return jsonify({'success': False, 'error': f'Failed to initialize service: {e}', 'connected': False}), 500
    
    try:
        # Check if TAK is connected (read directly from mifi_service)
        tak_connected = getattr(mifi_service, 'tak_connected', False)
        
        if tak_connected:
            # Disconnect TAK
            if mifi_service.tak_socket:
                try:
                    mifi_service.tak_socket.close()
                except:
                    pass
            mifi_service.tak_connected = False
            mifi_status['tak_status'] = 'disabled'
            mifi_status['tak_connected'] = False
            save_state()
            return jsonify({'success': True, 'connected': False, 'details': {'connected': False, 'message': 'TAK connection disconnected'}})
        else:
            # Connecting TAK service
            config = configparser.ConfigParser()
            config_path = os.path.join(os.path.dirname(__file__), 'config', 'config.ini')
            config.read(config_path)
            
            if 'TAK' not in config:
                if DEBUG_MODE:
                    print("[ERROR] TAK section not found in config/config.ini")
                return jsonify({'success': False, 'error': 'TAK not configured. Configure it in Config tab first.', 'connected': False})
            
            tak_host = config['TAK'].get('host', '')
            tak_cert = config['TAK'].get('cert_file', '')
            
            if not tak_host or not tak_cert:
                if DEBUG_MODE:
                    print("[ERROR] TAK host or cert_file missing")
                return jsonify({'success': False, 'error': 'TAK host and certificate must be configured first.', 'connected': False})
            
            # Set initial status and return immediately
            mifi_status['tak_status'] = 'enabled'
            mifi_status['tak_connected'] = False
            save_state()
            
            # Initialize TAK in background thread using mifi_service
            def init_tak_background():
                try:
                    debug_print("Background TAK initialization starting")
                    if mifi_service:
                        mifi_service.debug = DEBUG_MODE
                        debug_print(f"Set mifi_service.debug = {DEBUG_MODE}")
                    
                    # Load TAK config if needed
                    if not mifi_service.tak_enabled:
                        debug_print("TAK not enabled, loading config")
                        mifi_service.load_tak_config()
                    
                    if not mifi_service.tak_enabled:
                        error_msg = 'TAK not enabled in config'
                        if DEBUG_MODE:
                            print(f"[ERROR] {error_msg}")
                        debug_print(f"TAK not enabled after config load: {error_msg}")
                        mifi_status['tak_status'] = 'disabled'
                        mifi_status['tak_connected'] = False
                        save_state()
                        return
                    
                    def get_tak_password():
                        try:
                            prompt_id = f'tak_password_{int(time.time() * 1000)}'
                            prompt_data = {
                                'id': prompt_id,
                                'message': 'Enter PKCS#12 certificate password:',
                                'type': 'password',
                                'tak_password': True
                            }
                            log_entry = {
                                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'message': 'Enter PKCS#12 certificate password:',
                                'level': 'info',
                                'prefix': '[*]',
                                'prompt': prompt_data,
                                'tak_password_prompt': True
                            }
                            mifi_log_queue.put(log_entry)
                            if DEBUG_MODE:
                                print(f"[*] Enter PKCS#12 certificate password:")
                            debug_print("Waiting for password from queue")
                            password = tak_password_queue.get(timeout=30)
                            debug_print("Password received from queue")
                            return password
                        except queue.Empty:
                            error_msg = "Password not provided within timeout"
                            if DEBUG_MODE:
                                print(f"[ERROR] {error_msg}")
                            debug_print(f"Password timeout: {error_msg}")
                            error_log = {
                                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'message': error_msg,
                                'level': 'error',
                                'prefix': '[!]'
                            }
                            mifi_log_queue.put(error_log)
                            raise Exception(error_msg)
                    
                    mifi_service.tak_password_callback = get_tak_password
                    
                    debug_print(f"Initializing TAK connection: host={mifi_service.tak_host}, port={mifi_service.tak_port}")
                    debug_print("About to call mifi_service.init_tak_connection()")
                    success = False
                    try:
                        debug_print("Calling init_tak_connection now...")
                        success = mifi_service.init_tak_connection(
                            host=mifi_service.tak_host,
                            port=mifi_service.tak_port,
                            protocol=mifi_service.tak_protocol,
                            cert_file=mifi_service.tak_cert_file,
                            key_file=mifi_service.tak_key_file,
                            ca_file=mifi_service.tak_ca_file,
                            api_token=mifi_service.tak_api_token
                        )
                        debug_print(f"init_tak_connection returned: success={success}")
                    except Exception as conn_ex:
                        debug_print(f"Exception during init_tak_connection: {conn_ex}", prefix='[ERROR]')
                        import traceback
                        traceback.print_exc()
                        success = False
                    debug_print(f"After try/except block: success={success}")
                    
                    if success:
                        try:
                            debug_print("TAK connection succeeded, updating state")
                            # mifi_service.tak_connected is set by init_tak_connection
                            debug_print(f"mifi_service.tak_connected={getattr(mifi_service, 'tak_connected', 'NOT SET')}")
                            
                            # Update status
                            mifi_status['tak_status'] = 'connected'
                            mifi_status['tak_connected'] = True
                            debug_print(f"Updated mifi_status to connected: tak_status={mifi_status.get('tak_status')}, tak_connected={mifi_status.get('tak_connected')}")
                            
                            save_state()
                            debug_print("Saved state after TAK connection")
                            
                            # Start keepalive thread to maintain connection
                            def keepalive_loop():
                                debug_print("TAK keepalive loop started")
                                while True:
                                    if not mifi_service or not mifi_service.tak_connected:
                                        debug_print("TAK keepalive loop stopping")
                                        break
                                    try:
                                        if mifi_service.tak_connected:
                                            mifi_service._send_tak_presence()
                                            debug_print("Sent TAK keepalive")
                                    except Exception as e:
                                        debug_print(f"Error sending TAK keepalive: {e}", prefix='[ERROR]')
                                        # If connection is lost, mark as disconnected
                                        if mifi_service:
                                            mifi_service.tak_connected = False
                                        mifi_status['tak_status'] = 'disabled'
                                        mifi_status['tak_connected'] = False
                                        save_state()
                                        break
                                    time.sleep(30)
                            
                            threading.Thread(target=keepalive_loop, daemon=True).start()
                            debug_print("Started TAK keepalive thread")
                        except Exception as state_ex:
                            debug_print(f"Exception updating state after TAK connection: {state_ex}", prefix='[ERROR]')
                            import traceback
                            traceback.print_exc()
                            mifi_status['tak_status'] = 'disabled'
                            mifi_status['tak_connected'] = False
                            save_state()
                    else:
                        debug_print("TAK connection failed")
                        mifi_status['tak_status'] = 'disabled'
                        mifi_status['tak_connected'] = False
                        save_state()
                except Exception as e:
                    print(f"[ERROR] Background TAK init error: {e}")
                    debug_print(f"Exception in background TAK init: {e}", prefix='[ERROR]')
                    import traceback
                    traceback.print_exc()
                    mifi_status['tak_status'] = 'disabled'
                    mifi_status['tak_connected'] = False
                    save_state()
            
            threading.Thread(target=init_tak_background, daemon=True).start()
            
            # Return immediately with "connecting" status
            tak_host = config['TAK'].get('host', 'Unknown')
            tak_port = config['TAK'].getint('port', 8087)
            tak_protocol = config['TAK'].get('protocol', 'tcp')
            cert_file = config['TAK'].get('cert_file', 'Not specified')
            
            details = {
                'connected': False,
                'host': tak_host,
                'port': tak_port,
                'protocol': tak_protocol,
                'cert_file': cert_file,
                'message': f'Connecting to TAK server {tak_host}:{tak_port}... (check status in a few seconds)'
            }
            
            return jsonify({'success': True, 'connected': False, 'details': details, 'connecting': True})
    except Exception as e:
        print(f"[ERROR] Exception in TAK toggle: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e), 'connected': False}), 500

@app.route('/api/start', methods=['POST'])
def api_start():
    """Start a MiFi operation - calls mifi.py methods directly"""
    global mifi_process, mifi_service
    
    if mifi_process and mifi_process.poll() is None:
        return jsonify({'success': False, 'error': 'Operation already running'})
    
    data = request.json
    mode = data.get('mode')
    mode = MODE_MAP.get(mode, mode)
    
    # Initialize mifi_service if needed
    if mifi_service is None:
        try:
            from mifi import wifi_cracker
            mifi_service = wifi_cracker()
            mifi_service.initial_config()
            mifi_service.debug = DEBUG_MODE  # Apply debug setting from environment
        except Exception as e:
            print(f"[ERROR] Failed to initialize mifi_service: {e}")
            return jsonify({'success': False, 'error': f'Failed to initialize service: {e}'}), 500
    
    # overwatch branch: map mode now uses the same subprocess path as every
    # other mode (see below) for lifecycle/PID consistency with the USB
    # arbiter. The CLI subprocess already self-manages GPS via gps3/gpsd and
    # the MIFI_GPS_ACTIVE env var (see mifi.py mode_type == "map" handling),
    # so no in-process special case is needed here anymore.

    # Use sudo -E to preserve environment variables
    cmd = ['sudo', '-E', 'python3', '-u', os.path.join(os.path.dirname(__file__), 'mifi.py'), '--mode', mode]
    
    if data.get('verbose'):
        cmd.append('-v')
    
    if mode.startswith('collect') or mode == 'target' or mode.startswith('full'):
        if data.get('initial_scan'):
            cmd.extend(['-IS', str(data['initial_scan'])])
        if data.get('target_scan'):
            cmd.extend(['-TS', str(data['target_scan'])])
        if data.get('deauth_packets'):
            cmd.extend(['-p', str(data['deauth_packets'])])
    
    if mode == 'target':
        if data.get('target_essid'):
            cmd.extend(['-TID', data['target_essid']])
        if data.get('target_search_attempts'):
            cmd.extend(['-TSA', str(data['target_search_attempts'])])
        if data.get('target_attempts'):
            cmd.extend(['-TA', str(data['target_attempts'])])
    
    if mode.startswith('process') or mode.startswith('full'):
        if data.get('wordlist'):
            cmd.extend(['-WL', data['wordlist']])
    
    if mode == 'map':
        if data.get('max_scans'):
            cmd.extend(['-MS', str(data['max_scans'])])
        if data.get('scan_duration'):
            cmd.extend(['-MSD', str(data['scan_duration'])])
        gps_port = os.path.join(os.path.dirname(__file__), '.gps-stub')
        cmd.extend(['-GPS', gps_port])
        if data.get('gps_lock_attempts'):
            cmd.extend(['-GLA', str(data['gps_lock_attempts'])])
        if data.get('gps_lock_wait'):
            cmd.extend(['-GLW', str(data['gps_lock_wait'])])
    
    try:
        # Set environment to ensure unbuffered output
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
        gps_active = (mifi_service and mifi_service.gps_thread and mifi_service.gps_thread.is_alive())
        env['MIFI_GPS_ACTIVE'] = '1' if gps_active else '0'
        
        # Use pty (pseudo-terminal) on Unix to make process think it's connected to a terminal
        # This ensures prompts are flushed immediately (no buffering)
        if sys.platform != 'win32':
            # Create master/slave pty pair
            master_fd, slave_fd = pty.openpty()
            
            # Set terminal size (80x24) - this helps Python recognize it as a terminal
            try:
                winsize = struct.pack('HHHH', 24, 80, 0, 0)
                fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)
            except Exception as e:
                pass
            # Note: start_new_session=True creates a new session, but env should still be passed
            mifi_process = subprocess.Popen(
                cmd,
                stdout=slave_fd,
                stderr=slave_fd,
                stdin=slave_fd,
                env=env,  # Explicitly pass environment
                start_new_session=True
            )
            
            # Close slave_fd in parent (master_fd stays open for reading/writing)
            os.close(slave_fd)
            
            # Create file objects from master_fd (pty is bidirectional)
            # Use text mode with line buffering - Python will recognize it as a terminal
            # and flush output immediately (especially for input() prompts)
            process_stdout = os.fdopen(master_fd, 'r', buffering=1)  # Line buffered text mode
            # For writing, duplicate the fd since we can't open the same fd twice
            stdin_fd = os.dup(master_fd)
            process_stdin = os.fdopen(stdin_fd, 'w', buffering=1)  # Line buffered text mode
            
            # Store file objects for later use
            mifi_process.stdin_file = process_stdin
            mifi_process.stdout_file = process_stdout
        else:
            # Windows - use regular pipes
            mifi_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,  # Line buffered
                stdin=subprocess.PIPE,
                env=env
            )
            process_stdout = mifi_process.stdout
            process_stdin = mifi_process.stdin
        
        mifi_status['running'] = True
        mifi_status['mode'] = mode
        mifi_status['pid'] = mifi_process.pid
        mifi_status['start_time'] = datetime.now().isoformat()
        
        # Store stdin file object for prompt responses
        if sys.platform != 'win32':
            mifi_process.stdin_file = process_stdin
            mifi_process.stdout_file = process_stdout
        
        # Starting log reader thread (debug output removed)
        threading.Thread(target=read_process_logs, args=(mifi_process, process_stdout), daemon=True).start()
        
        # Operation started successfully (debug output removed)
        return jsonify({'success': True, 'pid': mifi_process.pid})
    except Exception as e:
        print(f"[ERROR] Failed to start operation: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/stop', methods=['POST'])
def api_stop():
    """Stop the currently running MiFi operation (subprocess-based for all modes)."""
    global mifi_process, mifi_service

    # All modes (including map, as of the overwatch branch) run as a subprocess.
    if mifi_process and mifi_process.poll() is None:
        try:
            # Send SIGINT (like Ctrl+C) for clean shutdown
            os.kill(mifi_process.pid, signal.SIGINT)
            time.sleep(2)
            # If still running after SIGINT, try terminate
            if mifi_process.poll() is None:
                mifi_process.terminate()
                time.sleep(1)
                # If still running, force kill
                if mifi_process.poll() is None:
                    mifi_process.kill()
            
            mifi_status['running'] = False
            mifi_status['mode'] = None
            mifi_status['pid'] = None
            
            return jsonify({'success': True})
        except ProcessLookupError:
            # Process already terminated
            mifi_status['running'] = False
            mifi_status['mode'] = None
            mifi_status['pid'] = None
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    
    return jsonify({'success': False, 'error': 'No operation running'})

@app.route('/api/logs/stream')
def api_logs_stream():
    """Stream logs via Server-Sent Events"""
    # Log stream endpoint called (debug output removed)
    
    def generate():
        try:
            # Log stream generator started (debug output removed)
            keepalive_count = 0
            while True:
                try:
                    message = mifi_log_queue.get(timeout=1)
                    # Send message if it has content OR if it has a prompt (prompts might have empty messages)
                    if (message.get('message') and message['message'].strip()) or message.get('prompt'):
                        msg_preview = message.get('message', '')[:50] if message.get('message') else 'NO MESSAGE'
                        has_prompt = 'YES' if message.get('prompt') else 'NO'
                        tak_prompt = 'YES' if message.get('tak_password_prompt') else 'NO'
                        # Debug logging removed for cleaner console output
                        if message.get('prompt'):
                            # Prompt details (debug output removed)
                            pass
                        # Ensure tak_password_prompt flag is set if prompt has tak_password
                        if message.get('prompt') and message.get('prompt', {}).get('tak_password'):
                            message['tak_password_prompt'] = True
                            # Set tak_password_prompt flag (debug output removed)
                        yield f"data: {json.dumps(message)}\n\n"
                except queue.Empty:
                    # Send keepalive to prevent connection timeout
                    keepalive_count += 1
                    if keepalive_count % 60 == 0:  # Log every 60 keepalives (1 minute)
                        # Log stream keepalive (debug output removed)
                        pass
                    yield f"data: {json.dumps({'message': '', 'level': 'keepalive'})}\n\n"
                except Exception as e:
                    # Log error but continue streaming
                    error_msg = f'Stream error: {str(e)}'
                    print(f"[ERROR] {error_msg}")
                    error_data = {'message': error_msg, 'level': 'error'}
                    yield f"data: {json.dumps(error_data)}\n\n"
                    time.sleep(0.5)  # Brief pause before retrying
        except GeneratorExit:
            # Client disconnected, clean up
            # Log stream client disconnected (debug output removed)
            pass
        except Exception as e:
            # Final error, send error message and close
            error_msg = f'Stream closed: {str(e)}'
            print(f"[ERROR] {error_msg}")
            import traceback
            traceback.print_exc()
            error_data = {'message': error_msg, 'level': 'error'}
            yield f"data: {json.dumps(error_data)}\n\n"
    
    response = Response(stream_with_context(generate()), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'  # Disable nginx buffering
    response.headers['Connection'] = 'keep-alive'
    return response

def read_process_logs(process, stdout_file=None):
    """Read logs from process and add to queue"""
    # Log reader started (debug output removed)
    line_count = 0
    
    # Use provided stdout_file (from pty) or process.stdout (from pipe)
    stdout = stdout_file if stdout_file else process.stdout
    # Using stdout (debug output removed)
    
    # Track recently processed prompts to avoid duplicates
    recent_prompts = set()
    buffer_check_counter = 0
    
    try:
        import select
        import sys
        
        # Entering read_process_logs try block (debug output removed)
        buffer = ''
        consecutive_errors = 0
        max_consecutive_errors = 10  # Allow up to 10 consecutive errors before giving up
        loop_iteration = 0
        last_buffer_size = 0
        buffer_unchanged_count = 0
        
        # Starting read loop (debug output removed)
        while True:
            loop_iteration += 1
            # Log every 100 iterations to show we're still running (roughly every 5 seconds)
            # Log reader loop iteration (debug output removed)
            
            # Check if buffer is stuck (same size for many iterations)
            if len(buffer) == last_buffer_size and len(buffer) > 0:
                buffer_unchanged_count += 1
                if buffer_unchanged_count > 20:  # Buffer unchanged for ~1 second
                    # Try to force read even if select says no data
                    if process.poll() is None:
                        try:
                            # Try a non-blocking read to see if there's data
                            fd = stdout.fileno()
                            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
                            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                            try:
                                # Read directly from raw file descriptor
                                raw_chunk = os.read(fd, 1024)
                                if raw_chunk:
                                    # Decode with better error handling for box-drawing characters
                                    try:
                                        chunk = raw_chunk.decode('utf-8', errors='surrogateescape')
                                        # Replace any surrogate characters
                                        if any(ord(c) >= 0xD800 and ord(c) <= 0xDFFF for c in chunk):
                                            chunk = chunk.encode('utf-8', errors='surrogateescape').decode('utf-8', errors='replace')
                                    except UnicodeDecodeError:
                                        chunk = raw_chunk.decode('utf-8', errors='replace')
                                    buffer += chunk
                                    buffer_unchanged_count = 0
                                    # Process any complete lines immediately
                                    while '\n' in buffer:
                                        line, buffer = buffer.split('\n', 1)
                                        if line and line.strip():
                                            _process_log_line(process, line, line_count, recent_prompts)
                                            line_count += 1
                            finally:
                                fcntl.fcntl(fd, fcntl.F_SETFL, flags)
                        except (IOError, OSError) as force_read_err:
                            errno = getattr(force_read_err, 'errno', None)
                            if errno != 11:  # Not EAGAIN
                                debug_print(f"Force read failed: {force_read_err}, errno: {errno}")
                        except UnicodeDecodeError as decode_err:
                            debug_print(f"Force read decode error: {decode_err}")
                    # If buffer still has incomplete data after many iterations, process it anyway
                    if buffer_unchanged_count > 100 and buffer and len(buffer.strip()) > 0:
                        # Buffer has been stuck for ~5 seconds, process incomplete line
                        _process_log_line(process, buffer.strip(), line_count)
                        line_count += 1
                        buffer = ''
                        buffer_unchanged_count = 0
                    else:
                        buffer_unchanged_count = 0  # Reset counter
            else:
                last_buffer_size = len(buffer)
                buffer_unchanged_count = 0
            # Check if process ended
            if process.poll() is not None:
                # Process ended, read any remaining data
                try:
                    if hasattr(stdout, 'read'):
                        remaining = stdout.read()
                        if remaining:
                            buffer += remaining
                            for line in buffer.splitlines(True):
                                if line.endswith('\n') or line.endswith('\r\n'):
                                    line = line.rstrip('\n\r')
                                    if line and line.strip():
                                        _process_log_line(process, line, line_count, recent_prompts)
                                        line_count += 1
                except:
                    pass
                break
            
            # Try to read available data
            try:
                if sys.platform != 'win32':
                    # Check if stdout file object is still valid
                    if stdout.closed:
                        break
                    
                    # Use select to check if data is available (works with both pipes and pty)
                    # Use shorter timeout to check more frequently for prompts
                    try:
                        ready, _, _ = select.select([stdout], [], [], 0.05)
                    except (ValueError, OSError) as select_err:
                        # File descriptor might be invalid, but process might still be running
                        if process.poll() is None:
                            # Process any buffered data
                            if '\n' in buffer:
                                lines = buffer.split('\n')
                                buffer = lines[-1]
                                for line in lines[:-1]:
                                    if line and line.strip():
                                        # Processing line after select error
                                        _process_log_line(process, line, line_count, recent_prompts)
                                        line_count += 1
                            # If buffer has incomplete data, log it
                            if buffer and len(buffer.strip()) > 0:
                                debug_print(f"Buffer has incomplete data: {buffer[:100]}")
                            import time
                            time.sleep(0.1)
                            continue
                        else:
                            break
                    except Exception as select_err:
                        # Catch any other exceptions from select
                        if process.poll() is None:
                            import traceback
                            traceback.print_exc()
                            # Process any buffered data
                            if '\n' in buffer:
                                lines = buffer.split('\n')
                                buffer = lines[-1]
                                for line in lines[:-1]:
                                    if line and line.strip():
                                        _process_log_line(process, line, line_count, recent_prompts)
                                        line_count += 1
                            import time
                            time.sleep(0.2)
                            continue
                        else:
                            break
                    
                    if ready:
                        # Read in smaller chunks to detect prompts faster
                        # Select returned ready (debug output removed)
                        # Ensure non-blocking mode before read
                        try:
                            fd = stdout.fileno()
                            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
                            if not (flags & os.O_NONBLOCK):
                                # Setting non-blocking mode (debug output removed)
                                fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                        except Exception as flag_err:
                            # Error setting non-blocking flags (debug output removed)
                            pass
                        
                        try:
                            # Read directly from raw file descriptor to avoid TextIOWrapper blocking
                            fd = stdout.fileno()
                            # Ensure non-blocking mode
                            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
                            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                            chunk = ''
                            try:
                                # os.read() called (debug output removed)
                                raw_chunk = os.read(fd, 1024)
                                # os.read() returned (debug output removed)
                                # Decode bytes to string - use 'surrogateescape' to preserve invalid bytes
                                # then replace surrogates to handle box-drawing characters properly
                                try:
                                    chunk = raw_chunk.decode('utf-8', errors='surrogateescape')
                                    # Replace any surrogate characters that couldn't be decoded
                                    if any(ord(c) >= 0xD800 and ord(c) <= 0xDFFF for c in chunk):
                                        chunk = chunk.encode('utf-8', errors='surrogateescape').decode('utf-8', errors='replace')
                                except UnicodeDecodeError:
                                    # Fallback to replace for truly invalid sequences
                                    chunk = raw_chunk.decode('utf-8', errors='replace')
                                # Decoded chunk (debug output removed)
                            finally:
                                # Restore original flags
                                fcntl.fcntl(fd, fcntl.F_SETFL, flags)
                            
                            if chunk:
                                # Read bytes from stdout (debug output removed)
                                pass
                            else:
                                # Read returned empty (debug output removed)
                                pass
                        except (IOError, OSError) as read_err:
                            errno = getattr(read_err, 'errno', None)
                            if errno == 11:  # EAGAIN/EWOULDBLOCK - no data available
                                # Read would block (debug output removed)
                                chunk = ''  # Treat as empty read
                                # Process any complete lines in buffer
                                if '\n' in buffer:
                                    lines = buffer.split('\n')
                                    buffer = lines[-1]
                                    for line in lines[:-1]:
                                        if line and line.strip():
                                            _process_log_line(process, line, line_count, recent_prompts)
                                            line_count += 1
                                import time
                                time.sleep(0.05)
                                continue
                            else:
                                # Read exception (debug output removed)
                                pass
                            # Handle read errors - might be transient
                            if hasattr(read_err, 'errno') and read_err.errno == 5:
                                # EIO - might be transient, check if process still running
                                if process.poll() is None:
                                    # Read I/O error (debug output removed)
                                    # Process any complete lines in buffer
                                    if '\n' in buffer:
                                        lines = buffer.split('\n')
                                        buffer = lines[-1]
                                        for line in lines[:-1]:
                                            if line and line.strip():
                                                # Processing buffered line after read error
                                                _process_log_line(process, line, line_count, recent_prompts)
                                                line_count += 1
                                    # If buffer has incomplete data, log it but continue
                                    elif buffer and len(buffer.strip()) > 0:
                                        # Buffer has incomplete data, continuing
                                        pass
                                    import time
                                    time.sleep(0.1)
                                    continue
                                else:
                                    # Process ended, break normally
                                    break
                            raise  # Re-raise if not handled
                        
                        if not chunk:
                            # Empty read - check if process is still running
                            if process.poll() is None:
                                # Process still running, empty read might be a false positive from select()
                                # Process any complete lines in buffer
                                if '\n' in buffer:
                                    lines = buffer.split('\n')
                                    buffer = lines[-1]
                                    for line in lines[:-1]:
                                        if line and line.strip():
                                            _process_log_line(process, line, line_count, recent_prompts)
                                            line_count += 1
                                # Continue loop to wait for more data
                                import time
                                time.sleep(0.05)
                                continue
                            else:
                                # Process ended, process remaining buffer and exit
                                if buffer:
                                    if '\n' in buffer:
                                        lines = buffer.split('\n')
                                        for line in lines:
                                            if line and line.strip():
                                                # Processing final buffer line
                                                _process_log_line(process, line, line_count, recent_prompts)
                                                line_count += 1
                                    else:
                                        # Process incomplete line as-is
                                        if buffer.strip():
                                            # Processing incomplete final buffer line
                                            _process_log_line(process, buffer.strip(), line_count)
                                break
                        buffer += chunk
                        consecutive_errors = 0  # Reset error count on successful read
                        has_newline = '\n' in buffer
                        # Buffer after read (debug output removed)
                        # Immediately process any complete lines
                        lines_processed = 0
                        while '\n' in buffer:
                            line, buffer = buffer.split('\n', 1)
                            if line and line.strip():
                                # Processing log line (debug output removed)
                                # Processing line
                                _process_log_line(process, line, line_count, recent_prompts)
                                line_count += 1
                                lines_processed += 1
                        if lines_processed > 0:
                            # Processed lines (debug output removed)
                            pass
                        # Also check if there's remaining data in buffer that should be processed
                        if buffer and len(buffer) > 0:
                            # Buffer has incomplete data
                            # If we have incomplete buffer data, try a forced read immediately
                            # Don't wait for select() - sometimes data is already available
                            if process.poll() is None:  # Process still running
                                try:
                                    # Try a quick non-blocking read to get more data
                                    fd = stdout.fileno()
                                    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
                                    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                                    try:
                                        # Read directly from raw file descriptor to avoid TextIOWrapper encoding issues
                                        raw_quick_chunk = os.read(fd, 1024)
                                        if raw_quick_chunk:
                                            # Decode bytes to string
                                            # Decode with better error handling for box-drawing characters
                                            try:
                                                quick_chunk = raw_quick_chunk.decode('utf-8', errors='surrogateescape')
                                                # Replace any surrogate characters
                                                if any(ord(c) >= 0xD800 and ord(c) <= 0xDFFF for c in quick_chunk):
                                                    quick_chunk = quick_chunk.encode('utf-8', errors='surrogateescape').decode('utf-8', errors='replace')
                                            except UnicodeDecodeError:
                                                quick_chunk = raw_quick_chunk.decode('utf-8', errors='replace')
                                            # Quick read successful
                                            buffer += quick_chunk
                                            buffer_unchanged_count = 0  # Reset counter
                                            # Process any complete lines immediately
                                            while '\n' in buffer:
                                                line, buffer = buffer.split('\n', 1)
                                                if line and line.strip():
                                                    # Processing line from quick read
                                                    _process_log_line(process, line, line_count, recent_prompts)
                                                    line_count += 1
                                    finally:
                                        # Always restore original flags
                                        fcntl.fcntl(fd, fcntl.F_SETFL, flags)
                                except (IOError, OSError) as quick_read_err:
                                    errno = getattr(quick_read_err, 'errno', None)
                                    if errno == 11:  # EAGAIN/EWOULDBLOCK - no data available
                                        pass  # Expected, no data available
                                    else:
                                        debug_print(f"Quick read error: {quick_read_err}, errno: {errno}")
                                except UnicodeDecodeError as decode_err:
                                    debug_print(f"Quick read decode error: {decode_err}")
                                    # Handle encoding errors gracefully
                                    # Try to process what we have in the buffer
                                    if '\n' in buffer:
                                        lines = buffer.split('\n')
                                        buffer = lines[-1]
                                        for line in lines[:-1]:
                                            if line and line.strip():
                                                _process_log_line(process, line, line_count, recent_prompts)
                                                line_count += 1
                    else:
                        # No data available from select, but process might still be running
                        # Check if process is still running - if so, keep trying to read
                        poll_result = process.poll()
                        if poll_result is None:
                            if loop_iteration % 50 == 0:  # Log every 50 iterations (~2.5 seconds)
                                # Select returned no data (debug output removed)
                                pass
                            # Process still running, check if we have complete lines in buffer
                            if '\n' in buffer:
                                lines = buffer.split('\n')
                                buffer = lines[-1]  # Keep incomplete line in buffer
                                for line in lines[:-1]:
                                    if line and line.strip():
                                        # Processing buffered line
                                        _process_log_line(process, line, line_count, recent_prompts)
                                        line_count += 1
                            # Always try a forced read when select() returns no data but process is running
                            # This helps catch data that might be buffered but not yet detected by select()
                            # Try forced read every iteration when process is running (not just when buffer has data)
                            try:
                                # Set stdout to non-blocking temporarily
                                flags = fcntl.fcntl(stdout.fileno(), fcntl.F_GETFL)
                                fcntl.fcntl(stdout.fileno(), fcntl.F_SETFL, flags | os.O_NONBLOCK)
                                try:
                                    forced_chunk = stdout.read(1024)
                                    if forced_chunk:
                                        # Forced read successful
                                        buffer += forced_chunk
                                        # Process any complete lines from the forced read
                                        while '\n' in buffer:
                                            line, buffer = buffer.split('\n', 1)
                                            if line and line.strip():
                                                # Processing buffered line
                                                _process_log_line(process, line, line_count, recent_prompts)
                                                line_count += 1
                                finally:
                                    # Always restore original flags
                                    fcntl.fcntl(stdout.fileno(), fcntl.F_SETFL, flags)
                            except (IOError, OSError) as forced_read_err:
                                # Expected if no data available - just continue
                                if hasattr(forced_read_err, 'errno') and forced_read_err.errno == 11:
                                    pass  # EAGAIN - no data, that's fine
                                else:
                                    # Forced read error (non-fatal)
                                    pass
                            # Continue the loop to try reading more data
                            continue
                        else:
                            # Process ended, process any remaining buffer
                            if buffer:
                                if '\n' in buffer:
                                    lines = buffer.split('\n')
                                    for line in lines:
                                        if line and line.strip():
                                            # Processing final buffered line
                                            _process_log_line(process, line, line_count, recent_prompts)
                                            line_count += 1
                                else:
                                    if buffer.strip():
                                        # Processing incomplete final buffer
                                        _process_log_line(process, buffer.strip(), line_count)
                            break
                else:
                    # Windows - use blocking readline
                    line = stdout.readline()
                    if not line:
                        break
                    if line and line.strip():
                        _process_log_line(process, line.strip(), line_count)
                        line_count += 1
            except (IOError, OSError) as e:
                # Handle read errors
                if hasattr(e, 'errno'):
                    if e.errno == 11:  # EAGAIN - no data available
                        # No data available, check buffer for complete lines
                        if '\n' in buffer:
                            lines = buffer.split('\n')
                            buffer = lines[-1]
                            for line in lines[:-1]:
                                if line and line.strip():
                                    _process_log_line(process, line, line_count, recent_prompts)
                                    line_count += 1
                        continue
                    elif e.errno == 5:  # EIO - Input/output error (can be transient with ptys)
                        # Check if process is still running
                        if process.poll() is None:
                            # Process still running, this might be a transient error
                            # Process any buffered data and continue
                            consecutive_errors += 1
                            if consecutive_errors <= max_consecutive_errors:
                                # Process any complete lines in buffer
                                if '\n' in buffer:
                                    lines = buffer.split('\n')
                                    buffer = lines[-1]
                                    for line in lines[:-1]:
                                        if line and line.strip():
                                            # Processing buffered line after error
                                            _process_log_line(process, line, line_count, recent_prompts)
                                            line_count += 1
                                    consecutive_errors = 0  # Reset on successful processing
                                # Small delay before retrying
                                import time
                                time.sleep(0.2)  # Slightly longer delay for I/O errors
                                continue
                            else:
                                print(f"[ERROR] Too many consecutive I/O errors ({consecutive_errors}). Process still running but pty may be broken.")
                                # Process any remaining buffer before giving up
                                if buffer:
                                    # Processing final buffer
                                    if '\n' in buffer:
                                        lines = buffer.split('\n')
                                        for line in lines:
                                            if line and line.strip():
                                                _process_log_line(process, line, line_count, recent_prompts)
                                                line_count += 1
                                break
                        else:
                            # Process ended, break normally
                            break
                    else:
                        # Other I/O error - check if process is still running
                        if process.poll() is None:
                            print(f"[WARNING] I/O error (errno {e.errno}), but process still running. Continuing...")
                            # Process any buffered data
                            if '\n' in buffer:
                                lines = buffer.split('\n')
                                buffer = lines[-1]
                                for line in lines[:-1]:
                                    if line and line.strip():
                                        _process_log_line(process, line, line_count, recent_prompts)
                                        line_count += 1
                            import time
                            time.sleep(0.1)
                            continue
                        else:
                            raise
                else:
                    # No errno, but process might still be running
                    if process.poll() is None:
                        print(f"[WARNING] I/O error (no errno), but process still running. Continuing...")
                        import time
                        time.sleep(0.1)
                        continue
                    else:
                        raise
            except Exception as e:
                # Check if process is still running before giving up
                if process.poll() is None:
                    print(f"[WARNING] Error reading from process (but process still running): {e}")
                    import traceback
                    traceback.print_exc()
                    # Process any buffered data
                    if '\n' in buffer:
                        lines = buffer.split('\n')
                        buffer = lines[-1]
                        for line in lines[:-1]:
                            if line and line.strip():
                                _process_log_line(process, line, line_count, recent_prompts)
                                line_count += 1
                    import time
                    time.sleep(0.5)  # Longer delay for unexpected errors
                    continue
                else:
                    print(f"[ERROR] Error reading from process: {e}")
                    import traceback
                    traceback.print_exc()
                    break
            
            # Always process complete lines from buffer at end of loop iteration
            # This ensures we don't miss any lines even if there are errors
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                if line and line.strip():
                    # Processing final buffer line
                    _process_log_line(process, line, line_count, recent_prompts)
                    line_count += 1
            
            # Check buffer for prompt-like patterns even without newlines
            # This helps detect prompts that are waiting for input (no newline yet)
            # Check every iteration if buffer unchanged, or every 2 iterations otherwise
            buffer_check_counter += 1
            should_check_prompt = False
            if buffer and len(buffer.strip()) > 10:
                buffer_stripped = buffer.strip()
                buffer_lower = buffer_stripped.lower()
                
                # Quick check: does buffer look like it might be a prompt?
                looks_like_prompt = (
                    (buffer_lower.endswith(':') or buffer_lower.endswith('?')) and
                    ('enter' in buffer_lower or 'select' in buffer_lower or 'choose' in buffer_lower or 'essid' in buffer_lower)
                )
                
                # Check every iteration if buffer unchanged (likely a prompt waiting) or looks like prompt
                if buffer_unchanged_count >= 2 or looks_like_prompt:
                    should_check_prompt = True
                # Otherwise check every 2 iterations
                elif buffer_check_counter % 2 == 0:
                    should_check_prompt = True
                
                # Debug output when buffer looks like prompt but we're not checking
                if looks_like_prompt and not should_check_prompt and buffer_check_counter % 10 == 0:
                    pass
            
            if should_check_prompt:
                buffer_stripped = buffer.strip()
                buffer_lower = buffer_stripped.lower()
                buffer_hash = hash(buffer_stripped)
                
                # Check if buffer looks like a prompt (ends with : or ?, or contains prompt keywords)
                prompt_indicators = [
                    buffer_lower.endswith(':') and ('enter' in buffer_lower or 'select' in buffer_lower or 'choose' in buffer_lower),
                    buffer_lower.endswith('?') and ('enter' in buffer_lower or 'select' in buffer_lower),
                    'enter the network' in buffer_lower and (buffer_lower.endswith(':') or buffer_lower.endswith('?')),
                    'enter ' in buffer_lower and (':' in buffer_stripped or '?' in buffer_stripped),
                    'essid' in buffer_lower and ('enter' in buffer_lower or 'select' in buffer_lower) and (buffer_lower.endswith(':') or buffer_lower.endswith('?')),
                ]
                matched_indicators = [i for i, matched in enumerate(prompt_indicators) if matched]
                if any(prompt_indicators):
                    if buffer_hash not in recent_prompts:
                        # Process the buffer as a potential prompt (even without newline)
                        # Detected potential prompt in buffer (debug output removed)
                        # Prompt indicators matched (debug output removed)
                        _process_log_line(process, buffer_stripped, line_count, recent_prompts)
                        recent_prompts.add(buffer_hash)
                        line_count += 1
                        # Clear the buffer after processing prompt to prevent re-detection
                        # The prompt has been sent to frontend, we don't need it in buffer anymore
                        buffer = ''
                        last_buffer_size = 0
                        buffer_unchanged_count = 0
                        # Cleared buffer after prompt detection (debug output removed)
                    else:
                        if buffer_check_counter % 20 == 0:  # Only log occasionally
                            # Prompt already processed (debug output removed)
                            pass
                        # If prompt already processed and buffer hasn't changed, clear it to prevent stuck buffer
                        if buffer_unchanged_count > 50:  # Buffer stuck for ~2.5 seconds
                            buffer = ''
                            last_buffer_size = 0
                            buffer_unchanged_count = 0
                else:
                    # Debug why it didn't match - log when buffer looks like it should match
                    if (buffer_lower.endswith(':') or buffer_lower.endswith('?')) and ('enter' in buffer_lower or 'essid' in buffer_lower):
                        if buffer_check_counter % 10 == 0:  # Log occasionally
                            debug_print(f"Buffer looks like prompt but not checking yet: {buffer_stripped[:80]}")
                # Clean up old prompt hashes (keep last 10)
                if len(recent_prompts) > 10:
                    recent_prompts.clear()
            
            # Update buffer tracking for unchanged detection
            if len(buffer) != last_buffer_size:
                last_buffer_size = len(buffer)
                buffer_unchanged_count = 0
            else:
                buffer_unchanged_count += 1
    except Exception as e:
        print(f"[ERROR] Error in read_process_logs: {e}")
        print(f"[ERROR] Buffer at error time: {buffer[:200] if 'buffer' in locals() and buffer else 'empty'}")
        print(f"[ERROR] Process still running: {process.poll() is None if process else 'N/A'}")
        print(f"[ERROR] Loop iteration: {loop_iteration if 'loop_iteration' in locals() else 'N/A'}")
        import traceback
        traceback.print_exc()
        # Process any remaining buffer before exiting
        if buffer:
            try:
                if '\n' in buffer:
                    for line in buffer.split('\n'):
                        if line and line.strip():
                            _process_log_line(process, line, line_count, recent_prompts)
                            line_count += 1
                else:
                    if buffer.strip():
                        _process_log_line(process, buffer.strip(), line_count)
            except Exception as buffer_err:
                print(f"[ERROR] Error processing final buffer: {buffer_err}")
    finally:
        # Log reader thread ending (debug output removed)
        # Final buffer state (debug output removed)
        mifi_status['running'] = False
        mifi_status['mode'] = None
        mifi_status['pid'] = None

_ANSI_RE = __import__('re').compile(r'\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def _queue_put_nowait(entry):
    """Non-blocking put -- drops oldest on overflow instead of blocking."""
    try:
        mifi_log_queue.put_nowait(entry)
    except __import__('queue').Full:
        try:
            mifi_log_queue.get_nowait()
            mifi_log_queue.put_nowait(entry)
        except Exception:
            pass

def _process_log_line(process, line, line_count, recent_prompts=None):
    """Process a single log line and detect prompts"""
    try:
        line = _ANSI_RE.sub('', line)
        if not line.strip():
            return
        parsed = parse_log_line(line.strip())
        message = parsed.get('message', '').strip()
        
        # Filter out verbose initialization and directory checking messages
        message_lower = message.lower()
        
        # Pre-filter: structural patterns that are always raw ip-link / TXQ stats
        import re as _re2
        if _re2.match(r'^\d+:\s+\w+:', message) or _re2.match(r'^\s*\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+', message):
            return
        
        if any(skip in message_lower for skip in [
            'checking system directory structure',
            "base directory '",
            "directory '",
            "' exists",
            'collect-manual parameters:',
            'search:',
            'initial scan timeout:',
            'target:',
            'target monitor timeout:',
            'deauth packets:',
            'configuring interface...',
            'found monitor interface for',
            'response submitted:',
            'exiting manual mode...',
            'mode: collect-manual complete',
            # Filter airodump-ng CSV/screen-refresh output
            'bssid, first time seen',
            'station mac,',
            'not associated',
            # wpapcap2john raw stdout
            'essids processed',
            'ap/sta pairs processed',
            'handshakes written',
            'rsn ie pmkids',
            ': eof',
            # iwconfig output lines
            'unassociated',
            'nickname:',
            'mode:monitor',
            'sensitivity:',
            'encryption key:',
            'link quality:',
            'rx invalid',
            'tx excessive',
            'missed beacon:',
            'access point: not-associated',
            'frequency=',
            # airmon-ng verbose lines
            'mac80211 monitor mode',
            'already enabled for',
            # airmon/iw/ip-link raw verbose output
            'phy#',
            'driver',
            'chipset',
            'monitor mode enabled',
            'managed mode enabled',
            'txpower',
            'ieee 802.11',
            'frequency:',
            'tx-power=',
            'retry',
            'rts thr:',
            'fragment thr:',
            'power management:',
            # Raw iw dev / ip link output lines
            'ifindex ',
            'wdev 0x',
            'qsz-byt',
            'qsz-pkt',
            'multicast txq',
            'link/ieee802.11',
            'broadcast,allmulti',
            'notrailers',
            'link/ether',
            'center1:',
            'rtw_8812au',
            # GPS internal polling debug
            'gps tpv data:',
            'gps mode=0',
            'gps mode=1',
            'gps attempting lock:',
            'gps receiving valid coordinates:',
            'gps polling thread started',
            '.gps-stub',
        ]):
            # Skip verbose messages but still process prompts
            if not any(prompt_indicator in message_lower for prompt_indicator in [
                'enter', 'select', 'choose', 'press', 'password'
            ]):
                return
        
        # TAK CoT sending is now handled entirely in mifi.py
        # The dashboard only displays logs - all TAK functionality is in mifi.py
        
        _queued_already = False
        
        line_lower = line.lower().strip()
        line_stripped = line.strip()
        
        # Clear recent_prompts when a new scan starts (new iteration)
        if 'detected networks' in line_lower:
            if recent_prompts is not None:
                recent_prompts.clear()
        
        is_prompt = False
        prompt_type = 'input'
        
        # TAK password prompt (must be checked first)
        # Only process if we don't already have a password callback (to avoid duplicate prompts)
        if ('pkcs#12 certificate password' in line_lower or 'certificate password' in line_lower or 'invalid password' in line_lower or 'please try again' in line_lower):
            # Check if we have a tak_password_callback - if so, don't create duplicate prompt from log
            # The callback will handle the prompt itself
            if mifi_service and hasattr(mifi_service, 'tak_password_callback') and mifi_service.tak_password_callback:
                # Password callback exists - let it handle the prompt, don't create duplicate from log
                debug_print("TAK password prompt detected in log, but callback exists - skipping duplicate prompt")
                return
            
            is_prompt = True
            prompt_type = 'password'
            parsed['tak_password_prompt'] = True
            if 'invalid password' in line_lower or 'please try again' in line_lower:
                parsed['message'] = 'Invalid password. Please enter PKCS#12 certificate password again:'
            else:
                parsed['message'] = 'Enter PKCS#12 certificate password:'
            prompt_id = f'tak_password_{int(time.time() * 1000)}'
            parsed['prompt'] = {
                'id': prompt_id,
                'message': parsed['message'],
                'type': 'password',
                'tak_password': True
            }
            # Detected TAK password prompt in log (debug output removed)
            _queue_put_nowait(parsed)
            return
        # Config mode: wireless interface prompt
        elif 'wireless interface' in line_lower and 'monitor mode' in line_lower:
            is_prompt = True
            prompt_type = 'input'
        # Collect-manual mode: Network ESSID prompt
        elif line_lower.startswith('enter the network') or 'enter the network' in line_lower or 'enter the network essid' in line_lower:
            is_prompt = True
            prompt_type = 'input'
        # Process-manual mode: file path prompt
        elif 'full path of the file to process' in line_lower or ('file to process' in line_lower and 'q to quit' in line_lower):
            is_prompt = True
            prompt_type = 'input'
        # Process-manual mode: processing option number prompt
        elif 'enter option number' in line_lower or ('option number' in line_lower and line_lower.endswith(':')):
            is_prompt = True
            prompt_type = 'input'
        # Generic prompts: starts with "enter" and has colon/question
        elif line_lower.startswith('enter ') and (':' in line_stripped or '?' in line_stripped):
            is_prompt = True
            prompt_type = 'input'
        # Generic prompts: starts with "input:"
        elif line_lower.startswith('input:') or line_lower.startswith('input '):
            is_prompt = True
            prompt_type = 'input'
        # Generic prompts: ends with colon/question and contains prompt keywords
        elif (line_lower.endswith(':') or line_lower.endswith('?')) and any(kw in line_lower for kw in ['enter', 'select', 'choose', 'press']):
            is_prompt = True
            prompt_type = 'input'
        # Generic ESSID prompts
        elif 'essid' in line_lower and ('enter' in line_lower or 'select' in line_lower or 'choose' in line_lower) and (line_lower.endswith(':') or line_lower.endswith('?')):
            is_prompt = True
            prompt_type = 'input'
        
        if is_prompt:
            prompt_id = f"prompt_{int(time.time() * 1000)}"
            prompt_msg = parsed.get('message', line.strip())
            prompt_msg = re.sub(r'\s+\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s*$', '', prompt_msg).strip()
            prompt_msg = re.sub(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s*', '', prompt_msg).strip()
            
            parsed['prompt'] = {
                'id': prompt_id,
                'message': prompt_msg,
                'type': prompt_type
            }
            if not parsed.get('message') or not parsed['message'].strip():
                parsed['message'] = prompt_msg
            _queue_put_nowait(parsed)
            _queued_already = True
            # Prompt queued for immediate delivery (debug output removed)
        if not _queued_already:
            _queue_put_nowait(parsed)
    except Exception as e:
        error_msg = f'Error processing log line: {str(e)}'
        print(f"[ERROR] {error_msg}")
        import traceback
        traceback.print_exc()
        error_data = {'message': error_msg, 'level': 'error'}
        try:
            _queue_put_nowait(error_data)
        except:
            pass

@app.route('/api/prompt/response', methods=['POST'])
def api_prompt_response():
    """Send response to interactive prompt"""
    data = request.json
    prompt_id = data.get('id')
    response = data.get('response')
    
    if prompt_id and mifi_process and mifi_process.poll() is None:
        try:
            if response is not None:
                prompt_responses[prompt_id] = response
                # Use stdin_file (pty) if available, otherwise use stdin (pipe)
                stdin = getattr(mifi_process, 'stdin_file', None) or mifi_process.stdin
                if stdin and not stdin.closed:
                    stdin.write(str(response) + '\n')
                    stdin.flush()
                return jsonify({'success': True})
            else:
                prompt_responses[prompt_id] = None
                return jsonify({'success': True})
        except (BrokenPipeError, OSError) as e:
            return jsonify({'success': False, 'error': 'Process stdin unavailable'})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
    
    return jsonify({'success': False, 'error': 'No active prompt or process'})

@app.route('/api/tak/password', methods=['POST'])
def api_tak_password():
    """Provide TAK certificate password"""
    data = request.json
    password = data.get('password', '')
    tak_password_queue.put(password)
    return jsonify({'success': True})

@app.route('/api/interface/prompt', methods=['POST'])
def api_interface_prompt():
    """Handle interface name prompt response"""
    global mifi_service
    data = request.json
    prompt_id = data.get('prompt_id')
    interface_name = data.get('interface', '').strip()
    
    if not prompt_id or not interface_name:
        return jsonify({'success': False, 'error': 'Missing prompt_id or interface name'}), 400
    
    # Store the response
    if prompt_id in interface_prompt_responses:
        interface_prompt_responses[prompt_id].put(interface_name)
        
        # Try to enable monitor mode with the provided interface
        try:
            if mifi_service is None:
                from mifi import wifi_cracker
                mifi_service = wifi_cracker()
                mifi_service.initial_config()
                mifi_service.debug = DEBUG_MODE  # Apply debug setting from environment
            
            # Validate interface exists
            result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=2, check=True)
            all_interfaces = re.findall(r'Interface\s+(\S+)', result.stdout)
            base_ifaces = [iface for iface in all_interfaces if not iface.endswith('mon')]
            
            if interface_name not in base_ifaces:
                error_msg = f'Invalid interface: {interface_name}. Available: {", ".join(base_ifaces)}'
                log_entry = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'message': error_msg,
                    'level': 'error',
                    'prefix': '[!]'
                }
                mifi_log_queue.put(log_entry)
                return jsonify({'success': False, 'error': error_msg}), 400
            
            # Enable monitor mode
            try:
                subprocess.run(['sudo', 'airmon-ng', 'start', interface_name], check=True, timeout=10)
                # Find the new monitor interface
                result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=2, check=True)
                interfaces = re.findall(r'Interface\s+(\S+)', result.stdout)
                monitor_iface = None
                for iface in interfaces:
                    try:
                        iwconfig_result = subprocess.run(['iwconfig', iface], capture_output=True, text=True, timeout=1)
                        if 'Mode:Monitor' in iwconfig_result.stdout:
                            monitor_iface = iface
                            break
                    except:
                        continue
                
                if monitor_iface:
                    # Update config
                    mifi_service._update_config(interface_name)
                    mifi_service.interface = monitor_iface
                    
                    log_entry = {
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'message': f'Monitor mode enabled on {monitor_iface}',
                        'level': 'success',
                        'prefix': '[✓]'
                    }
                    mifi_log_queue.put(log_entry)
                    return jsonify({
                        'success': True,
                        'status': 'monitor_mode',
                        'interface': monitor_iface,
                        'message': f'Monitor mode enabled on {monitor_iface}'
                    })
                else:
                    error_msg = 'Failed to find monitor interface after enabling'
                    log_entry = {
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'message': error_msg,
                        'level': 'error',
                        'prefix': '[!]'
                    }
                    mifi_log_queue.put(log_entry)
                    return jsonify({'success': False, 'error': error_msg}), 500
            except subprocess.CalledProcessError as e:
                error_msg = f'Failed to enable monitor mode: {e}'
                log_entry = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'message': error_msg,
                    'level': 'error',
                    'prefix': '[!]'
                }
                mifi_log_queue.put(log_entry)
                return jsonify({'success': False, 'error': error_msg}), 500
        except Exception as e:
            error_msg = f'Error enabling monitor mode: {e}'
            print(f"[ERROR] {error_msg}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'error': error_msg}), 500
    else:
        return jsonify({'success': False, 'error': 'Invalid or expired prompt_id'}), 400

@app.route('/api/interface/toggle', methods=['POST'])
def api_interface_toggle():
    """Toggle monitor mode on/off"""
    global mifi_service
    
    # Initialize shared service if needed
    if mifi_service is None:
        try:
            from mifi import wifi_cracker
            mifi_service = wifi_cracker()
            mifi_service.initial_config()
            mifi_service.debug = DEBUG_MODE  # Apply debug setting from environment
        except Exception as e:
            print(f"[ERROR] Failed to initialize mifi_service: {e}")
            return jsonify({'success': False, 'error': f'Failed to initialize service: {e}'}), 500
    
    try:
        # Check current monitor mode status
        current_status = check_interface_status()
        # Interface toggle called (debug output removed)
        
        if current_status == 'monitor_mode':
            # Disable monitor mode - find the monitor interface and stop it
            try:
                result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=2, check=True)
                interfaces = re.findall(r'Interface\s+(\S+)', result.stdout)
                
                monitor_iface = None
                for iface in interfaces:
                    try:
                        iwconfig_result = subprocess.run(['iwconfig', iface], capture_output=True, text=True, timeout=1)
                        if 'Mode:Monitor' in iwconfig_result.stdout:
                            monitor_iface = iface
                            break
                    except:
                        continue
                
                if monitor_iface:
                    # Stop monitor mode using airmon-ng
                    try:
                        subprocess.run(['sudo', 'airmon-ng', 'stop', monitor_iface], check=True, timeout=10)
                        log_entry = {
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'message': f'Monitor mode disabled on {monitor_iface}',
                            'level': 'success',
                            'prefix': '[✓]'
                        }
                        mifi_log_queue.put(log_entry)
                        return jsonify({
                            'success': True,
                            'status': 'managed_mode',
                            'message': f'Monitor mode disabled on {monitor_iface}'
                        })
                    except subprocess.CalledProcessError as e:
                        error_msg = f'Failed to disable monitor mode: {e}'
                        print(f"[ERROR] {error_msg}")
                        log_entry = {
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'message': error_msg,
                            'level': 'error',
                            'prefix': '[!]'
                        }
                        mifi_log_queue.put(log_entry)
                        return jsonify({'success': False, 'error': error_msg}), 500
                else:
                    error_msg = 'Monitor mode interface not found'
                    print(f"[ERROR] {error_msg}")
                    return jsonify({'success': False, 'error': error_msg}), 500
            except Exception as e:
                error_msg = f'Error disabling monitor mode: {e}'
                print(f"[ERROR] {error_msg}")
                import traceback
                traceback.print_exc()
                return jsonify({'success': False, 'error': error_msg}), 500
        else:
            # Enable monitor mode - use mifi_service's configure_interface
            
            # Check if we need to prompt for interface
            config = configparser.ConfigParser()
            config_path = os.path.join(os.path.dirname(__file__), 'config', 'config.ini')
            config.read(config_path)
            
            candidates = []
            if "DEFAULT" in config and "monitor_candidates" in config["DEFAULT"]:
                candidates = [iface.strip() for iface in config["DEFAULT"]["monitor_candidates"].split(",")]
            
            # Get all interfaces
            try:
                result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, timeout=2, check=True)
                all_interfaces = re.findall(r'Interface\s+(\S+)', result.stdout)
            except:
                all_interfaces = []
            
            # Check if any candidate interfaces exist
            base_ifaces = [iface for iface in all_interfaces if not iface.endswith('mon')]
            available_candidates = [c for c in candidates if c in base_ifaces]
            
            # If no candidates available, prompt for interface
            if not available_candidates and base_ifaces:
                log_entry = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'message': 'Available interfaces to enable monitor mode:',
                    'level': 'info',
                    'prefix': '[*]'
                }
                mifi_log_queue.put(log_entry)
                
                # List available interfaces
                for iface in base_ifaces:
                    log_entry = {
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'message': f'  {iface}',
                        'level': 'info',
                        'prefix': '  '
                    }
                    mifi_log_queue.put(log_entry)
                
                # Prompt for interface name
                prompt_id = f'interface_prompt_{int(time.time() * 1000)}'
                prompt_data = {
                    'id': prompt_id,
                    'message': 'Enter your wireless interface to put into monitor mode (e.g., wlan1):',
                    'type': 'text',
                    'interface_prompt': True
                }
                log_entry = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'message': 'Enter your wireless interface to put into monitor mode (e.g., wlan1):',
                    'level': 'info',
                    'prefix': '[*]',
                    'prompt': prompt_data
                }
                mifi_log_queue.put(log_entry)
                
                # Store prompt ID for response handling
                interface_prompt_responses[prompt_id] = queue.Queue()
                
                # Return immediately with prompt info
                return jsonify({
                    'success': True,
                    'prompt': True,
                    'prompt_id': prompt_id,
                    'message': 'Please enter interface name in the log prompt'
                })
            
            # Try to enable monitor mode using mifi_service
            try:
                # Use mifi_service's configure_interface method
                # This will handle the logic automatically
                if mifi_service.configure_interface():
                    log_entry = {
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'message': f'Monitor mode enabled on {mifi_service.interface}',
                        'level': 'success',
                        'prefix': '[✓]'
                    }
                    mifi_log_queue.put(log_entry)
                    return jsonify({
                        'success': True,
                        'status': 'monitor_mode',
                        'interface': mifi_service.interface,
                        'message': f'Monitor mode enabled on {mifi_service.interface}'
                    })
                else:
                    error_msg = 'Failed to enable monitor mode'
                    log_entry = {
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'message': error_msg,
                        'level': 'error',
                        'prefix': '[!]'
                    }
                    mifi_log_queue.put(log_entry)
                    return jsonify({'success': False, 'error': error_msg}), 500
            except Exception as e:
                error_msg = f'Error enabling monitor mode: {e}'
                print(f"[ERROR] {error_msg}")
                import traceback
                traceback.print_exc()
                log_entry = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'message': error_msg,
                    'level': 'error',
                    'prefix': '[!]'
                }
                mifi_log_queue.put(log_entry)
                return jsonify({'success': False, 'error': error_msg}), 500
    except Exception as e:
        error_msg = f'Error in interface toggle: {e}'
        print(f"[ERROR] {error_msg}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': error_msg}), 500

@app.route('/api/gps/toggle', methods=['POST'])
def api_gps_toggle():
    """Toggle GPS monitoring on/off - uses mifi.py's native GPS service"""
    global mifi_service
    
    # Check if verbose mode is requested in request body
    data = request.json if request.is_json else {}
    verbose_requested = data.get('verbose', False) if isinstance(data, dict) else False
    
    # Initialize shared service if needed
    if mifi_service is None:
        try:
            from mifi import wifi_cracker
            mifi_service = wifi_cracker()
            mifi_service.initial_config()
            mifi_service.verbose = verbose_requested
            mifi_service.debug = DEBUG_MODE
            
            # Set up GPS status callback for dashboard visualization
            def gps_status_update(status):
                """Callback from mifi.py GPS polling to update dashboard status"""
                global mifi_status
                mifi_status['gps_status'] = status
                # GPS is enabled if status is not 'disabled'
                mifi_status['gps_enabled'] = (status != 'disabled')
                save_state()
            
            mifi_service.gps_status_callback = gps_status_update
        except Exception as e:
            print(f"[ERROR] Failed to initialize MiFi service: {e}")
            return jsonify({'success': False, 'error': f'Failed to initialize service: {e}'}), 500
    
    try:
        # Check if GPS is currently running
        gps_running = False
        if mifi_service:
            if mifi_service.gps_lock.acquire(blocking=True, timeout=0.1):
                try:
                    gps_running = (mifi_service.gps_thread and mifi_service.gps_thread.is_alive())
                finally:
                    mifi_service.gps_lock.release()
        
        if gps_running:
            # Stop GPS polling
            if mifi_service:
                mifi_service.stop_gps_polling()
            mifi_status['gps_enabled'] = False
            mifi_status['gps_status'] = 'disabled'
            save_state()
            
            status_details = {
                'enabled': False,
                'status': 'disabled',
                'message': 'GPS monitoring disabled'
            }
            return jsonify({'success': True, 'enabled': False, 'details': status_details})
        else:
            # Enable GPS monitoring (network gpsd -- no local USB device check)
            if verbose_requested:
                mifi_service.verbose = True
            if mifi_service.start_gps_polling():
                mifi_status['gps_enabled'] = True
                mifi_status['gps_status'] = 'searching'
                save_state()
                gps_target = f"{mifi_service.gps_network_host}:{mifi_service.gps_network_port}"
                status_details = {
                    'enabled': True,
                    'status': 'searching',
                    'message': f'GPS monitoring enabled - connecting to gpsd at {gps_target}...'
                }
                return jsonify({'success': True, 'enabled': True, 'details': status_details})
            else:
                current_status = getattr(mifi_service, 'gps_status', 'no_data')
                mifi_status['gps_status'] = current_status
                mifi_status['gps_enabled'] = False
                save_state()
                gps_target = f"{mifi_service.gps_network_host}:{mifi_service.gps_network_port}"
                status_details = {
                    'enabled': False,
                    'status': current_status,
                    'message': f'Could not reach gpsd at {gps_target}. Confirm gpsd-overwatch.service is running there.'
                }
                return jsonify({'success': False, 'enabled': False, 'details': status_details})
    except Exception as e:
        print(f"[ERROR] Error in GPS toggle: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e), 'enabled': False}), 500

# ===== DASHBOARD API ROUTES =====

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

@app.route('/api/captures')
def list_captures():
    """
    Returns capture inventory grouped by ESSID -- one entry per unique network,
    each containing its captures[] array. Each capture contains its
    processing_runs[] and crack_results[]. Drives the three-level Analysis tab
    table: ESSID row > capture sub-row > attempt sub-sub-row.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM captures WHERE cap_deleted = 0 ORDER BY captured_at DESC')
    all_caps = [dict(row) for row in c.fetchall()]

    for cap in all_caps:
        c.execute('SELECT * FROM processing_runs WHERE capture_id = ? ORDER BY started_at', (cap['id'],))
        cap['processing_runs'] = [dict(r) for r in c.fetchall()]
        c.execute('SELECT * FROM crack_results WHERE capture_id = ? ORDER BY cracked_at', (cap['id'],))
        cap['crack_results'] = [dict(r) for r in c.fetchall()]
        if cap['crack_results']:
            cap['status'] = 'cracked'
        elif any(r['status'] == 'running' for r in cap['processing_runs']):
            cap['status'] = 'processing'
        elif cap['processing_runs']:
            cap['status'] = 'attempted'
        else:
            cap['status'] = 'unprocessed'

    # Group by ESSID
    seen = {}
    for cap in all_caps:
        essid = cap['essid']
        if essid not in seen:
            seen[essid] = {'essid': essid, 'bssid': cap['bssid'], 'captures': [],
                           'gps_lat': None, 'gps_lon': None}
        seen[essid]['captures'].append(cap)
        if cap['gps_lat'] and not seen[essid]['gps_lat']:
            seen[essid]['gps_lat'] = cap['gps_lat']
            seen[essid]['gps_lon'] = cap['gps_lon']

    grouped = list(seen.values())
    for g in grouped:
        statuses = [cap['status'] for cap in g['captures']]
        if 'cracked' in statuses:
            g['status'] = 'cracked'
            g['password'] = next((cr['password'] for cap in g['captures']
                                  for cr in cap['crack_results']), None)
        elif 'processing' in statuses:
            g['status'] = 'processing'; g['password'] = None
        elif 'attempted' in statuses:
            g['status'] = 'attempted'; g['password'] = None
        else:
            g['status'] = 'unprocessed'; g['password'] = None

    conn.close()
    return jsonify(grouped)


@app.route('/api/captures/<int:capture_id>/process', methods=['POST'])
def process_capture(capture_id):
    """
    Launches mifi.py --mode analyze for a single capture/tool, reusing the
    same PTY subprocess + log-streaming infrastructure as /api/start (see
    read_process_logs) so output appears in the Analysis tab's log panel
    exactly like Control tab operations.
    """
    global mifi_process, mifi_status

    if mifi_status.get('running'):
        return jsonify({'success': False, 'error': 'Another operation is already running'}), 409

    data = request.get_json() or {}
    tool = data.get('tool')
    if tool not in ('aircrack', 'jtr', 'hashcat'):
        return jsonify({'success': False, 'error': 'tool must be aircrack, jtr, or hashcat'}), 400
    word_list = data.get('wordlist', 'config/rockyou.txt')

    cmd = ['sudo', '-E', 'python3', '-u', os.path.join(os.path.dirname(__file__), 'mifi.py'),
           '--mode', 'analyze', '-CID', str(capture_id), '-TOOL', tool, '-WL', word_list]

    env = os.environ.copy()
    env['PYTHONUNBUFFERED'] = '1'
    gps_active = (mifi_service and mifi_service.gps_thread and mifi_service.gps_thread.is_alive())
    env['MIFI_GPS_ACTIVE'] = '1' if gps_active else '0'

    try:
        if sys.platform != 'win32':
            master_fd, slave_fd = pty.openpty()
            try:
                winsize = struct.pack('HHHH', 24, 80, 0, 0)
                fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, winsize)
            except Exception:
                pass
            mifi_process = subprocess.Popen(
                cmd, stdout=slave_fd, stderr=slave_fd, stdin=slave_fd,
                env=env, start_new_session=True
            )
            os.close(slave_fd)
            process_stdout = os.fdopen(master_fd, 'r', buffering=1)
            stdin_fd = os.dup(master_fd)
            process_stdin = os.fdopen(stdin_fd, 'w', buffering=1)
            mifi_process.stdin_file = process_stdin
            mifi_process.stdout_file = process_stdout
        else:
            mifi_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, stdin=subprocess.PIPE, env=env
            )
            process_stdout = mifi_process.stdout
            mifi_process.stdin_file = mifi_process.stdin
            mifi_process.stdout_file = process_stdout

        mifi_status['running'] = True
        mifi_status['mode'] = f'analyze-{tool}'
        mifi_status['pid'] = mifi_process.pid
        mifi_status['start_time'] = datetime.now().isoformat()

        threading.Thread(target=read_process_logs, args=(mifi_process, process_stdout), daemon=True).start()

        return jsonify({'success': True, 'pid': mifi_process.pid})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/captures/<int:capture_id>/delete', methods=['POST'])
def delete_capture(capture_id):
    """
    Manual delete for a capture the user has given up on cracking -- removes
    the .cap from disk and marks cap_deleted=1. Mirrors mifi.py's
    delete_capture_file() but implemented directly here so it doesn't depend
    on mifi_service being initialized (the Analysis tab should work even if
    no operation has been launched yet this session).
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT cap_filename, cap_deleted FROM captures WHERE id = ?", (capture_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'error': 'capture not found'}), 404

    cap_filename, already_deleted = row
    if not already_deleted and cap_filename:
        cap_path = os.path.join(os.path.dirname(__file__), 'collection', cap_filename)
        if os.path.exists(cap_path):
            try:
                os.remove(cap_path)
            except OSError as e:
                conn.close()
                return jsonify({'success': False, 'error': f'Failed to delete file: {e}'}), 500

    c.execute("UPDATE captures SET cap_deleted = 1 WHERE id = ?", (capture_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/data')
def get_data():
    db = DB_PATH  # Always use absolute path
    session_id = request.args.get('session_id')
    essid = request.args.get('essid')
    bssid = request.args.get('bssid')
    essid_search = request.args.get('essid_search')  # Partial match search
    bssid_search = request.args.get('bssid_search')  # Partial match search
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
        # Support multiple ESSIDs (comma-separated)
        essid_list = [e.strip() for e in essid.split(',') if e.strip()]
        if essid_list:
            placeholders = ','.join(['?'] * len(essid_list))
            query += f' AND essid IN ({placeholders})'
            params.extend(essid_list)
    elif essid_search:
        query += ' AND essid LIKE ?'
        params.append(f'%{essid_search}%')
    if bssid:
        # Support multiple BSSIDs (comma-separated)
        bssid_list = [b.strip() for b in bssid.split(',') if b.strip()]
        if bssid_list:
            placeholders = ','.join(['?'] * len(bssid_list))
            query += f' AND bssid IN ({placeholders})'
            params.extend(bssid_list)
    elif bssid_search:
        query += ' AND bssid LIKE ?'
        params.append(f'%{bssid_search}%')
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

@app.route('/favicon.ico')
def favicon():
    # Return empty response for favicon to prevent 404 errors
    from flask import Response
    return Response('', mimetype='image/x-icon', status=204)

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

@app.route('/dashboard')
def dashboard():
    """Serve the full dashboard interface"""
    try:
        dashboard_html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>MiFi Visualizer</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" href="data:,">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.7.1/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.7.1/dist/leaflet.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/leaflet.heat@0.2.0/dist/leaflet-heat.min.js"></script>
    <style>
        :root {
            --bg-primary: #1a1a1a;
            --bg-secondary: #2d2d2d;
            --bg-tertiary: #252525;
            --text-primary: #e0e0e0;
            --text-secondary: #ccc;
            --text-muted: #888;
            --border-color: #404040;
            --input-bg: #1a1a1a;
            --input-border: #444;
            --shadow: rgba(0,0,0,0.3);
            --shadow-hover: rgba(0,0,0,0.5);
        }
        [data-theme="dark"] {
            --bg-primary: #1a1a1a;
            --bg-secondary: #2d2d2d;
            --bg-tertiary: #252525;
            --text-primary: #e0e0e0;
            --text-secondary: #ccc;
            --text-muted: #888;
            --border-color: #404040;
            --input-bg: #1a1a1a;
            --input-border: #444;
            --shadow: rgba(0,0,0,0.3);
            --shadow-hover: rgba(0,0,0,0.5);
        }
        body, #dashboardContainer { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            margin: 0; 
            padding: 0; 
            background: var(--bg-primary);
            color: var(--text-primary);
            transition: background 0.3s, color 0.3s;
        }
        #toolbar {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            color: var(--text-primary);
            padding: 0;
            box-shadow: 0 2px 12px var(--shadow);
            border-radius: 0 0 12px 12px;
            margin-bottom: 8px;
            position: relative;
            z-index: 1001;
            transition: background 0.3s, box-shadow 0.3s;
        }
        .toolbar-main {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 16px;
            padding: 14px 20px;
            border-bottom: 1px solid var(--border-color);
        }
        .toolbar-advanced {
            display: block;
            padding: 20px;
            background: var(--bg-tertiary);
            border-top: 1px solid var(--border-color);
            border-radius: 0 0 12px 12px;
        }
        .filter-item {
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .filter-item label {
            font-weight: 500;
            font-size: 0.9em;
            color: var(--text-secondary);
            white-space: nowrap;
        }
        .filter-item select, .filter-item input[type=number], .filter-item input[type=text], .filter-item input[type=date], .filter-item input[type=search] {
            padding: 6px 10px;
            border-radius: 6px;
            border: 1px solid #444;
            font-size: 0.9em;
            background: #1a1a1a;
            color: #e0e0e0;
            transition: all 0.2s;
            min-width: 120px;
        }
        .filter-item select:focus, .filter-item input:focus {
            outline: none;
            border-color: #4CAF50;
            box-shadow: 0 0 0 3px rgba(76, 175, 80, 0.2);
        }
        .filter-item select:disabled, .filter-item input:disabled {
            background: var(--bg-tertiary);
            color: var(--text-muted);
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
            background: #4CAF50;
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
            background: #45a049;
            transform: translateY(-1px);
            box-shadow: 0 2px 6px rgba(0,0,0,0.3);
        }
        button:active {
            transform: translateY(0);
        }
        button.danger {
            background: #f44336;
        }
        button.danger:hover {
            background: #da190b;
        }
        button.secondary {
            background: #2d2d2d;
            color: #ccc;
            border: 1px solid #444;
        }
        button.secondary:hover {
            background: #3d3d3d;
        }
        button.expand-toggle {
            background: #2d2d2d;
            color: #ccc;
            border: 1px solid #444;
            padding: 6px 12px;
            font-size: 0.85em;
        }
        button.expand-toggle:hover {
            background: #3d3d3d;
        }
        #status {
            margin-left: auto;
            font-size: 0.9em;
            color: var(--text-muted);
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 10px;
            background: rgba(76, 175, 80, 0.2);
            color: #4CAF50;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .status-badge.error {
            background: rgba(244, 67, 54, 0.2);
            color: #f44336;
        }
        .status-badge.warning {
            background: rgba(255, 152, 0, 0.2);
            color: #ff9800;
        }
        .status-badge.success {
            background: rgba(76, 175, 80, 0.2);
            color: #4CAF50;
        }
        [data-theme="dark"] .status-badge {
            background: rgba(76, 175, 80, 0.2);
        }
        [data-theme="dark"] .status-badge.error {
            background: rgba(244, 67, 54, 0.2);
            color: #f44336;
        }
        [data-theme="dark"] .status-badge.warning {
            background: rgba(255, 152, 0, 0.2);
            color: #ff9800;
        }
        [data-theme="dark"] .status-badge.success {
            background: rgba(76, 175, 80, 0.2);
            color: #4CAF50;
        }
        #map-container {
            display: flex;
            gap: 12px;
            width: 100%;
            height: calc(100vh - 250px);
            min-height: 500px;
            position: relative;
        }
        #map { 
            height: 100%;
            flex: 1;
            border-radius: 12px; 
            box-shadow: 0 2px 12px rgba(0,0,0,0.08);
            position: relative;
        }
        #data-table-panel {
            width: 600px;
            min-width: 400px;
            max-width: 800px;
            background: var(--bg-secondary);
            border-radius: 12px;
            box-shadow: 0 2px 12px var(--shadow);
            display: flex;
            flex-direction: column;
            transition: width 0.3s ease, min-width 0.3s ease, max-width 0.3s ease;
            overflow: hidden;
            height: calc(100vh - 250px);
            min-height: 500px;
        }
        #data-table-panel.collapsed {
            width: 0;
            min-width: 0;
            max-width: 0;
            padding: 0;
            border: none;
            overflow: hidden;
        }
        .data-table-header {
            padding: 12px 16px;
            background: linear-gradient(135deg, var(--bg-tertiary) 0%, var(--border-color) 100%);
            border-bottom: 2px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            flex-shrink: 0;
            user-select: none;
        }
        .data-table-header:hover {
            background: linear-gradient(135deg, var(--border-color) 0%, var(--bg-tertiary) 100%);
        }
        .data-table-title {
            font-weight: 600;
            color: var(--text-primary);
            font-size: 0.95em;
        }
        .data-table-toggle {
            background: none;
            border: none;
            color: var(--text-secondary);
            font-size: 1.2em;
            cursor: pointer;
            padding: 0;
            width: 24px;
            height: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: transform 0.2s;
        }
        .data-table-toggle:hover {
            color: var(--text-primary);
            transform: scale(1.1);
        }
        #data-table-content {
            flex: 1;
            display: block;
            position: relative;
            min-height: 0;
            overflow-y: auto;
            overflow-x: auto;
        }
        #data-table-content.collapsed {
            display: none;
        }
        /* Custom scrollbar for data table */
        #data-table-content::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        #data-table-content::-webkit-scrollbar-track {
            background: var(--bg-tertiary);
            border-radius: 4px;
        }
        #data-table-content::-webkit-scrollbar-thumb {
            background: var(--text-muted);
            border-radius: 4px;
        }
        #data-table-content::-webkit-scrollbar-thumb:hover {
            background: var(--text-secondary);
        }
        .data-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85em;
            table-layout: auto;
        }
        .data-table thead {
            position: sticky;
            top: 0;
            background: var(--bg-tertiary);
            z-index: 10;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .data-table th {
            padding: 10px 8px;
            text-align: left;
            font-weight: 600;
            color: var(--text-secondary);
            border-bottom: 2px solid var(--border-color);
            background: var(--bg-tertiary);
            white-space: nowrap;
            font-size: 0.8em;
            position: sticky;
            top: 0;
        }
        .data-table td {
            padding: 8px;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-primary);
            white-space: nowrap;
            font-size: 0.85em;
        }
        .data-table tbody tr {
            cursor: pointer;
            transition: background-color 0.15s, transform 0.1s;
        }
        .data-table tbody tr:hover {
            background-color: rgba(0, 102, 255, 0.1);
            transform: translateX(2px);
        }
        .data-table tbody tr.highlighted {
            background-color: rgba(0, 102, 255, 0.2) !important;
            font-weight: 500;
        }
        .data-table tbody tr.marker-highlighted {
            background-color: rgba(255, 193, 7, 0.3) !important;
            box-shadow: inset 3px 0 0 #ff9800;
        }
        .data-table tbody tr:active {
            background-color: rgba(0, 102, 255, 0.15);
        }
        .legend {
            position: absolute;
            bottom: 30px;
            right: 30px;
            background: var(--bg-secondary);
            padding: 12px 16px;
            border-radius: 8px;
            box-shadow: 0 2px 8px var(--shadow);
            z-index: 1000;
            min-width: 200px;
            display: none;
            cursor: default;
            user-select: none;
            max-width: calc(100% - 60px);
            max-height: calc(100% - 60px);
            overflow-y: auto;
        }
        .legend.visible {
            display: block;
        }
        .legend.dragging {
            opacity: 0.8;
            box-shadow: 0 4px 12px var(--shadow-hover);
        }
        .legend-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border-color);
            cursor: move;
            user-select: none;
        }
        .legend-drag-handle {
            color: var(--text-muted);
            font-size: 0.9em;
            margin-right: 8px;
        }
        .legend-drag-handle:hover {
            color: var(--text-secondary);
        }
        .legend-title {
            font-weight: 600;
            margin: 0;
            color: var(--text-primary);
            font-size: 0.9em;
            flex: 1;
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
            border: 1px solid var(--border-color);
            flex-shrink: 0;
        }
        .legend-label {
            color: var(--text-secondary);
        }
        .color-editor {
            background: var(--bg-secondary);
            padding: 16px;
            border-radius: 8px;
            box-shadow: 0 2px 8px var(--shadow);
            margin-top: 12px;
            border-top: 1px solid var(--border-color);
        }
        .color-editor-title {
            font-weight: 600;
            margin-bottom: 12px;
            color: var(--text-primary);
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
            display: flex;
            flex-direction: column;
            gap: 20px;
            margin-bottom: 12px;
        }
        .filter-row {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
        }
        .filter-row-second {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
        }
        .filter-row-second .advanced-filter-group {
            gap: 6px;
        }
        .filter-row-second .filter-item {
            margin-bottom: 0;
        }
        .advanced-filter-group {
            display: flex;
            flex-direction: column;
            gap: 8px;
            padding: 0 8px;
            box-sizing: border-box;
        }
        .advanced-filter-group label {
            font-size: 0.85em;
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-size: 0.75em;
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
        .toggle-switch {
            display: flex;
            align-items: center;
            gap: 10px;
            cursor: pointer;
            user-select: none;
        }
        .toggle-switch input[type="checkbox"] {
            display: none;
        }
        .toggle-slider {
            position: relative;
            width: 44px;
            height: 24px;
            background: var(--input-border);
            border-radius: 24px;
            transition: background 0.3s;
        }
        .toggle-slider::before {
            content: '';
            position: absolute;
            width: 18px;
            height: 18px;
            border-radius: 50%;
            background: white;
            top: 3px;
            left: 3px;
            transition: transform 0.3s;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        .toggle-switch input:checked + .toggle-slider {
            background: #0066ff;
        }
        .toggle-switch input:checked + .toggle-slider::before {
            transform: translateX(20px);
        }
        .toggle-label {
            font-size: 0.9em;
            color: var(--text-secondary);
            font-weight: 500;
        }
        .toolbar-actions {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-top: 16px;
            padding-top: 16px;
            border-top: 1px solid var(--border-color);
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
            background-color: #2d2d2d;
            margin: 15% auto;
            padding: 28px;
            border-radius: 12px;
            width: 90%;
            max-width: 500px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.5);
            animation: modalSlideIn 0.3s ease;
            border: 1px solid #444;
        }
        @keyframes modalSlideIn {
            from { transform: translateY(-20px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        .modal-header {
            font-size: 1.4em;
            font-weight: 600;
            margin-bottom: 16px;
            color: #fff;
        }
        .modal-body {
            margin-bottom: 24px;
            color: #e0e0e0;
            line-height: 1.6;
        }
        #takPasswordInput {
            background-color: #1a1a1a;
            color: #e0e0e0;
            border: 1px solid #444 !important;
        }
        #takPasswordInput:focus {
            outline: none;
            border-color: #0066ff !important;
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
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .marker-label {
            background: rgba(255, 255, 255, 0.9);
            border: 2px solid #000;
            border-radius: 4px;
            padding: 2px 6px;
            font-size: 0.75em;
            font-weight: bold;
            pointer-events: none;
            text-shadow: 1px 1px 1px rgba(255,255,255,0.8);
            -webkit-text-stroke: 0.5px #000;
            text-stroke: 0.5px #000;
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
        .context-menu {
            position: absolute;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            box-shadow: 0 4px 12px var(--shadow-hover);
            padding: 8px 0;
            min-width: 280px;
            z-index: 2000;
            display: none;
            font-size: 0.9em;
        }
        .context-menu.visible {
            display: block;
        }
        .context-menu-item {
            padding: 10px 16px;
            cursor: pointer;
            color: var(--text-primary);
            transition: background 0.15s;
            border-bottom: 1px solid var(--border-color);
        }
        .context-menu-item:last-child {
            border-bottom: none;
        }
        .context-menu-item:hover {
            background: var(--bg-tertiary);
        }
        .context-menu-label {
            font-weight: 600;
            color: var(--text-secondary);
            font-size: 0.85em;
            padding: 6px 16px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid var(--border-color);
        }
        .context-menu-value {
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: var(--text-primary);
            word-break: break-all;
            user-select: all;
        }
        .context-menu-copy {
            font-size: 0.8em;
            color: var(--text-muted);
            margin-top: 4px;
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
            .filter-row, .filter-row-second {
                grid-template-columns: 1fr;
            }
            #map-container { 
                flex-direction: column; 
                height: calc(100vh - 250px);
                min-height: 500px;
            }
            #map { 
                height: 50%;
                min-height: 300px;
            }
            #data-table-panel { 
                width: 100%; 
                height: 50%;
                min-height: 300px;
            }
            #data-table-panel.collapsed { 
                height: 0;
                min-height: 0;
            }
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
            <button id="labelToggle" title="Toggle plot labels (L)" class="secondary">
                <span id="labelToggleText">Show Labels</span><span class="keyboard-hint">(L)</span>
            </button>
            <button id="legendToggle" title="Toggle color legend" class="secondary">
                <span id="legendToggleText">Show Legend</span>
            </button>
            <button id="dataTableToggleBtn" title="Toggle data table (T)" class="secondary">
                <span id="dataTableToggleText">Show Table</span><span class="keyboard-hint">(T)</span>
            </button>
            <div class="divider"></div>
            <button id="exportBtn" title="Export data to CSV" class="secondary">
                <span>📥 Export</span>
            </button>
            <button id="refreshBtn" title="Refresh data (R)">Refresh<span class="keyboard-hint">(R)</span></button>
            <div id="status">
                <span class="status-badge" id="statusBadgeGPS">0 GPS Plots</span>
                <span class="status-badge" id="statusBadgeNetworks" style="margin-left: 8px;">0 Networks</span>
            </div>
        </div>
        <div id="toolbarAdvanced" class="toolbar-advanced">
            <div class="advanced-filters">
                <div class="filter-row">
                    <div class="advanced-filter-group">
                        <label>Session Filter</label>
                        <div class="filter-item">
                            <select id="sessionSelect" title="Filter by session"></select>
                        </div>
                    </div>
                    <div class="advanced-filter-group">
                        <label>ESSID Filter</label>
                        <div class="filter-item">
                            <select id="essidSelect" multiple size="5" title="Select one or more ESSIDs (hold Ctrl/Cmd to select multiple)">
                                <option value="">All ESSIDs</option>
                            </select>
                            <button type="button" onclick="toggleSelectAll('essidSelect')" class="secondary" style="margin-top: 4px; padding: 4px 8px; font-size: 0.8em; width: 100%;">Select All</button>
                            <small style="display: block; margin-top: 4px; color: #666; font-size: 11px;">Hold Ctrl/Cmd to select multiple</small>
                        </div>
                    </div>
                    <div class="advanced-filter-group">
                        <label>BSSID Filter</label>
                        <div class="filter-item">
                            <select id="bssidSelect" multiple size="5" title="Select one or more BSSIDs (hold Ctrl/Cmd to select multiple)">
                                <option value="">All BSSIDs</option>
                            </select>
                            <button type="button" onclick="toggleSelectAll('bssidSelect')" class="secondary" style="margin-top: 4px; padding: 4px 8px; font-size: 0.8em; width: 100%;">Select All</button>
                            <small style="display: block; margin-top: 4px; color: #666; font-size: 11px;">Hold Ctrl/Cmd to select multiple</small>
                        </div>
                    </div>
                    <div class="advanced-filter-group">
                        <label>Channel Filter</label>
                        <div class="filter-item">
                            <input id="channelFilter" type="text" placeholder="1,6,11" title="Channels (comma-separated)">
                        </div>
                    </div>
                </div>
                <div class="filter-row-second">
                    <div class="advanced-filter-group">
                        <label>Signal Range (dBm)</label>
                        <div class="filter-item">
                            <input id="minSignal" type="number" min="-150" max="0" step="1" value="-150" title="Min signal (dBm)" placeholder="Min">
                        </div>
                        <div class="filter-item">
                            <input id="maxSignal" type="number" min="-150" max="0" step="1" value="0" title="Max signal (dBm)" placeholder="Max">
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
                        <label>Altitude Range (m)</label>
                        <div class="filter-item">
                            <input id="minAlt" type="number" step="0.1" placeholder="Min altitude" title="Minimum altitude">
                        </div>
                        <div class="filter-item">
                            <input id="maxAlt" type="number" step="0.1" placeholder="Max altitude" title="Maximum altitude">
                        </div>
                    </div>
                    <div></div>
                </div>
            </div>
            <div class="toolbar-actions">
                <label class="toggle-switch">
                    <input type="checkbox" id="autoReposition" checked>
                    <span class="toggle-slider"></span>
                    <span class="toggle-label">Auto Reposition Map</span>
                </label>
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
    <div id="takPasswordModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">TAK Certificate Password Required</div>
            <div class="modal-body" id="takPasswordModalBody">
                <p id="takPasswordMessage">Enter PKCS#12 certificate password:</p>
                <input type="password" id="takPasswordInput" placeholder="Enter password..." style="width: 100%; padding: 10px; margin-top: 10px; font-size: 1em; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box;">
                <p id="takPasswordError" style="color: #f44336; margin-top: 10px; display: none;"></p>
            </div>
            <div class="modal-footer">
                <button onclick="closeTakPasswordModal()" class="secondary">Cancel</button>
                <button onclick="submitTakPassword()" class="btn-primary">Submit</button>
            </div>
        </div>
    </div>
    <div id="contextMenu" class="context-menu"></div>
    <div id="map-container">
        <div id="map"></div>
        <div id="legend" class="legend">
            <div class="legend-header">
                <span class="legend-drag-handle" title="Drag to move">☰</span>
                <div class="legend-title">Signal Strength (dBm)</div>
            </div>
            <div id="legendContent"></div>
            <div id="heatmapControls" style="display: none; margin-top: 10px; padding-top: 10px; border-top: 1px solid #ddd;">
                <label style="display: block; margin-bottom: 5px; font-size: 12px; font-weight: bold;">Transparency:</label>
                <input type="range" id="heatmapTransparency" min="0.1" max="1.0" step="0.1" value="0.9" style="width: 100%;">
                <div style="display: flex; justify-content: space-between; font-size: 10px; color: #666; margin-top: 2px;">
                    <span>Transparent</span>
                    <span id="transparencyValue">90%</span>
                    <span>Opaque</span>
                </div>
            </div>
            <div class="color-editor" id="colorEditor" style="display:none;">
                <div class="color-editor-title">Custom Color Thresholds</div>
                <div id="colorThresholds"></div>
                <button class="add-threshold-btn secondary" onclick="addColorThreshold()">+ Add Threshold</button>
            </div>
            <button onclick="toggleColorEditor()" class="secondary" style="margin-top:8px;width:100%;font-size:0.85em;">Edit Colors</button>
        </div>
        <div id="data-table-panel">
            <div class="data-table-header" onclick="toggleDataTable()">
                <span class="data-table-title">Data Table</span>
                <button class="data-table-toggle" id="dataTableToggle" title="Toggle data table">▼</button>
            </div>
            <div id="data-table-content">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>ESSID</th>
                            <th>BSSID</th>
                            <th>Signal</th>
                            <th>Channel</th>
                            <th>Latitude</th>
                            <th>Longitude</th>
                            <th>Altitude</th>
                            <th>Timestamp</th>
                        </tr>
                    </thead>
                    <tbody id="data-table-body">
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <script>
        // Prevent redeclaration errors - check if already initialized
        if (typeof window.dashboardInitialized === 'undefined' || !window.dashboardInitialized) {
            window.dashboardInitialized = true;
        
        // Global variables - declare only if not already declared
        if (typeof window.dashboardMap === 'undefined') {
            window.dashboardMap = null;
            window.dashboardLabelsEnabled = false;
            window.dashboardLegendVisible = false;
            window.dashboardColorThresholds = [
                {low: 0, high: -20, color: '#ff00f7'},
                {low: -20, high: -40, color: '#0066ff'},
                {low: -40, high: -60, color: '#00ff00'},
                {low: -60, high: -80, color: '#ffff00'},
                {low: -80, high: -100, color: '#ff8800'},
                {low: -100, high: -120, color: '#ff0000'},
            ];
            // Network count color thresholds for GPS location markers
            // Colors inverted: 0 networks = magenta (best), 16+ = red (worst)
            window.dashboardNetworkCountThresholds = [
                {min: 0, max: 0, color: '#ff00f7'},
                {min: 1, max: 3, color: '#0066ff'},
                {min: 4, max: 8, color: '#00ff00'},
                {min: 9, max: 12, color: '#ffff00'},
                {min: 13, max: 15, color: '#ff8800'},
                {min: 16, max: 9999, color: '#ff0000'},
            ];
            window.dashboardOsmLayer = null;
            window.dashboardSatLayer = null;
            window.dashboardCurrentBaseLayer = null;
            window.dashboardMarkers = [];
            window.dashboardHeatLayer = null;
            window.dashboardDataTableRows = [];
            window.dashboardMarkerToRowMap = new Map();
            window.dashboardRowToMarkerMap = new Map();
            window.dashboardDataTableCollapsed = false;
            window.dashboardContextMenu = null;
        }
        
        // Create local references for convenience
        // Helper function to get current map instance
        function getMap() {
            return map || window.dashboardMap;
        }
        var map = window.dashboardMap;
        var labelsEnabled = window.dashboardLabelsEnabled;
        var legendVisible = window.dashboardLegendVisible;
        var colorThresholds = window.dashboardColorThresholds;
        var networkCountThresholds = window.dashboardNetworkCountThresholds || [
            {min: 0, max: 0, color: '#ff00f7'},
            {min: 1, max: 3, color: '#0066ff'},
            {min: 4, max: 8, color: '#00ff00'},
            {min: 9, max: 12, color: '#ffff00'},
            {min: 13, max: 15, color: '#ff8800'},
            {min: 16, max: 9999, color: '#ff0000'},
        ];
        var osmLayer = window.dashboardOsmLayer;
        var satLayer = window.dashboardSatLayer;
        var currentBaseLayer = window.dashboardCurrentBaseLayer;
        var markers = window.dashboardMarkers;
        var heatLayer = window.dashboardHeatLayer;
        var dataTableRows = window.dashboardDataTableRows;
        var markerToRowMap = window.dashboardMarkerToRowMap;
        var rowToMarkerMap = window.dashboardRowToMarkerMap;
        var dataTableCollapsed = window.dashboardDataTableCollapsed;
        var contextMenu = window.dashboardContextMenu;
        
        // Convert lat/lon to MGRS (Military Grid Reference System)
        function latLonToMGRS(lat, lon) {
            // Simplified MGRS conversion - for production use a proper library
            // This is a basic approximation
            const zone = Math.floor((lon + 180) / 6) + 1;
            const latBand = 'CDEFGHJKLMNPQRSTUVWX'[Math.floor((lat + 80) / 8)];
            const easting = ((lon + 180) % 6) * 100000;
            const northing = (lat + 80) % 8 * 100000;
            return `${zone}${latBand} ${Math.floor(easting/1000)} ${Math.floor(northing/1000)}`;
        }
        
        // Convert lat/lon to UTM
        function latLonToUTM(lat, lon) {
            const zone = Math.floor((lon + 180) / 6) + 1;
            const isNorthern = lat >= 0;
            const hemisphere = isNorthern ? 'N' : 'S';
            // Simplified UTM - for production use proper conversion
            return `UTM Zone ${zone}${hemisphere}`;
        }
        
        // Convert lat/lon to DMS (Degrees Minutes Seconds)
        function latLonToDMS(lat, lon) {
            function toDMS(decimal, isLat) {
                const abs = Math.abs(decimal);
                const degrees = Math.floor(abs);
                const minutes = Math.floor((abs - degrees) * 60);
                const seconds = ((abs - degrees) * 60 - minutes) * 60;
                const dir = isLat ? (decimal >= 0 ? 'N' : 'S') : (decimal >= 0 ? 'E' : 'W');
                return `${degrees}°${minutes}'${seconds.toFixed(2)}"${dir}`;
            }
            return {
                lat: toDMS(lat, true),
                lon: toDMS(lon, false)
            };
        }
        
        // Show context menu with coordinates
        function showContextMenu(e, lat, lon) {
            e.preventDefault();
            e.stopPropagation();
            
            const menu = document.getElementById('contextMenu');
            if (!menu) return;
            
            const dms = latLonToDMS(lat, lon);
            const mgrs = latLonToMGRS(lat, lon);
            const utm = latLonToUTM(lat, lon);
            
            menu.innerHTML = `
                <div class="context-menu-label">Coordinates</div>
                <div class="context-menu-item">
                    <div style="font-weight: 600; margin-bottom: 4px;">Decimal Degrees</div>
                    <div class="context-menu-value">${lat.toFixed(8)}, ${lon.toFixed(8)}</div>
                    <div class="context-menu-copy">Click to copy</div>
                </div>
                <div class="context-menu-item">
                    <div style="font-weight: 600; margin-bottom: 4px;">Degrees Minutes Seconds</div>
                    <div class="context-menu-value">${dms.lat}, ${dms.lon}</div>
                    <div class="context-menu-copy">Click to copy</div>
                </div>
                <div class="context-menu-item">
                    <div style="font-weight: 600; margin-bottom: 4px;">MGRS</div>
                    <div class="context-menu-value">${mgrs}</div>
                    <div class="context-menu-copy">Click to copy</div>
                </div>
                <div class="context-menu-item">
                    <div style="font-weight: 600; margin-bottom: 4px;">UTM</div>
                    <div class="context-menu-value">${utm}</div>
                    <div class="context-menu-copy">Click to copy</div>
                </div>
                <div class="context-menu-item">
                    <div style="font-weight: 600; margin-bottom: 4px;">Google Maps</div>
                    <div class="context-menu-value">https://maps.google.com/?q=${lat},${lon}</div>
                    <div class="context-menu-copy">Click to copy</div>
                </div>
            `;
            
            // Position menu at cursor
            menu.style.left = e.pageX + 'px';
            menu.style.top = e.pageY + 'px';
            menu.classList.add('visible');
            
            // Add click handlers to copy values
            menu.querySelectorAll('.context-menu-item').forEach(item => {
                item.addEventListener('click', function() {
                    const valueDiv = this.querySelector('.context-menu-value');
                    if (valueDiv) {
                        const text = valueDiv.textContent.trim();
                        navigator.clipboard.writeText(text).then(() => {
                            const copyDiv = this.querySelector('.context-menu-copy');
                            if (copyDiv) {
                                const original = copyDiv.textContent;
                                copyDiv.textContent = 'Copied!';
                                setTimeout(() => {
                                    copyDiv.textContent = original;
                                }, 1000);
                            }
                        }).catch(err => {
                            console.error('Failed to copy:', err);
                        });
                    }
                });
            });
            
            contextMenu = { lat, lon };
        }
        
        // Hide context menu
        function hideContextMenu() {
            const menu = document.getElementById('contextMenu');
            if (menu) {
                menu.classList.remove('visible');
            }
            contextMenu = null;
        }
        
        function clearMarkers() {
            // Ensure map is available
            const currentMap = map || window.dashboardMap;
            if (currentMap) {
                markers.forEach(m => currentMap.removeLayer(m));
                if (heatLayer) { currentMap.removeLayer(heatLayer); heatLayer = null; }
            }
            markers = [];
            dataTableRows = [];
            essidTableGroups = {};
            markerToRowMap.clear();
            rowToMarkerMap.clear();
            const tbody = document.getElementById('data-table-body');
            if (tbody) tbody.innerHTML = '';
        }
        
        function toggleDataTable() {
            dataTableCollapsed = !dataTableCollapsed;
            const panel = document.getElementById('data-table-panel');
            const content = document.getElementById('data-table-content');
            const toggle = document.getElementById('dataTableToggle');
            const toggleBtn = document.getElementById('dataTableToggleBtn');
            const toggleText = document.getElementById('dataTableToggleText');
            
            if (dataTableCollapsed) {
                panel.classList.add('collapsed');
                content.classList.add('collapsed');
                toggle.textContent = '▶';
                if (toggleText) toggleText.textContent = 'Show Table';
            } else {
                panel.classList.remove('collapsed');
                content.classList.remove('collapsed');
                toggle.textContent = '▼';
                if (toggleText) toggleText.textContent = 'Hide Table';
            }
            
            // Invalidate map size to recalculate viewport after panel resize
            setTimeout(() => {
                // Ensure map is available
                const currentMap = map || window.dashboardMap;
                if (currentMap) {
                    currentMap.invalidateSize();
                }
            }, 350); // Wait for CSS transition to complete
        }
        window.toggleDataTable = toggleDataTable;
        // Convert signal strength (dBm) to estimated distance (meters)
        // Based on US FCC regulations for WiFi:
        // - 2.4 GHz: Max 30 dBm (1W) EIRP, typical consumer routers: 15-20 dBm (32-100 mW)
        // - 5 GHz: Max 30 dBm EIRP for some bands, typically 15-23 dBm
        // Using Friis transmission equation with path loss model
        // Reference power at 1m for typical consumer router (20 dBm = 100 mW): ~-30 dBm
        function signalToDistance(signalDbm, referencePower = -30) {
            // US WiFi regulations (FCC Part 15):
            // - 2.4 GHz (802.11b/g/n): Max 30 dBm (1W) EIRP, typical consumer: 15-20 dBm (32-100 mW)
            // - Most consumer routers: 20 dBm (100 mW) transmit power
            // 
            // Free space path loss at 2.4 GHz:
            // PL(d) = 20*log10(4*π*d*f/c) where f=2.4e9 Hz, c=3e8 m/s
            // At 1m: PL(1m) = 20*log10(4*π*1*2.4e9/3e8) ≈ 40 dB
            // 
            // For 20 dBm transmitter, received power at 1m = 20 - 40 = -20 dBm (free space)
            // But in real environments with obstacles, typical is -30 to -35 dBm at 1m
            // 
            // Using log-distance path loss model:
            // PL(d) = PL(d0) + 10*n*log10(d/d0)
            // Where n = path loss exponent (2.0 free space, 2.5-4.0 real environments)
            
            const transmitPower = 20; // dBm (typical US consumer router, 100 mW)
            const pathLossExponent = 2.5; // Typical for suburban/urban environments
            const referenceDistance = 1; // 1 meter
            const pathLossAtReference = 50; // dB at 1m (20 dBm tx - (-30) dBm rx = 50 dB typical)
            
            // Calculate total path loss from transmit to receive
            const totalPathLoss = transmitPower - signalDbm;
            
            // Calculate distance using log-distance model
            // PL(d) = PL(d0) + 10*n*log10(d/d0)
            // Rearranging: d = d0 * 10^((PL(d) - PL(d0)) / (10*n))
            const distance = referenceDistance * Math.pow(10, (totalPathLoss - pathLossAtReference) / (10 * pathLossExponent));
            
            // No maximum cap - sensors may be at different altitudes (ground level, aerial, etc.)
            return Math.max(0.1, distance); // Minimum 0.1m to avoid division issues
        }
        
        // Calculate confidence score for location estimation
        // Returns object with score (0-100) and reasons
        function calculateConfidence(readings) {
            let score = 0;
            let reasons = [];
            let warnings = [];
            
            // 1. Sample size check (0-35 points) - Primary factor for confidence
            const minReadings = 3;
            const idealReadings = 5;
            const excellentReadings = 10;
            if (readings.length < minReadings) {
                reasons.push(`Insufficient readings (${readings.length} < ${minReadings} minimum)`);
                return { score: 0, reasons: reasons, warnings: warnings, pass: false };
            }
            if (readings.length >= excellentReadings) {
                score += 35;
                reasons.push(`Excellent sample size (${readings.length} readings)`);
            } else if (readings.length >= idealReadings) {
                score += 30;
                reasons.push(`Good sample size (${readings.length} readings)`);
            } else {
                score += (readings.length / idealReadings) * 30;
                reasons.push(`Adequate sample size (${readings.length} readings)`);
            }
            
            // 2. Signal variance check (0-30 points) - Primary factor for confidence
            // Higher variance indicates better triangulation data
            const signals = readings.map(r => r.signal);
            const avgSignal = signals.reduce((a, b) => a + b, 0) / signals.length;
            const signalVariance = signals.reduce((sum, s) => sum + Math.pow(s - avgSignal, 2), 0) / signals.length;
            const signalStdDev = Math.sqrt(signalVariance);
            
            // Signal variance scoring: more variance = better (indicates movement/spread)
            if (signalStdDev >= 15) {
                score += 30; // Excellent variance - good spread of signal strengths
                reasons.push(`Excellent signal variance (std dev: ${signalStdDev.toFixed(1)} dBm)`);
            } else if (signalStdDev >= 10) {
                score += 25; // Good variance
                reasons.push(`Good signal variance (std dev: ${signalStdDev.toFixed(1)} dBm)`);
            } else if (signalStdDev >= 5) {
                score += 15; // Adequate variance
                reasons.push(`Adequate signal variance (std dev: ${signalStdDev.toFixed(1)} dBm)`);
            } else {
                warnings.push('Low signal variance - readings may be too close together');
                score += 5; // Low variance - readings too similar
            }
            
            // 3. Location variance check (0-35 points) - Primary factor for confidence
            // Higher spatial spread indicates better triangulation
            const lats = readings.map(r => r.lat);
            const lons = readings.map(r => r.lon);
            const latRange = Math.max(...lats) - Math.min(...lats);
            const lonRange = Math.max(...lons) - Math.min(...lons);
            
            // Convert to approximate meters (rough estimate: 1 degree ≈ 111km)
            const latRangeMeters = latRange * 111000;
            const lonRangeMeters = lonRange * 111000 * Math.cos((Math.max(...lats) + Math.min(...lats)) / 2 * Math.PI / 180);
            const maxRange = Math.max(latRangeMeters, lonRangeMeters);
            
            // Location variance scoring: optimal range is 20-100m for good triangulation
            if (maxRange >= 20 && maxRange <= 100) {
                score += 35; // Excellent spatial distribution for triangulation
                reasons.push(`Excellent spatial distribution (${maxRange.toFixed(0)}m spread)`);
            } else if (maxRange >= 10 && maxRange < 20) {
                score += 25; // Good but could be better
                reasons.push(`Good spatial distribution (${maxRange.toFixed(0)}m spread)`);
            } else if (maxRange >= 5 && maxRange < 10) {
                score += 15; // Adequate
                reasons.push(`Adequate spatial distribution (${maxRange.toFixed(0)}m spread)`);
            } else if (maxRange > 100 && maxRange <= 500) {
                score += 20; // Very spread out but still usable
                warnings.push('Readings far apart - may affect accuracy');
                reasons.push(`Wide spatial distribution (${maxRange.toFixed(0)}m spread)`);
            } else if (maxRange > 500) {
                warnings.push('Readings very far apart - may be different access points');
                score += 10;
            } else {
                warnings.push('Readings too close together - poor spatial distribution');
                score += 5; // Too close - poor triangulation
            }
            
            // 4. Distance validation (0-15 points)
            // Check if estimated distances are reasonable
            // Note: No hard cap on distance - sensors may be at different altitudes
            const distances = readings.map(r => signalToDistance(r.signal));
            const avgDistance = distances.reduce((a, b) => a + b, 0) / distances.length;
            const maxDistance = Math.max(...distances);
            
            if (maxDistance > 1000) {
                warnings.push('Estimated distances very large - may be inaccurate or sensor at high altitude');
                score += 5;
            } else if (avgDistance <= 200 && maxDistance <= 500) {
                score += 15;
                reasons.push(`Reasonable distance estimates (avg: ${avgDistance.toFixed(0)}m)`);
            } else if (avgDistance <= 500) {
                score += 12;
                reasons.push(`Acceptable distance estimates (avg: ${avgDistance.toFixed(0)}m)`);
            } else {
                score += 8;
                warnings.push('Large distance estimates - sensor may be at high altitude');
                reasons.push(`Distance estimates (avg: ${avgDistance.toFixed(0)}m)`);
            }
            
            // Ensure score is between 0 and 100
            score = Math.max(0, Math.min(100, score));
            
            // Minimum confidence threshold: 50 points
            const minConfidence = 50;
            const pass = score >= minConfidence;
            
            if (!pass) {
                reasons.push(`Confidence score ${score.toFixed(0)}/100 below minimum threshold (${minConfidence})`);
            }
            
            return {
                score: Math.round(score),
                reasons: reasons,
                warnings: warnings,
                pass: pass,
                avgSignal: avgSignal.toFixed(1),
                avgDistance: avgDistance.toFixed(1),
                spatialSpread: maxRange.toFixed(0)
            };
        }
        
        // Estimate source location using trilateration or weighted centroid
        function estimateSourceLocation(readings) {
            if (readings.length < 2) return null;
            
            // Convert signal strengths to distance estimates
            let points = readings.map(r => ({
                lat: r.lat,
                lon: r.lon,
                distance: signalToDistance(r.signal),
                signal: r.signal
            }));
            
            // If we have exactly 3 points, use trilateration
            if (points.length === 3) {
                return trilaterate(points[0], points[1], points[2]);
            }
            
            // For more than 3 points, use weighted centroid
            // Weight by inverse distance (stronger signal = closer = more weight)
            let totalWeight = 0;
            let weightedLat = 0;
            let weightedLon = 0;
            
            points.forEach(p => {
                // Weight inversely proportional to estimated distance
                // Stronger signals (closer) get more weight
                let weight = 1 / (p.distance + 1); // +1 to avoid division by zero
                totalWeight += weight;
                weightedLat += p.lat * weight;
                weightedLon += p.lon * weight;
            });
            
            if (totalWeight === 0) return null;
            
            return {
                lat: weightedLat / totalWeight,
                lon: weightedLon / totalWeight
            };
        }
        
        // Trilateration using three circles
        function trilaterate(p1, p2, p3) {
            // Convert lat/lon to meters for calculation
            // Using Haversine formula for distance between two lat/lon points
            function haversineDistance(lat1, lon1, lat2, lon2) {
                const R = 6371000; // Earth radius in meters
                const dLat = (lat2 - lat1) * Math.PI / 180;
                const dLon = (lon2 - lon1) * Math.PI / 180;
                const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
                    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
                    Math.sin(dLon/2) * Math.sin(dLon/2);
                const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
                return R * c;
            }
            
            // Convert to local coordinate system (meters) relative to p1
            const lat1 = p1.lat;
            const lon1 = p1.lon;
            const d12 = haversineDistance(lat1, lon1, p2.lat, p2.lon);
            const d13 = haversineDistance(lat1, lon1, p3.lat, p3.lon);
            
            // Calculate bearing from p1 to p2 and p1 to p3
            function bearing(lat1, lon1, lat2, lon2) {
                const dLon = (lon2 - lon1) * Math.PI / 180;
                const lat1Rad = lat1 * Math.PI / 180;
                const lat2Rad = lat2 * Math.PI / 180;
                const y = Math.sin(dLon) * Math.cos(lat2Rad);
                const x = Math.cos(lat1Rad) * Math.sin(lat2Rad) - 
                         Math.sin(lat1Rad) * Math.cos(lat2Rad) * Math.cos(dLon);
                return Math.atan2(y, x);
            }
            
            const bearing12 = bearing(lat1, lon1, p2.lat, p2.lon);
            const bearing13 = bearing(lat1, lon1, p3.lat, p3.lon);
            
            // Convert to local x,y coordinates (meters)
            const x2 = d12 * Math.sin(bearing12);
            const y2 = d12 * Math.cos(bearing12);
            const x3 = d13 * Math.sin(bearing13);
            const y3 = d13 * Math.cos(bearing13);
            
            const r1 = p1.distance;
            const r2 = p2.distance;
            const r3 = p3.distance;
            
            // Trilateration calculation using intersecting circles
            // Since p1 is at origin (0,0), we have:
            // Circle 1: x² + y² = r1²
            // Circle 2: (x-x2)² + (y-y2)² = r2²
            // Circle 3: (x-x3)² + (y-y3)² = r3²
            //
            // Subtracting circle 1 from circle 2:
            // (x-x2)² + (y-y2)² - (x² + y²) = r2² - r1²
            // x² - 2x2*x + x2² + y² - 2y2*y + y2² - x² - y² = r2² - r1²
            // -2x2*x - 2y2*y = r2² - r1² - x2² - y2²
            // x2*x + y2*y = (r1² - r2² + x2² + y2²) / 2
            //
            // Similarly for circle 3:
            // x3*x + y3*y = (r1² - r3² + x3² + y3²) / 2
            
            const A = x2;
            const B = y2;
            const C = (r1 * r1 - r2 * r2 + x2 * x2 + y2 * y2) / 2;
            const D = x3;
            const E = y3;
            const F = (r1 * r1 - r3 * r3 + x3 * x3 + y3 * y3) / 2;
            
            // Solve system: A*x + B*y = C, D*x + E*y = F
            const denominator = A * E - B * D;
            if (Math.abs(denominator) < 1e-10) {
                // Circles are collinear, fall back to weighted centroid
                let totalWeight = 0;
                let weightedLat = 0;
                let weightedLon = 0;
                [p1, p2, p3].forEach(p => {
                    let weight = 1 / (p.distance + 1);
                    totalWeight += weight;
                    weightedLat += p.lat * weight;
                    weightedLon += p.lon * weight;
                });
                if (totalWeight === 0) return null;
                return {
                    lat: weightedLat / totalWeight,
                    lon: weightedLon / totalWeight
                };
            }
            
            const x = (C * E - B * F) / denominator;
            const y = (A * F - C * D) / denominator;
            
            // Convert back to lat/lon
            const distance = Math.sqrt(x * x + y * y);
            const bearingAngle = Math.atan2(x, y);
            
            // Convert distance and bearing back to lat/lon
            const R = 6371000; // Earth radius in meters
            const lat = lat1 + (distance * Math.cos(bearingAngle) / R) * 180 / Math.PI;
            const lon = lon1 + (distance * Math.sin(bearingAngle) / (R * Math.cos(lat1 * Math.PI / 180))) * 180 / Math.PI;
            
            return { lat: lat, lon: lon };
        }
        
        function plotData(data) {
            // Ensure map is available - use window.dashboardMap if local map is null
            if (!map && window.dashboardMap) {
                map = window.dashboardMap;
            }
            if (!map) {
                console.error('[ERROR] Map not initialized, cannot plot data');
                updateStatusBadge('Map not initialized', 'error');
                return;
            }
            clearMarkers();
            // Value filtering
            let minSignal = parseInt(document.getElementById('minSignal').value) || -150;
            let maxSignal = parseInt(document.getElementById('maxSignal').value) || 0;
            let channelFilter = document.getElementById('channelFilter').value.trim();
            let allowedChannels = channelFilter ? channelFilter.split(',').map(s => s.trim()) : null;
            let filtered = data.filter(point => {
                if (!point || point.lat === null || point.lat === undefined || point.lon === null || point.lon === undefined) {
                    return false; // Skip invalid points
                }
                let s = point.signal;
                let ch = point.channel ? String(point.channel).trim() : '';
                let inSignal = (s >= minSignal && s <= maxSignal);
                let inChannel = !allowedChannels || allowedChannels.includes(ch);
                return inSignal && inChannel;
            });
            if (filtered.length === 0) {
                const status = document.getElementById('status');
                updateStatusBadge('No data', 'warning');
                if (status) status.title = 'No data matches current filters';
                return;
            }
            let mode = document.getElementById('displayMode').value;
            let bounds = [];
            let estimatedSources = []; // For heatmap mode
            let bssidGroups = {}; // For heatmap mode
            
            // Validate gradient mode requires ESSID or BSSID
            if (mode === 'gradient') {
                const essidSelectEl = document.getElementById('essidSelect');
                const bssidSelectEl = document.getElementById('bssidSelect');
                const essidSearchEl = document.getElementById('essidSearch');
                const bssidSearchEl = document.getElementById('bssidSearch');
                const hasEssid = (essidSelectEl && essidSelectEl.value) || (essidSearchEl && essidSearchEl.value.trim());
                const hasBssid = (bssidSelectEl && bssidSelectEl.value) || (bssidSearchEl && bssidSearchEl.value.trim());
                
                if (!hasEssid && !hasBssid) {
                    updateStatusBadge('Gradient mode requires ESSID or BSSID filter', 'error');
                    if (essidSelectEl) essidSelectEl.style.borderColor = '#f44336';
                    if (bssidSelectEl) bssidSelectEl.style.borderColor = '#f44336';
                    if (essidSearchEl) essidSearchEl.style.borderColor = '#f44336';
                    if (bssidSearchEl) bssidSearchEl.style.borderColor = '#f44336';
                    return;
                } else {
                    // Reset border colors
                    if (essidSelectEl) essidSelectEl.style.borderColor = '';
                    if (bssidSelectEl) bssidSelectEl.style.borderColor = '';
                    if (essidSearchEl) essidSearchEl.style.borderColor = '';
                    if (bssidSearchEl) bssidSearchEl.style.borderColor = '';
                }
            }
            
            if (mode === 'markers') {
                // Group points by GPS location (round to 6 decimal places for ~0.1m precision)
                let gpsGroups = {};
                filtered.forEach(point => {
                    // Round coordinates to group nearby points
                    const latKey = point.lat ? point.lat.toFixed(6) : '0';
                    const lonKey = point.lon ? point.lon.toFixed(6) : '0';
                    const altKey = point.altitude ? point.altitude.toFixed(1) : '0';
                    const gpsKey = `${latKey},${lonKey},${altKey}`;
                    
                    if (!gpsGroups[gpsKey]) {
                        gpsGroups[gpsKey] = {
                            lat: point.lat,
                            lon: point.lon,
                            altitude: point.altitude,
                            networks: []
                        };
                    }
                    gpsGroups[gpsKey].networks.push(point);
                });
                
                // Plot one marker per GPS location
                let gpsPlotIndex = 0;
                let totalNetworks = 0;
                Object.keys(gpsGroups).forEach(gpsKey => {
                    const location = gpsGroups[gpsKey];
                    const networkCount = location.networks.length;
                    totalNetworks += networkCount;
                    
                    // Get color based on network count
                    let color = getNetworkCountColor(networkCount);
                    
                    let marker = L.circleMarker([location.lat, location.lon], {
                        radius: 8,
                        fillColor: color,
                        color: '#000',
                        weight: 1,
                        opacity: 1,
                        fillOpacity: 0.8
                    }).addTo(map);
                    
                    // Build popup content with GPS location info and scrollable network list
                    let altText = location.altitude ? '<br>Altitude: ' + location.altitude.toFixed(1) + 'm' : '';
                    let googleMapsUrl = 'https://www.google.com/maps?q=' + location.lat + ',' + location.lon;
                    
                    let popupContent = '<div style="max-width: 400px;">';
                    popupContent += '<b>GPS Location</b><br>';
                    popupContent += 'Latitude: ' + location.lat.toFixed(6) + '<br>';
                    popupContent += 'Longitude: ' + location.lon.toFixed(6) + altText + '<br>';
                    popupContent += 'Networks Detected: ' + networkCount + '<br>';
                    popupContent += '<hr style="margin: 8px 0;">';
                    popupContent += '<b>Networks at this location:</b><br>';
                    popupContent += '<div style="max-height: 300px; overflow-y: auto; overflow-x: hidden; margin-top: 8px; padding: 4px; background: #f5f5f5; border-radius: 4px;">';
                    
                    location.networks.forEach((net, idx) => {
                        popupContent += '<div style="padding: 4px; margin-bottom: 4px; background: white; border-radius: 2px; border-left: 3px solid ' + getSignalColor(net.signal) + ';">';
                        popupContent += '<b>' + (net.essid || 'Hidden') + '</b><br>';
                        popupContent += 'BSSID: ' + (net.bssid || 'N/A') + '<br>';
                        popupContent += 'Signal: ' + net.signal + ' dBm | Channel: ' + (net.channel || 'N/A');
                        if (net.timestamp) {
                            popupContent += '<br>Time: ' + net.timestamp;
                        }
                        popupContent += '</div>';
                    });
                    
                    popupContent += '</div>';
                    popupContent += '<br><a href="' + googleMapsUrl + '" target="_blank" style="display: inline-block; padding: 6px 12px; background: #0066ff; color: white; text-decoration: none; border-radius: 4px; font-size: 0.9em; margin-top: 8px;">View in Google Maps</a>';
                    popupContent += '</div>';
                    
                    marker.bindPopup(popupContent, {maxWidth: 450});
                    
                    if (labelsEnabled && networkCount <= 500) {
                        marker.bindTooltip(networkCount + ' networks', {
                            permanent: true,
                            direction: 'center',
                            className: 'marker-label'
                        });
                    }
                    
                    // Add hover events
                    let pointId = `gps_${gpsPlotIndex}_${Date.now()}`;
                    marker.on('mouseover', function() {
                        marker.setStyle({weight: 3, radius: 10});
                    });
                    marker.on('mouseout', function() {
                        marker.setStyle({weight: 1, radius: 8});
                    });
                    
                    markers.push(marker);
                    bounds.push([location.lat, location.lon]);
                    
                    // Create table rows for all networks at this location
                    location.networks.forEach((net, netIdx) => {
                        let netPointId = `${pointId}_net_${netIdx}`;
                        createTableRow(net, netPointId, marker);
                    });
                    
                    gpsPlotIndex++;
                });
                
                // Update status with GPS plots and network counts
                const gpsPlotCount = Object.keys(gpsGroups).length;
                updateStatusBadge(`${gpsPlotCount} GPS Plots | ${totalNetworks} Networks`, 'success');
            } else if (mode === 'heatmap') {
                // Group readings by network (ESSID+BSSID combination) to estimate source locations
                // This allows filtering by ESSID/BSSID like other modes
                let networkGroups = {};
                filtered.forEach(point => {
                    // Use ESSID+BSSID as key, or just BSSID if ESSID is missing
                    let networkKey = point.bssid ? 
                        ((point.essid || 'Unknown') + '|' + point.bssid) : 
                        (point.essid || 'Unknown');
                    
                    if (!networkGroups[networkKey]) {
                        networkGroups[networkKey] = [];
                    }
                    networkGroups[networkKey].push(point);
                });
                
                // Estimate source location for each network using trilateration
                heatData = []; // Use global variable
                estimatedSources = []; // Reset for this plot
                
                Object.keys(networkGroups).forEach(networkKey => {
                    let readings = networkGroups[networkKey];
                    
                    // Calculate confidence score
                    let confidence = calculateConfidence(readings);
                    
                    // Only plot if confidence threshold is met
                    if (!confidence.pass) {
                        // Skip low-confidence estimates
                        return;
                    }
                    
                    // Estimate source location using trilateration
                    let estimated = estimateSourceLocation(readings);
                    if (estimated) {
                        // Use confidence score (0-100) normalized to 0-1 for heatmap intensity
                        // Higher confidence = higher intensity (brighter color)
                        // The actual color will be determined by the gradient based on confidence
                        let intensity = confidence.score / 100;
                        
                        // Only add if intensity is meaningful (confidence >= 10%)
                        if (intensity >= 0.1) {
                            heatData.push([estimated.lat, estimated.lon, intensity]);
                            estimatedSources.push({
                                bssid: readings[0].bssid || 'N/A',
                                essid: readings[0].essid || 'Unknown',
                                lat: estimated.lat,
                                lon: estimated.lon,
                                confidence: confidence.score >= 75 ? 'high' : (confidence.score >= 50 ? 'medium' : 'low'),
                                confidenceScore: confidence.score,
                                readings: readings.length,
                                avgSignal: confidence.avgSignal,
                                avgDistance: confidence.avgDistance,
                                spatialSpread: confidence.spatialSpread,
                                reasons: confidence.reasons,
                                warnings: confidence.warnings
                            });
                        }
                    }
                });
                
                if (heatData.length > 0) {
                    // Create transparent heatmap layer (not markers)
                    // Check if leaflet.heat is available
                    if (typeof L.heatLayer === 'function') {
                        // Get transparency from slider (default 0.9 = 90% opacity)
                        // Lower value = more transparent, higher = more opaque
                        let transparency = parseFloat(document.getElementById('heatmapTransparency')?.value || '0.9');
                        // Remove existing heat layer if present
                        if (heatLayer) {
                            map.removeLayer(heatLayer);
                        }
                        // Gradient colors represent confidence levels:
                        // Blue (low confidence) -> Cyan -> Green -> Yellow -> Orange -> Red (high confidence)
                        // Use fixed minOpacity for color intensity, apply CSS opacity for transparency
                        heatLayer = L.heatLayer(heatData, {
                            radius: 40,
                            blur: 30,
                            maxZoom: 18,
                            minOpacity: 0.4, // Fixed - controls color intensity, not transparency
                            max: 1.0,
                            gradient: {
                                0.0: 'blue',    // Low confidence (0-20%)
                                0.2: 'cyan',   // Low-medium confidence (20-40%)
                                0.4: 'lime',   // Medium confidence (40-60%)
                                0.6: 'yellow', // Medium-high confidence (60-80%)
                                0.8: 'orange', // High confidence (80-90%)
                                1.0: 'red'     // Very high confidence (90-100%)
                            }
                        }).addTo(map);
                        
                        // Apply CSS opacity to the canvas element for true transparency control
                        // This doesn't affect color values, only visual opacity
                        setTimeout(() => {
                            const canvas = map.getContainer().querySelector('canvas.leaflet-heatmap-layer');
                            if (canvas) {
                                canvas.style.opacity = transparency;
                            }
                        }, 100);
                        
                        window.dashboardHeatLayer = heatLayer;
                        window.dashboardHeatData = heatData; // Store data for transparency updates
                        window.dashboardHeatTransparency = transparency; // Store current transparency
                    } else {
                        // Fallback: log error
                        console.error('L.heatLayer is not available. Please check leaflet.heat library is loaded.');
                        updateStatusBadge('Heatmap library error', 'error');
                        alert('Heatmap library not loaded. Please refresh the page to reload libraries.');
                        return;
                    }
                    bounds = heatData.map(h => [h[0], h[1]]);
                    
                    // Add small transparent clickable markers for popup interaction (not visible, just for clicks)
                    estimatedSources.forEach((source, index) => {
                        // Very small transparent marker just for popup interaction
                        let marker = L.circleMarker([source.lat, source.lon], {
                            radius: 8,
                            fillColor: '#ffffff',
                            color: '#000000',
                            weight: 1,
                            opacity: 0.0,
                            fillOpacity: 0.0
                        }).addTo(map);
                        
                        let popupContent = '<b>Estimated Source Location</b><br>' +
                            'ESSID: ' + (source.essid || 'Unknown') + '<br>' +
                            'BSSID: ' + source.bssid + '<br>' +
                            'Latitude: ' + source.lat.toFixed(8) + '<br>' +
                            'Longitude: ' + source.lon.toFixed(8) + '<br>' +
                            '<hr>' +
                            '<b>Confidence: ' + source.confidence + ' (' + source.confidenceScore + '/100)</b><br>' +
                            'Readings: ' + source.readings + '<br>' +
                            'Avg Signal: ' + source.avgSignal + ' dBm<br>' +
                            'Avg Distance: ' + source.avgDistance + 'm<br>' +
                            'Spatial Spread: ' + source.spatialSpread + 'm<br>';
                        
                        if (source.reasons && source.reasons.length > 0) {
                            popupContent += '<br><b>Quality Factors:</b><br>';
                            source.reasons.forEach(r => {
                                popupContent += '✓ ' + r + '<br>';
                            });
                        }
                        
                        if (source.warnings && source.warnings.length > 0) {
                            popupContent += '<br><b>Warnings:</b><br>';
                            source.warnings.forEach(w => {
                                popupContent += '⚠ ' + w + '<br>';
                            });
                        }
                        
                        marker.bindPopup(popupContent);
                        markers.push(marker);
                    });
                }
                
                // Create table rows for all filtered points
                filtered.forEach((point, index) => {
                    let pointId = `point_${index}_${Date.now()}`;
                    createTableRow(point, pointId, null);
                });
            } else if (mode === 'gradient') {
                // Gradient mode - plot individual points with gradient colors
                // Group points by GPS location to show all networks at same location in labels
                let gpsGroups = {};
                filtered.forEach(point => {
                    // Round coordinates to group nearby points (same as markers mode)
                    const latKey = point.lat ? point.lat.toFixed(6) : '0';
                    const lonKey = point.lon ? point.lon.toFixed(6) : '0';
                    const altKey = point.altitude ? point.altitude.toFixed(1) : '0';
                    const gpsKey = `${latKey},${lonKey},${altKey}`;
                    
                    if (!gpsGroups[gpsKey]) {
                        gpsGroups[gpsKey] = {
                            lat: point.lat,
                            lon: point.lon,
                            altitude: point.altitude,
                            networks: []
                        };
                    }
                    gpsGroups[gpsKey].networks.push(point);
                });
                
                let totalNetworks = filtered.length;
                let gpsPlotIndex = 0;
                
                // Plot one marker per GPS location, showing all networks at that location
                Object.keys(gpsGroups).forEach(gpsKey => {
                    const location = gpsGroups[gpsKey];
                    const networksAtLocation = location.networks;
                    
                    // Use the strongest signal for marker color
                    const strongestSignal = Math.max(...networksAtLocation.map(n => n.signal));
                    let color = getSignalColor(strongestSignal);
                    
                    let marker = L.circleMarker([location.lat, location.lon], {
                        radius: 8,
                        fillColor: color,
                        color: '#000',
                        weight: 1,
                        opacity: 1,
                        fillOpacity: 0.8
                    }).addTo(map);
                    
                    // Build popup with all networks at this location
                    let altText = location.altitude ? '<br>Altitude: ' + location.altitude.toFixed(1) + 'm' : '';
                    let googleMapsUrl = 'https://www.google.com/maps?q=' + location.lat + ',' + location.lon;
                    let popupContent = '<div style="max-width: 400px;">';
                    popupContent += '<b>GPS Location</b><br>';
                    popupContent += 'Latitude: ' + location.lat.toFixed(6) + '<br>';
                    popupContent += 'Longitude: ' + location.lon.toFixed(6) + altText + '<br>';
                    popupContent += 'Networks: ' + networksAtLocation.length + '<br>';
                    popupContent += '<hr style="margin: 8px 0;">';
                    popupContent += '<b>Networks at this location:</b><br>';
                    popupContent += '<div style="max-height: 300px; overflow-y: auto; overflow-x: hidden; margin-top: 8px; padding: 4px; background: #f5f5f5; border-radius: 4px;">';
                    
                    networksAtLocation.forEach((net, idx) => {
                        popupContent += '<div style="padding: 4px; margin-bottom: 4px; background: white; border-radius: 2px; border-left: 3px solid ' + getSignalColor(net.signal) + ';">';
                        popupContent += '<b>' + (net.essid || 'Hidden') + '</b><br>';
                        popupContent += 'BSSID: ' + (net.bssid || 'N/A') + '<br>';
                        popupContent += 'Signal: ' + net.signal + ' dBm | Channel: ' + (net.channel || 'N/A');
                        if (net.timestamp) {
                            popupContent += '<br>Time: ' + net.timestamp;
                        }
                        popupContent += '</div>';
                    });
                    
                    popupContent += '</div>';
                    popupContent += '<br><a href="' + googleMapsUrl + '" target="_blank" style="display: inline-block; padding: 6px 12px; background: #0066ff; color: white; text-decoration: none; border-radius: 4px; font-size: 0.9em; margin-top: 8px;">View in Google Maps</a>';
                    popupContent += '</div>';
                    
                    marker.bindPopup(popupContent, {maxWidth: 450});
                    
                    // Label shows all network ESSIDs at this location (one per line, bold with black outline)
                    if (labelsEnabled && totalNetworks <= 500) {
                        // Use String.fromCharCode to avoid newline escaping issues in embedded JavaScript
                        const newlineChar = String.fromCharCode(10);
                        const labelText = networksAtLocation.map(n => (n.essid || 'Hidden')).join(newlineChar);
                        marker.bindTooltip(labelText, {
                            permanent: true,
                            direction: 'center',
                            className: 'marker-label'
                        });
                    }
                    
                    // Add hover events for bidirectional highlighting
                    networksAtLocation.forEach((net, netIdx) => {
                        let pointId = `gps_${gpsPlotIndex}_net_${netIdx}_${Date.now()}`;
                        marker.on('mouseover', function() {
                            marker.setStyle({weight: 3, radius: 10});
                        });
                        marker.on('mouseout', function() {
                            marker.setStyle({weight: 1, radius: 8});
                        });
                        
                        // Create table row for each network
                        createTableRow(net, pointId, marker);
                    });
                    
                    markers.push(marker);
                    bounds.push([location.lat, location.lon]);
                    gpsPlotIndex++;
                });
                
                // Count unique GPS locations for gradient mode
                const gpsPlotCount = Object.keys(gpsGroups).length;
                updateStatusBadge(`${gpsPlotCount} GPS Plots | ${totalNetworks} Networks`, 'success');
            }
            if (bounds.length > 0) {
                // Ensure map is available
                const currentMap = map || window.dashboardMap;
                if (currentMap) {
                    // Invalidate size to ensure map uses full viewport
                    currentMap.invalidateSize();
                    // Only auto-reposition if toggle is enabled
                    const autoReposition = document.getElementById('autoReposition');
                    if (autoReposition && autoReposition.checked) {
                        currentMap.fitBounds(bounds, {padding: [30,30]});
                    }
                }
            }
            const status = document.getElementById('status');
            if (mode === 'heatmap') {
                let sourceCount = estimatedSources ? estimatedSources.length : 0;
                let totalBssids = Object.keys(bssidGroups || {}).length;
                let filteredCount = totalBssids - sourceCount;
                updateStatusBadge(`${sourceCount} GPS Plots | ${filtered.length} Networks`, 'success');
                if (status) status.title = `Showing ${sourceCount} estimated sources (${filteredCount} filtered out due to low confidence) from ${filtered.length} sensor readings`;
            }
            // Status for markers and gradient modes is already updated above
        }
        window.plotData = plotData;
        
        // Helper function to update status badge with proper colors
        function updateStatusBadge(text, type) {
            // Parse text format: "X GPS Plots | Y Networks" or single message
            const parts = text.split(' | ');
            const gpsBadge = document.getElementById('statusBadgeGPS');
            const networkBadge = document.getElementById('statusBadgeNetworks');
            const oldBadge = document.getElementById('statusBadge'); // Fallback for old format
            
            if (parts.length === 2) {
                // Two-part format: GPS Plots and Networks
                if (gpsBadge) {
                    gpsBadge.textContent = parts[0].trim();
                    gpsBadge.classList.remove('error', 'warning', 'success');
                    if (type === 'success') gpsBadge.classList.add('success');
                    else if (type === 'warning') gpsBadge.classList.add('warning');
                    else if (type === 'error') gpsBadge.classList.add('error');
                }
                if (networkBadge) {
                    networkBadge.textContent = parts[1].trim();
                    networkBadge.classList.remove('error', 'warning', 'success');
                    if (type === 'success') networkBadge.classList.add('success');
                    else if (type === 'warning') networkBadge.classList.add('warning');
                    else if (type === 'error') networkBadge.classList.add('error');
                }
            } else {
                // Single message format - update both badges or fallback to old badge
                if (gpsBadge && networkBadge) {
                    // If we have the new format, show message on GPS badge, hide network badge
                    gpsBadge.textContent = text;
                    networkBadge.textContent = '';
                    gpsBadge.classList.remove('error', 'warning', 'success');
                    networkBadge.classList.remove('error', 'warning', 'success');
                    if (type === 'error') {
                        gpsBadge.classList.add('error');
                    } else if (type === 'warning') {
                        gpsBadge.classList.add('warning');
                    } else if (type === 'success') {
                        gpsBadge.classList.add('success');
                    }
                } else if (oldBadge) {
                    // Fallback to old badge format
                    oldBadge.textContent = text;
                    oldBadge.classList.remove('error', 'warning', 'success');
                    if (type === 'error') {
                        oldBadge.classList.add('error');
                    } else if (type === 'warning') {
                        oldBadge.classList.add('warning');
                    } else if (type === 'success') {
                        oldBadge.classList.add('success');
                    }
                }
            }
        }
        
        // ESSID-grouped data table
        // essidTableGroups maps essid -> {rows:[], marker, pointIds:[]}
        var essidTableGroups = {};

        function createTableRow(point, pointId, marker) {
            const tbody = document.getElementById('data-table-body');
            if (!tbody) return;

            const essid = point.essid || '(hidden)';

            if (!essidTableGroups[essid]) {
                // Create the parent ESSID row
                essidTableGroups[essid] = {detections: [], marker: marker};

                const parentRow = document.createElement('tr');
                parentRow.id = `essid_row_${CSS.escape(essid)}`;
                parentRow.style.cursor = 'pointer';
                parentRow.style.borderTop = '2px solid #444';
                parentRow.innerHTML = `
                    <td style="font-weight:600;">${essid}</td>
                    <td style="font-family:monospace; font-size:0.88em; color:#ccc;">${point.bssid || ''}</td>
                    <td>${point.signal !== null && point.signal !== undefined ? point.signal : ''}</td>
                    <td>${point.channel || ''}</td>
                    <td>${point.lat ? point.lat.toFixed(6) : ''}</td>
                    <td>${point.lon ? point.lon.toFixed(6) : ''}</td>
                    <td>${point.altitude !== null && point.altitude !== undefined ? point.altitude.toFixed(1) : ''}</td>
                    <td style="color:#666; font-size:0.82em;">${point.timestamp || ''}</td>
                `;

                const subRowContainer = document.createElement('tr');
                subRowContainer.id = `essid_sub_${CSS.escape(essid)}`;
                subRowContainer.style.display = 'none';
                const subTd = document.createElement('td');
                subTd.colSpan = 8;
                subTd.style.padding = '0 0 4px 16px';
                subTd.style.background = '#1c1c1c';
                subRowContainer.appendChild(subTd);

                parentRow.addEventListener('click', function() {
                    const sub = document.getElementById(`essid_sub_${CSS.escape(essid)}`);
                    if (sub) sub.style.display = sub.style.display === 'none' ? 'table-row' : 'none';
                    if (point.lat && point.lon) {
                        const currentMap = map || window.dashboardMap;
                        if (currentMap) currentMap.setView([point.lat, point.lon], Math.max(currentMap.getZoom(), 15), {animate: true});
                        if (marker) marker.openPopup();
                    }
                });
                parentRow.addEventListener('mouseenter', () => { if (marker) marker.setStyle({weight:3,radius:10,fillOpacity:1}); });
                parentRow.addEventListener('mouseleave', () => { if (marker) marker.setStyle({weight:1,radius:6,fillOpacity:0.7}); });

                tbody.appendChild(parentRow);
                tbody.appendChild(subRowContainer);
                dataTableRows.push(parentRow);
                if (marker) { markerToRowMap.set(marker, parentRow); rowToMarkerMap.set(parentRow, marker); }
            }

            // Add this detection to the sub-table
            const group = essidTableGroups[essid];
            group.detections.push(point);

            const subTd = document.querySelector(`#essid_sub_${CSS.escape(essid)} td`);
            if (subTd && group.detections.length > 1) {
                // Rebuild sub-table with all detections
                let subHtml = `<table style="width:100%;font-size:0.8em;color:#888;border-collapse:collapse;">
                    <thead><tr style="border-bottom:1px solid #2a2a2a;">
                        <th style="text-align:left;padding:2px 8px 2px 0;font-weight:400;color:#555;">Signal</th>
                        <th style="text-align:left;padding:2px 8px 2px 0;font-weight:400;color:#555;">Lat</th>
                        <th style="text-align:left;padding:2px 8px 2px 0;font-weight:400;color:#555;">Lon</th>
                        <th style="text-align:left;padding:2px 0;font-weight:400;color:#555;">Time</th>
                    </tr></thead><tbody>`;
                group.detections.forEach(d => {
                    subHtml += `<tr style="border-top:1px dashed #252525;">
                        <td style="padding:2px 8px 2px 0;">${d.signal !== null && d.signal !== undefined ? d.signal : '—'}</td>
                        <td style="padding:2px 8px 2px 0;">${d.lat ? d.lat.toFixed(6) : '—'}</td>
                        <td style="padding:2px 8px 2px 0;">${d.lon ? d.lon.toFixed(6) : '—'}</td>
                        <td style="padding:2px 0;font-size:0.9em;color:#666;">${d.timestamp || '—'}</td>
                    </tr>`;
                });
                subHtml += '</tbody></table>';
                subTd.innerHTML = subHtml;

                // Update parent row signal to show best (min = closest to 0)
                const parentRow = document.getElementById(`essid_row_${CSS.escape(essid)}`);
                if (parentRow) {
                    const signals = group.detections.map(d => d.signal).filter(s => s !== null && s !== undefined);
                    const bestSignal = signals.length ? Math.max(...signals) : '';
                    const cells = parentRow.querySelectorAll('td');
                    if (cells[2]) cells[2].textContent = bestSignal + (signals.length > 1 ? ` (${signals.length})` : '');
                }
            }
        }

        
        function highlightRow(pointId) {
            const row = document.getElementById(`row_${pointId}`);
            if (row) {
                row.classList.add('marker-highlighted');
                // Scroll row into view
                row.scrollIntoView({behavior: 'smooth', block: 'nearest'});
            }
        }
        
        function unhighlightRow(pointId) {
            const row = document.getElementById(`row_${pointId}`);
            if (row) {
                row.classList.remove('marker-highlighted');
            }
        }
        
        function highlightMarker(pointId) {
            const row = document.getElementById(`row_${pointId}`);
            if (row) {
                const marker = rowToMarkerMap.get(row);
                if (marker) {
                    marker.setStyle({weight: 3, radius: 10, fillOpacity: 1.0});
                    // Bring marker to front
                    marker.bringToFront();
                }
            }
        }
        
        function unhighlightMarker(pointId) {
            const row = document.getElementById(`row_${pointId}`);
            if (row) {
                const marker = rowToMarkerMap.get(row);
                if (marker) {
                    marker.setStyle({weight: 1, radius: 8, fillOpacity: 0.8});
                }
            }
        }
        function getSignalColor(signal) {
            // Handle null/undefined signal
            if (signal === null || signal === undefined || isNaN(signal)) {
                signal = -120; // Default to worst signal
            }
            
            // Find the appropriate threshold range
            // Note: low and high may be reversed (low > high) to represent ranges from better to worse
            for (let threshold of colorThresholds) {
                let minVal = Math.min(threshold.low, threshold.high);
                let maxVal = Math.max(threshold.low, threshold.high);
                
                // Check if signal falls within this range
                // Lower bound (minVal) is inclusive (>=), upper bound (maxVal) is exclusive (<)
                // For the highest range where maxVal might be 0 or equal to minVal
                if (maxVal === 0 || maxVal === minVal) {
                    // Highest range: signal >= minVal
                    if (signal >= minVal) {
                        return threshold.color;
                    }
                } else {
                    // Other ranges: signal >= minVal AND signal < maxVal
                    if (signal >= minVal && signal < maxVal) {
                        return threshold.color;
                    }
                }
            }
            
            // If signal is below all thresholds, use the lowest threshold color
            let sorted = [...colorThresholds].sort((a, b) => Math.min(a.low, a.high) - Math.min(b.low, b.high));
            return sorted[0].color;
        }
        
        // Get color based on network count at GPS location
        function getNetworkCountColor(count) {
            for (let threshold of networkCountThresholds) {
                if (count >= threshold.min && count <= threshold.max) {
                    return threshold.color;
                }
            }
            // Default to highest count color
            return networkCountThresholds[networkCountThresholds.length - 1].color;
        }
        function updateLegend() {
            let legendContent = document.getElementById('legendContent');
            let heatmapControls = document.getElementById('heatmapControls');
            legendContent.innerHTML = '';
            let mode = document.getElementById('displayMode') ? document.getElementById('displayMode').value : 'markers';
            
            // Show/hide heatmap intensity slider
            if (mode === 'heatmap' && heatmapControls) {
                heatmapControls.style.display = 'block';
            } else if (heatmapControls) {
                heatmapControls.style.display = 'none';
            }
            
            // For markers mode, show network count legend; for other modes, show signal strength
            if (mode === 'markers') {
                // Show network count thresholds in descending order (highest to lowest)
                let sorted = [...networkCountThresholds].sort((a, b) => b.min - a.min);
                for (let threshold of sorted) {
                    let range;
                    if (threshold.max >= 9999) {
                        range = threshold.min + '+';
                    } else if (threshold.min === threshold.max) {
                        range = threshold.min.toString();
                    } else {
                        range = threshold.min + '-' + threshold.max;
                    }
                    let item = document.createElement('div');
                    item.className = 'legend-item';
                    item.innerHTML = `
                        <div class="legend-color" style="background-color: ${threshold.color};"></div>
                        <span class="legend-label">${range} Networks</span>
                    `;
                    legendContent.appendChild(item);
                }
            } else {
                // Show signal strength thresholds for heatmap/gradient modes
                // For gradient mode, invert colors: red (highest) to magenta (lowest)
                let sorted = [...colorThresholds].sort((a, b) => {
                    let aMin = Math.min(a.low, a.high);
                    let bMin = Math.min(b.low, b.high);
                    return bMin - aMin; // Descending order (highest to lowest)
                });
                
                // Invert the color order for gradient mode - reverse the array
                if (mode === 'gradient') {
                    sorted = sorted.reverse();
                }
                
                for (let threshold of sorted) {
                    let minVal = Math.min(threshold.low, threshold.high);
                    let maxVal = Math.max(threshold.low, threshold.high);
                    let range;
                    if (maxVal === 0 || maxVal === minVal) {
                        range = minVal + '+';
                    } else {
                        range = minVal + ' to ' + maxVal;
                    }
                    let item = document.createElement('div');
                    item.className = 'legend-item';
                    item.innerHTML = `
                        <div class="legend-color" style="background-color: ${threshold.color};"></div>
                        <span class="legend-label">${range} dBm</span>
                    `;
                    legendContent.appendChild(item);
                }
            }
        }
        window.updateLegend = updateLegend;
        function toggleLegend() {
            // Only allow legend toggle on map tab
            const mapTab = document.getElementById('mapTab');
            if (!mapTab || !mapTab.classList.contains('active')) {
                console.warn('[WARN] Legend can only be toggled on the Map tab');
                return;
            }
            
            legendVisible = !legendVisible;
            window.dashboardLegendVisible = legendVisible;
            let legend = document.getElementById('legend');
            let toggleText = document.getElementById('legendToggleText');
            if (legendVisible) {
                legend.classList.add('visible');
                legend.style.display = 'block';
                toggleText.textContent = 'Hide Legend';
                updateLegend();
            } else {
                legend.classList.remove('visible');
                legend.style.display = 'none';
                toggleText.textContent = 'Show Legend';
            }
        }
        window.toggleLegend = toggleLegend;
        function toggleLabels() {
            // Check marker count before enabling labels to prevent crashes
            const currentMap = map || window.dashboardMap;
            if (!currentMap) {
                alert('Map not initialized. Please wait for the map to load.');
                return;
            }
            
            // Count current markers
            const markerCount = markers ? markers.length : 0;
            const maxMarkersForLabels = 500;
            
            // If trying to enable labels and we have too many markers, prevent it
            if (!labelsEnabled && markerCount >= maxMarkersForLabels) {
                alert('Labels can only be enabled when there are fewer than ' + maxMarkersForLabels + ' markers. Current count: ' + markerCount + '. Please filter the data to reduce the number of markers.');
                return;
            }
            
            labelsEnabled = !labelsEnabled;
            let toggleText = document.getElementById('labelToggleText');
            toggleText.textContent = labelsEnabled ? 'Hide Labels' : 'Show Labels';
            refreshData();
        }
        window.toggleLabels = toggleLabels;
        function toggleColorEditor() {
            let editor = document.getElementById('colorEditor');
            editor.style.display = editor.style.display === 'none' ? 'block' : 'none';
            if (editor.style.display === 'block') {
                renderColorThresholds();
            }
        }
        window.toggleColorEditor = toggleColorEditor;
        function renderColorThresholds() {
            let container = document.getElementById('colorThresholds');
            container.innerHTML = '';
            // Sort by low value descending (highest to lowest)
            let sorted = [...colorThresholds].sort((a, b) => b.low - a.low);
            sorted.forEach((threshold, index) => {
                let div = document.createElement('div');
                div.className = 'color-threshold';
                let highValue = threshold.high === 0 ? threshold.low : threshold.high;
                div.innerHTML = `
                    <label style="font-size:0.8em;">Low:</label>
                    <input type="number" value="${threshold.low}" min="-120" max="0" step="1" 
                           onchange="updateThresholdLow(${index}, this.value)" style="width:70px;">
                    <label style="font-size:0.8em;">High:</label>
                    <input type="number" value="${highValue}" min="-120" max="0" step="1" 
                           onchange="updateThresholdHigh(${index}, this.value)" style="width:70px;">
                    <span>dBm:</span>
                    <input type="color" value="${threshold.color}" 
                           onchange="updateThresholdColor(${index}, this.value)">
                    ${colorThresholds.length > 1 ? `<button onclick="removeThreshold(${index})">×</button>` : ''}
                `;
                container.appendChild(div);
            });
        }
        function updateThresholdLow(index, value) {
            let sorted = [...colorThresholds].sort((a, b) => b.low - a.low);
            let threshold = sorted[index];
            // Find and update in original array
            let originalIndex = colorThresholds.findIndex(t => t.low === threshold.low && t.high === threshold.high && t.color === threshold.color);
            if (originalIndex !== -1) {
                colorThresholds[originalIndex].low = parseInt(value);
            }
            updateLegend();
            refreshData();
        }
        function updateThresholdHigh(index, value) {
            let sorted = [...colorThresholds].sort((a, b) => b.low - a.low);
            let threshold = sorted[index];
            // Find and update in original array
            let originalIndex = colorThresholds.findIndex(t => t.low === threshold.low && t.high === threshold.high && t.color === threshold.color);
            if (originalIndex !== -1) {
                let highValue = parseInt(value);
                // If high equals low, set to 0 to indicate highest range
                colorThresholds[originalIndex].high = (highValue === threshold.low) ? 0 : highValue;
            }
            updateLegend();
            refreshData();
        }
        function updateThresholdColor(index, color) {
            let sorted = [...colorThresholds].sort((a, b) => b.low - a.low);
            let threshold = sorted[index];
            // Find and update in original array
            let originalIndex = colorThresholds.findIndex(t => t.low === threshold.low && t.high === threshold.high && t.color === threshold.color);
            if (originalIndex !== -1) {
                colorThresholds[originalIndex].color = color;
            }
            updateLegend();
            refreshData();
        }
        function removeThreshold(index) {
            if (colorThresholds.length <= 1) return;
            let sorted = [...colorThresholds].sort((a, b) => b.low - a.low);
            let threshold = sorted[index];
            // Find and remove from original array
            let originalIndex = colorThresholds.findIndex(t => t.low === threshold.low && t.high === threshold.high && t.color === threshold.color);
            if (originalIndex !== -1) {
                colorThresholds.splice(originalIndex, 1);
            }
            renderColorThresholds();
            updateLegend();
            refreshData();
        }
        function addColorThreshold() {
            let lowInput = prompt('Enter low threshold value (dBm, e.g., -50):');
            if (lowInput === null) return;
            let lowValue = parseInt(lowInput);
            if (isNaN(lowValue) || lowValue < -120 || lowValue > 0) {
                alert('Invalid low threshold. Must be between -120 and 0.');
                return;
            }
            
            let highInput = prompt('Enter high threshold value (dBm, e.g., -30). Use same as low for highest range:');
            if (highInput === null) return;
            let highValue = parseInt(highInput);
            if (isNaN(highValue) || highValue < -120 || highValue > 0) {
                alert('Invalid high threshold. Must be between -120 and 0.');
                return;
            }
            
            if (highValue < lowValue) {
                alert('High threshold must be greater than or equal to low threshold.');
                return;
            }
            
            // Check for overlapping ranges
            let overlaps = colorThresholds.some(t => {
                return (lowValue >= t.low && lowValue < (t.high || t.low)) ||
                       (highValue > t.low && highValue <= (t.high || t.low)) ||
                       (lowValue <= t.low && highValue >= (t.high || t.low));
            });
            
            if (overlaps) {
                alert('This range overlaps with an existing threshold range.');
                return;
            }
            
            // If high equals low, set to 0 to indicate highest range
            let finalHigh = (highValue === lowValue) ? 0 : highValue;
            colorThresholds.push({low: lowValue, high: finalHigh, color: '#888888'});
            renderColorThresholds();
            updateLegend();
            refreshData();
        }
        function signalToHeat(signal) {
            // Normalize signal from -120 to 0 range
            let norm = (signal + 120) / 120;
            return Math.max(0.05, Math.min(1, norm));
        }
        function getGradientColor(signal, min, max) {
            let t = (signal - min) / (max - min || 1);
            // Inverted: red (highest) -> yellow -> green -> blue -> magenta (lowest)
            let colors = [
                [255, 0, 0],      // Red (highest signal)
                [255, 255, 0],    // Yellow
                [0, 255, 0],      // Green
                [0, 102, 255],    // Blue
                [255, 0, 255]     // Magenta (lowest signal)
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
        window.loadSessions = loadSessions;
        async function loadEssids() {
            let session_id = document.getElementById('sessionSelect').value;
            let url = `/api/essids`;
            if (session_id) url += `?session_id=${session_id}`;
            let res = await fetch(url);
            let essids = await res.json();
            let essidSelect = document.getElementById('essidSelect');
            // Preserve selected values
            let selectedValues = Array.from(essidSelect.selectedOptions).map(opt => opt.value).filter(v => v);
            essidSelect.innerHTML = '';
            essids.forEach(e => {
                let opt = document.createElement('option');
                opt.value = e;
                opt.textContent = e;
                if (selectedValues.includes(e)) {
                    opt.selected = true;
                }
                essidSelect.appendChild(opt);
            });
            await loadBssids();
            // Enable/disable ESSID filter based on display mode
            let displayMode = document.getElementById('displayMode').value;
            // Heatmap mode now supports ESSID/BSSID filtering like other modes
        }
        window.loadEssids = loadEssids;
        async function loadBssids() {
            let session_id = document.getElementById('sessionSelect').value;
            let essidSelect = document.getElementById('essidSelect');
            // Get all selected ESSIDs (for multi-select)
            let selectedEssids = Array.from(essidSelect.selectedOptions).map(opt => opt.value).filter(v => v);
            let url = `/api/bssids`;
            let params = [];
            if (session_id) params.push(`session_id=${session_id}`);
            // Use first selected ESSID for BSSID filtering (or all if none selected)
            if (selectedEssids.length > 0) {
                params.push(`essid=${encodeURIComponent(selectedEssids[0])}`);
            }
            if (params.length > 0) url += '?' + params.join('&');
            let res = await fetch(url);
            let bssids = await res.json();
            let bssidSelect = document.getElementById('bssidSelect');
            // Preserve selected values
            let selectedValues = Array.from(bssidSelect.selectedOptions).map(opt => opt.value).filter(v => v);
            bssidSelect.innerHTML = '';
            bssids.forEach(b => {
                let opt = document.createElement('option');
                opt.value = b;
                opt.textContent = b;
                if (selectedValues.includes(b)) {
                    opt.selected = true;
                }
                bssidSelect.appendChild(opt);
            });
            // Update Select All button text based on current selection
            const button = bssidSelect.nextElementSibling;
            if (button && button.tagName === 'BUTTON') {
                const allSelected = bssids.length > 0 && bssids.every(b => selectedValues.includes(b));
                button.textContent = allSelected ? 'Deselect All' : 'Select All';
            }
        }
        window.loadBssids = loadBssids;
        async function refreshData() {
            let session_id = document.getElementById('sessionSelect')?.value || '';
            let essidSelect = document.getElementById('essidSelect');
            let bssidSelect = document.getElementById('bssidSelect');
            // Get all selected ESSIDs and BSSIDs (for multi-select)
            let selectedEssids = Array.from(essidSelect?.selectedOptions || []).map(opt => opt.value).filter(v => v);
            let selectedBssids = Array.from(bssidSelect?.selectedOptions || []).map(opt => opt.value).filter(v => v);
            let dateFrom = document.getElementById('dateFrom')?.value || '';
            let dateTo = document.getElementById('dateTo')?.value || '';
            let minAlt = document.getElementById('minAlt')?.value || '';
            let maxAlt = document.getElementById('maxAlt')?.value || '';
            let url = `/api/data`;
            let params = [];
            if (session_id) params.push(`session_id=${session_id}`);
            // Use multi-select values (comma-separated)
            if (selectedEssids.length > 0 && essidSelect && !essidSelect.disabled) {
                params.push(`essid=${encodeURIComponent(selectedEssids.join(','))}`);
            }
            if (selectedBssids.length > 0) {
                params.push(`bssid=${encodeURIComponent(selectedBssids.join(','))}`);
            }
            if (dateFrom) params.push(`date_from=${dateFrom}`);
            if (dateTo) params.push(`date_to=${dateTo}`);
            if (minAlt) params.push(`min_alt=${minAlt}`);
            if (maxAlt) params.push(`max_alt=${maxAlt}`);
            if (params.length > 0) url += '?' + params.join('&');
            // Reset border colors for ESSID/BSSID selects
            const essidSelectEl = document.getElementById('essidSelect');
            const bssidSelectEl = document.getElementById('bssidSelect');
            if (essidSelectEl) essidSelectEl.style.borderColor = '';
            if (bssidSelectEl) bssidSelectEl.style.borderColor = '';
            
            updateStatusBadge('Loading...', 'warning');
            try {
                let res = await fetch(url);
                if (!res.ok) {
                    throw new Error('HTTP error! status: ' + res.status);
                }
                let data = await res.json();
                if (!Array.isArray(data)) {
                    console.error('Invalid data format:', data);
                    updateStatusBadge('Error: Invalid data', 'error');
                    return;
                }
                plotData(data);
            } catch (e) {
                console.error('Error in refreshData:', e);
                updateStatusBadge('Error', 'error');
                const status = document.getElementById('status');
                if (status) status.title = 'Error loading data: ' + e.message;
                alert('Error loading data: ' + e.message);
            }
        }
        window.refreshData = refreshData;
        function clearFilters() {
            document.getElementById('sessionSelect').value = '';
            // Clear multi-selects
            let essidSelect = document.getElementById('essidSelect');
            let bssidSelect = document.getElementById('bssidSelect');
            Array.from(essidSelect.options).forEach(opt => opt.selected = false);
            Array.from(bssidSelect.options).forEach(opt => opt.selected = false);
            document.getElementById('minSignal').value = '-100';
            document.getElementById('maxSignal').value = '0';
            document.getElementById('channelFilter').value = '';
            document.getElementById('dateFrom').value = '';
            document.getElementById('dateTo').value = '';
            document.getElementById('minAlt').value = '';
            document.getElementById('maxAlt').value = '';
            refreshData();
        }
        window.clearFilters = clearFilters;
        function toggleSelectAll(selectId) {
            const select = document.getElementById(selectId);
            if (!select) return;
            
            // Get all options except the first one (usually "All" option)
            const options = Array.from(select.options).filter(opt => opt.value !== '');
            const allSelected = options.every(opt => opt.selected);
            
            // Toggle all options
            options.forEach(opt => {
                opt.selected = !allSelected;
            });
            
            // Update button text
            const button = select.nextElementSibling;
            if (button && button.tagName === 'BUTTON') {
                button.textContent = allSelected ? 'Select All' : 'Deselect All';
            }
            
            // Trigger change event to refresh data
            select.dispatchEvent(new Event('change'));
        }
        window.toggleSelectAll = toggleSelectAll;
        function showDeleteDialog() {
            let session_id = document.getElementById('sessionSelect').value;
            let essidSelect = document.getElementById('essidSelect');
            let bssidSelect = document.getElementById('bssidSelect');
            let selectedEssids = Array.from(essidSelect.selectedOptions).map(opt => opt.value).filter(v => v);
            let selectedBssids = Array.from(bssidSelect.selectedOptions).map(opt => opt.value).filter(v => v);
            let dateFrom = document.getElementById('dateFrom').value;
            let dateTo = document.getElementById('dateTo').value;
            let filters = [];
            if (session_id) filters.push(`Session: ${session_id}`);
            if (selectedEssids.length > 0) filters.push(`ESSID: ${selectedEssids.join(', ')}`);
            if (selectedBssids.length > 0) filters.push(`BSSID: ${selectedBssids.join(', ')}`);
            if (dateFrom) filters.push(`From: ${dateFrom}`);
            if (dateTo) filters.push(`To: ${dateTo}`);
            let filterText = filters.length > 0 ? filters.join(', ') : 'all tracks';
            document.getElementById('deleteModalBody').innerHTML = 
                `Are you sure you want to delete tracks matching: <strong>${filterText}</strong>?<br><br>This action cannot be undone.`;
            document.getElementById('deleteModal').style.display = 'block';
        }
        window.showDeleteDialog = showDeleteDialog;
        function closeDeleteDialog() {
            document.getElementById('deleteModal').style.display = 'none';
        }
        window.closeDeleteDialog = closeDeleteDialog;
        async function confirmDelete() {
            let session_id = document.getElementById('sessionSelect').value;
            let essidSelect = document.getElementById('essidSelect');
            let bssidSelect = document.getElementById('bssidSelect');
            let selectedEssids = Array.from(essidSelect.selectedOptions).map(opt => opt.value).filter(v => v);
            let selectedBssids = Array.from(bssidSelect.selectedOptions).map(opt => opt.value).filter(v => v);
            let dateFrom = document.getElementById('dateFrom').value;
            let dateTo = document.getElementById('dateTo').value;
            let deleteData = {};
            if (session_id) deleteData.session_id = session_id;
            if (selectedEssids.length > 0) deleteData.essid = selectedEssids.join(',');
            if (selectedBssids.length > 0) deleteData.bssid = selectedBssids.join(',');
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
                    // Update status badge if it exists (check for both old and new format)
                    const statusBadge = document.getElementById('statusBadge');
                    const statusBadgeGPS = document.getElementById('statusBadgeGPS');
                    if (statusBadge) {
                        statusBadge.textContent = `Deleted ${result.deleted}`;
                    } else if (statusBadgeGPS) {
                        statusBadgeGPS.textContent = `Deleted ${result.deleted}`;
                    }
                    const status = document.getElementById('status');
                    if (status) {
                        status.title = `Successfully deleted ${result.deleted} tracks`;
                    }
                    closeDeleteDialog();
                    await refreshData();
                    await loadSessions();
                    await loadEssids();
                } else {
                    alert('Error deleting tracks: ' + (result.error || 'Unknown error'));
                }
            } catch (e) {
                alert('Error deleting tracks: ' + e.message);
            }
        }
        window.confirmDelete = confirmDelete;
        
        // Function to attach all event listeners - called after DOM is ready
        function attachDashboardEventListeners() {
            
            // Display mode dropdown
            const displayModeSelect = document.getElementById('displayMode');
            if (displayModeSelect && !displayModeSelect.hasAttribute('data-listener-attached')) {
                displayModeSelect.addEventListener('change', async function() {
                    let displayMode = this.value;
                    let essidSelect = document.getElementById('essidSelect');
                    if (essidSelect) {
                        // Heatmap mode now supports ESSID/BSSID filtering like other modes
                    }
                    // Update legend when mode changes
                    if (typeof window.updateLegend === 'function') {
                        window.updateLegend();
                    }
                    if (typeof window.refreshData === 'function') {
                        await window.refreshData();
                    }
                });
                displayModeSelect.setAttribute('data-listener-attached', 'true');
            }
            
            // Heatmap transparency slider
            const heatmapTransparency = document.getElementById('heatmapTransparency');
            if (heatmapTransparency && !heatmapTransparency.hasAttribute('data-listener-attached')) {
                heatmapTransparency.addEventListener('input', function() {
                    let value = parseFloat(this.value);
                    let percent = Math.round(value * 100);
                    let transparencyValue = document.getElementById('transparencyValue');
                    if (transparencyValue) {
                        transparencyValue.textContent = percent + '%';
                    }
                    // Update existing heatmap layer opacity without recalculating data
                    let displayMode = document.getElementById('displayMode')?.value;
                    if (displayMode === 'heatmap' && window.dashboardHeatLayer) {
                        const map = window.dashboardMap;
                        if (map && window.dashboardHeatLayer) {
                            // Apply CSS opacity directly to the canvas - this only affects visual transparency
                            // and does NOT change the color/intensity values
                            const canvas = map.getContainer().querySelector('canvas.leaflet-heatmap-layer');
                            if (canvas) {
                                canvas.style.opacity = value;
                                window.dashboardHeatTransparency = value;
                            }
                        }
                    }
                });
                heatmapTransparency.setAttribute('data-listener-attached', 'true');
            }
            
            // Map style dropdown
            const mapStyleSelect = document.getElementById('mapStyle');
            if (mapStyleSelect && !mapStyleSelect.hasAttribute('data-listener-attached')) {
                mapStyleSelect.addEventListener('change', function() {
                    if (typeof window.dashboardMap !== 'undefined' && window.dashboardMap) {
                        const map = window.dashboardMap;
                        const currentBaseLayer = window.dashboardCurrentBaseLayer;
                        if (currentBaseLayer) map.removeLayer(currentBaseLayer);
                        if (this.value === 'osm') {
                            const osmLayer = window.dashboardOsmLayer;
                            if (osmLayer) {
                                osmLayer.addTo(map);
                                window.dashboardCurrentBaseLayer = osmLayer;
                            }
                        } else if (this.value === 'satellite') {
                            const satLayer = window.dashboardSatLayer;
                            if (satLayer) {
                                satLayer.addTo(map);
                                window.dashboardCurrentBaseLayer = satLayer;
                            }
                        }
                    }
                });
                mapStyleSelect.setAttribute('data-listener-attached', 'true');
            }
            
            // Session select
            const sessionSelect = document.getElementById('sessionSelect');
            if (sessionSelect && !sessionSelect.hasAttribute('data-listener-attached')) {
                sessionSelect.addEventListener('change', async function() {
                    if (typeof window.loadEssids === 'function') {
                        await window.loadEssids();
                    }
                    if (typeof window.refreshData === 'function') {
                        await window.refreshData();
                    }
                });
                sessionSelect.setAttribute('data-listener-attached', 'true');
            }
            
            // ESSID select
            const essidSelect = document.getElementById('essidSelect');
            if (essidSelect && !essidSelect.hasAttribute('data-listener-attached')) {
                essidSelect.addEventListener('change', async function() {
                    if (typeof window.loadBssids === 'function') {
                        await window.loadBssids();
                    }
                    if (typeof window.refreshData === 'function') {
                        await window.refreshData();
                    }
                });
                essidSelect.setAttribute('data-listener-attached', 'true');
            }
            
            // BSSID select
            const bssidSelect = document.getElementById('bssidSelect');
            if (bssidSelect && !bssidSelect.hasAttribute('data-listener-attached')) {
                bssidSelect.addEventListener('change', function() {
                    if (typeof window.refreshData === 'function') {
                        window.refreshData();
                    }
                });
                bssidSelect.setAttribute('data-listener-attached', 'true');
            }
            
            // Filter inputs
            const filterInputs = ['minSignal', 'maxSignal', 'channelFilter', 'dateFrom', 'dateTo', 'minAlt', 'maxAlt'];
            filterInputs.forEach(function(inputId) {
                const input = document.getElementById(inputId);
                if (input && !input.hasAttribute('data-listener-attached')) {
                    input.addEventListener('change', function() {
                        if (typeof window.refreshData === 'function') {
                            window.refreshData();
                        }
                    });
                    input.setAttribute('data-listener-attached', 'true');
                }
            });
            
            // Search inputs with debounce
            let searchTimeout;
            const essidSearch = document.getElementById('essidSearch');
            if (essidSearch && !essidSearch.hasAttribute('data-listener-attached')) {
                essidSearch.addEventListener('input', function() {
                    clearTimeout(searchTimeout);
                    searchTimeout = setTimeout(function() {
                        if (typeof window.refreshData === 'function') {
                            window.refreshData();
                        }
                    }, 500);
                });
                essidSearch.setAttribute('data-listener-attached', 'true');
            }
            
            const bssidSearch = document.getElementById('bssidSearch');
            if (bssidSearch && !bssidSearch.hasAttribute('data-listener-attached')) {
                bssidSearch.addEventListener('input', function() {
                    clearTimeout(searchTimeout);
                    searchTimeout = setTimeout(function() {
                        if (typeof window.refreshData === 'function') {
                            window.refreshData();
                        }
                    }, 500);
                });
                bssidSearch.setAttribute('data-listener-attached', 'true');
            }
            
        }
        window.attachDashboardEventListeners = attachDashboardEventListeners;
        // Dark mode is always enabled to match main webapp
        // Export data function
        async function exportData() {
            try {
                let session_id = document.getElementById('sessionSelect').value;
                let essid = document.getElementById('essidSelect').value;
                let bssid = document.getElementById('bssidSelect').value;
                let essidSearch = document.getElementById('essidSearch').value.trim();
                let bssidSearch = document.getElementById('bssidSearch').value.trim();
                let dateFrom = document.getElementById('dateFrom').value;
                let dateTo = document.getElementById('dateTo').value;
                let minAlt = document.getElementById('minAlt').value;
                let maxAlt = document.getElementById('maxAlt').value;
                let url = `/api/data`;
                let params = [];
                if (session_id) params.push(`session_id=${session_id}`);
                if (essidSearch) {
                    params.push(`essid_search=${encodeURIComponent(essidSearch)}`);
                } else if (essid && !document.getElementById('essidSelect').disabled) {
                    params.push(`essid=${encodeURIComponent(essid)}`);
                }
                if (bssidSearch) {
                    params.push(`bssid_search=${encodeURIComponent(bssidSearch)}`);
                } else if (bssid) {
                    params.push(`bssid=${encodeURIComponent(bssid)}`);
                }
                if (dateFrom) params.push(`date_from=${dateFrom}`);
                if (dateTo) params.push(`date_to=${dateTo}`);
                if (minAlt) params.push(`min_alt=${minAlt}`);
                if (maxAlt) params.push(`max_alt=${maxAlt}`);
                if (params.length > 0) url += '?' + params.join('&');
                
                let res = await fetch(url);
                let data = await res.json();
                
                // Convert to CSV
                let csv = 'ESSID,BSSID,Channel,Signal (dBm),Latitude,Longitude,Altitude,Timestamp,Session ID\\n';
                data.forEach(function(point) {
                    csv += '"' + (point.essid || '').replace(/"/g, '""') + '","' + (point.bssid || '').replace(/"/g, '""') + '",' + (point.channel || '') + ',' + (point.signal || '') + ',' + (point.lat || '') + ',' + (point.lon || '') + ',' + (point.altitude || '') + ',"' + (point.timestamp || '').replace(/"/g, '""') + '","' + (point.session_id || '').replace(/"/g, '""') + '"\\n';
                });
                
                // Download
                let blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
                let link = document.createElement('a');
                let url_blob = URL.createObjectURL(blob);
                link.setAttribute('href', url_blob);
                let filename = 'map_data_' + new Date().toISOString().split('T')[0] + '.csv';
                link.setAttribute('download', filename);
                link.style.visibility = 'hidden';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            } catch (e) {
                alert('Error exporting data: ' + e.message);
            }
        }
        window.exportData = exportData;
        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') {
                if (e.key === 'Enter' && e.ctrlKey) {
                    e.preventDefault();
                    refreshData();
                }
                return;
            }
            if (e.key === 'r' || e.key === 'R') {
                e.preventDefault();
                refreshData();
            } else if (e.key === 'm' || e.key === 'M') {
                e.preventDefault();
                document.getElementById('displayMode').focus();
            } else if (e.key === 'l' || e.key === 'L') {
                e.preventDefault();
                toggleLabels();
            } else if (e.key === 't' || e.key === 'T') {
                e.preventDefault();
                toggleDataTable();
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
        // Event listeners for mapStyle and other elements are now attached via attachDashboardEventListeners()
        // Advanced filters are now always visible - no toggle needed
        // Note: Automatic geolocation disabled - map does not center on user location
        // Make legend draggable
        function makeLegendDraggable() {
            const legend = document.getElementById('legend');
            if (!legend) return;
            
            let isDragging = false;
            let currentX;
            let currentY;
            let initialX;
            let initialY;
            let xOffset = 0;
            let yOffset = 0;
            
            // Function to constrain position within entire map window (including data table area)
            function constrainPosition(x, y) {
                const container = document.getElementById('map-container');
                if (!container) return {x: x, y: y};
                
                const legendWidth = legend.offsetWidth || 200;
                const legendHeight = legend.offsetHeight || 100;
                const containerWidth = container.offsetWidth;
                const containerHeight = container.offsetHeight;
                
                // Constrain to map container bounds (relative positioning)
                const minX = 0;
                const maxX = containerWidth - legendWidth;
                const constrainedX = Math.max(minX, Math.min(maxX, x));
                
                const minY = 0;
                const maxY = containerHeight - legendHeight;
                const constrainedY = Math.max(minY, Math.min(maxY, y));
                
                return {x: constrainedX, y: constrainedY};
            }
            
            // Load saved position from localStorage and validate it
            const savedPos = localStorage.getItem('legendPosition');
            if (savedPos) {
                try {
                    const pos = JSON.parse(savedPos);
                    // Wait for legend to be visible to get accurate dimensions
                    setTimeout(function() {
                        const constrained = constrainPosition(pos.x, pos.y);
                        xOffset = constrained.x;
                        yOffset = constrained.y;
                        legend.style.right = 'auto';
                        legend.style.bottom = 'auto';
                        legend.style.left = xOffset + 'px';
                        legend.style.top = yOffset + 'px';
                    }, 100);
                } catch (e) {
                    console.error('Error loading legend position:', e);
                    // Keep default CSS positioning if saved position is invalid
                }
            }
            
            // Drag handler functions
            function dragStart(e) {
                if (e.button !== 0) return; // Only handle left mouse button
                isDragging = true;
                const container = document.getElementById('map-container');
                if (!container) return;
                const containerRect = container.getBoundingClientRect();
                // Get current legend position relative to container
                const legendRect = legend.getBoundingClientRect();
                const currentX = legendRect.left - containerRect.left;
                const currentY = legendRect.top - containerRect.top;
                initialX = e.clientX - currentX;
                initialY = e.clientY - currentY;
                legend.classList.add('dragging');
            }
            
            function drag(e) {
                if (!isDragging) return;
                e.preventDefault();
                const container = document.getElementById('map-container');
                if (!container) return;
                const containerRect = container.getBoundingClientRect();
                // Calculate position relative to container
                currentX = e.clientX - containerRect.left - (e.clientX - initialX);
                currentY = e.clientY - containerRect.top - (e.clientY - initialY);
                // Get current position from legend style or calculate from mouse
                const rect = legend.getBoundingClientRect();
                const relX = rect.left - containerRect.left;
                const relY = rect.top - containerRect.top;
                const deltaX = e.clientX - (initialX + relX);
                const deltaY = e.clientY - (initialY + relY);
                currentX = relX + deltaX;
                currentY = relY + deltaY;
                const constrained = constrainPosition(currentX, currentY);
                xOffset = constrained.x;
                yOffset = constrained.y;
                legend.style.right = 'auto';
                legend.style.bottom = 'auto';
                legend.style.left = xOffset + 'px';
                legend.style.top = yOffset + 'px';
            }
            
            function dragEnd(e) {
                if (!isDragging) return;
                isDragging = false;
                legend.classList.remove('dragging');
                // Save position to localStorage
                localStorage.setItem('legendPosition', JSON.stringify({x: xOffset, y: yOffset}));
            }
            
            // Only allow dragging from the legend header (drag handle area)
            const legendHeader = legend.querySelector('.legend-header');
            if (legendHeader) {
                legendHeader.addEventListener('mousedown', dragStart);
                legendHeader.style.cursor = 'move';
            }
            // Prevent dragging from the rest of the legend
            legend.style.cursor = 'default';
            document.addEventListener('mousemove', drag);
            document.addEventListener('mouseup', dragEnd);
        }
        window.makeLegendDraggable = makeLegendDraggable;
        
        // Handle window resize to update map viewport
        if (typeof window.dashboardResizeTimeout === 'undefined') {
            window.dashboardResizeTimeout = null;
        }
        window.addEventListener('resize', function() {
            if (window.dashboardResizeTimeout) {
                clearTimeout(window.dashboardResizeTimeout);
            }
            window.dashboardResizeTimeout = setTimeout(() => {
                if (map) map.invalidateSize();
            }, 250);
        });
        window.makeLegendDraggable = makeLegendDraggable;
        
        // Wait for DOM to be ready, then initialize
        // Check if dashboard is already initialized to prevent multiple initializations
        // Note: Early return removed to allow script execution when injected dynamically
        
        function initDashboard() {
            // Check if map is already initialized, not just the flag
            const mapElement = document.getElementById('map');
            if (window.dashboardInitialized && window.dashboardMap && mapElement && mapElement._leaflet_id) {
                // Ensure map variable is set
                map = window.dashboardMap;
                return;
            }
            window.dashboardInitialized = true;
            // Always use dark theme to match main webapp
            document.documentElement.setAttribute('data-theme', 'dark');
            
            // Initialize map - check if already initialized
            try {
                const mapElement = document.getElementById('map');
                if (!mapElement) {
                    console.error('[ERROR] Map container element not found');
                    // Retry after a short delay
                    setTimeout(function() {
                        if (document.getElementById('map')) {
                            initDashboard();
                        }
                    }, 500);
                    return;
                }
                
                // Check if map is already initialized by Leaflet
                if (mapElement._leaflet_id) {
                    console.log('Map already initialized, skipping re-initialization');
                    // Try to get existing map instance from Leaflet's internal registry
                    // Leaflet stores the instance reference on the element
                    if (window.dashboardMap && window.dashboardMap._container === mapElement) {
                        map = window.dashboardMap;
                        // Just invalidate size to ensure it displays correctly
                        setTimeout(() => {
                            if (map) {
                                map.invalidateSize();
                            }
                        }, 100);
                        return;
                    }
                    // If we can't get the instance, remove the old one first
                    try {
                        const oldMap = L.Map.prototype.remove.call({_container: mapElement});
                    } catch(e) {
                        // If removal fails, try to get instance from Leaflet's registry
                        if (L.Map && L.Map._instances) {
                            const instanceId = mapElement._leaflet_id;
                            if (L.Map._instances[instanceId]) {
                                L.Map._instances[instanceId].remove();
                            }
                        }
                    }
                }
                
                // Initialize new map
                map = L.map('map', {maxZoom: 18}).setView([0,0], 2);
                window.dashboardMap = map; // Sync to window
                
                osmLayer = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                    attribution: '© OpenStreetMap contributors',
                    maxZoom: 18
                });
                window.dashboardOsmLayer = osmLayer;
                satLayer = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
                    attribution: 'Tiles © Esri &mdash; Source: Esri, i-cubed, USDA, USGS, AEX, GeoEye, Getmapping, Aerogrid, IGN, IGP, UPR-EGP, and the GIS User Community',
                    maxZoom: 18
                });
                window.dashboardSatLayer = satLayer;
                osmLayer.addTo(map);
                currentBaseLayer = osmLayer;
                window.dashboardCurrentBaseLayer = currentBaseLayer;
                
                // Initialize heatmap layer
                if (typeof L.heatLayer === 'function') {
                    heatLayer = L.heatLayer([], {radius: 25});
                    window.dashboardHeatLayer = heatLayer;
                    heatLayer.addTo(map);
                }
                
                // Initialize marker cluster group
                if (typeof L.markerClusterGroup === 'function') {
                    if (!window.dashboardMarkers || !Array.isArray(window.dashboardMarkers)) {
                        window.dashboardMarkers = L.markerClusterGroup();
                        map.addLayer(window.dashboardMarkers);
                    }
                    markers = window.dashboardMarkers;
                } else {
                    markers = [];
                    window.dashboardMarkers = markers;
                }
                
                // Add right-click context menu for coordinates
                map.on('contextmenu', function(e) {
                    showContextMenu(e.originalEvent, e.latlng.lat, e.latlng.lng);
                });
                
                // Hide context menu on click elsewhere
                document.addEventListener('click', hideContextMenu);
                document.addEventListener('contextmenu', function(e) {
                    if (!e.target.closest('#contextMenu') && !e.target.closest('#map')) {
                        hideContextMenu();
                    }
                });
                } catch (e) {
                console.error('[ERROR] Error initializing map:', e);
                console.error('[ERROR] Stack:', e.stack);
                // Don't alert, just log - map might initialize later
                return;
            }
            
            // Initial load
            (async function() {
                try {
                    await loadSessions();
                    await loadEssids();
                    await loadBssids();
                    updateLegend();
                    makeLegendDraggable();
                    
                    // Attach all event listeners after DOM is ready
                    if (typeof window.attachDashboardEventListeners === 'function') {
                        setTimeout(function() {
                            window.attachDashboardEventListeners();
                        }, 200);
                    }
                    
                    // Ensure functions are available before calling refreshData
                    if (typeof window.refreshData === 'function') {
                        await window.refreshData();
                    } else if (typeof refreshData === 'function') {
                        window.refreshData = refreshData;
                        await window.refreshData();
                    } else {
                        console.warn('[WARN] refreshData not available, will retry...');
                        setTimeout(async function() {
                            if (typeof window.refreshData === 'function') {
                                await window.refreshData();
                            } else if (typeof refreshData === 'function') {
                                window.refreshData = refreshData;
                                await window.refreshData();
                            }
                        }, 500);
                    }
                    // Ensure map loads data for full viewport
                    setTimeout(() => {
                        if (map) {
                            map.invalidateSize();
                        }
                    }, 100);
                } catch (e) {
                    console.error('[ERROR] Error during initial load:', e);
                    console.error('[ERROR] Stack:', e.stack);
                    updateStatusBadge('Error loading', 'error');
                }
            })();
        }
        
        // Listen for DOMContentLoaded
        document.addEventListener('DOMContentLoaded', function() {
            initDashboard();
        });
        
        // Also expose globally for manual initialization
        window.initDashboard = initDashboard;
        
        // Expose all dashboard functions to window for onclick handlers
        if (typeof refreshData === 'function') window.refreshData = refreshData;
        if (typeof toggleLabels === 'function') window.toggleLabels = toggleLabels;
        if (typeof toggleLegend === 'function') window.toggleLegend = toggleLegend;
        if (typeof toggleDataTable === 'function') window.toggleDataTable = toggleDataTable;
        if (typeof exportData === 'function') window.exportData = exportData;
        if (typeof loadSessions === 'function') window.loadSessions = loadSessions;
        if (typeof loadEssids === 'function') window.loadEssids = loadEssids;
        if (typeof loadBssids === 'function') window.loadBssids = loadBssids;
        if (typeof plotData === 'function') window.plotData = plotData;
        if (typeof toggleSelectAll === 'function') window.toggleSelectAll = toggleSelectAll;
        if (typeof switchTab === 'function') window.switchTab = switchTab;
        
        // If DOMContentLoaded already fired, initialize immediately
        if (document.readyState === 'complete' || document.readyState === 'interactive') {
            setTimeout(function() {
                if (!window.dashboardInitialized) {
                    initDashboard();
                }
            }, 100);
        }
    </script>
</body>
</html>
"""
        return render_template_string(dashboard_html_template)
    except Exception as e:
        print(f"[ERROR] Error in /dashboard route: {e}")
        import traceback
        traceback.print_exc()
        return f"<html><body><h1>Error loading dashboard</h1><p>{str(e)}</p></body></html>", 500

# --- Frontend ---

@app.route('/')
def index():
    """Main control panel page"""
    control_panel_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MiFi Control Panel</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/leaflet.heat@0.2.0/dist/leaflet-heat.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #1a1a1a;
            color: #e0e0e0;
            padding: 20px;
        }
        .container {
            max-width: 1600px;
            margin: 0 auto;
        }
        .header {
            background: #2d2d2d;
            padding: 12px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
        }
        .header h1 { color: #4CAF50; margin: 0; font-size: 1.3em; white-space: nowrap; }
        /* Header right: two columns - buttons | indicators */
        .header-right {
            display: flex;
            align-items: stretch;
            gap: 12px;
            margin-left: auto;
        }
        .header-btn-col {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        .header-ind-col {
            display: flex;
            flex-direction: column;
            gap: 4px;
            justify-content: center;
        }
        /* All toggle buttons: fixed width, fixed font size, dot always on left */
        .status-toggle-btn {
            display: flex;
            align-items: center;
            gap: 6px;
            width: 140px;
            background: #1a1a1a;
            border: 1px solid #444;
            border-radius: 6px;
            padding: 5px 10px;
            color: #ccc;
            font-size: 0.8em;
            cursor: pointer;
            transition: border-color 0.2s;
            white-space: nowrap;
            box-sizing: border-box;
        }
        .status-toggle-btn:hover { border-color: #666; }
        .status-toggle-btn .status-dot {
            width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0;
        }
        .status-toggle-btn .btn-label { color: #aaa; }
        .status-toggle-btn .btn-value { color: #666; font-size: 0.92em; }
        /* Indicators in the right column */
        .header-indicator {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 0.8em;
            color: #888;
            white-space: nowrap;
            padding: 5px 0;
        }
        .header-indicator .status-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            background: #2d2d2d;
            padding: 10px;
            border-radius: 8px;
        }
        .tab {
            padding: 12px 24px;
            background: #1a1a1a;
            border: none;
            border-radius: 6px;
            color: #ccc;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s;
        }
        .tab.active {
            background: #4CAF50;
            color: white;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .tab-content.active[style*="flex-direction"] {
            display: flex;
        }
        .status-panel {
            background: #2d2d2d;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .status-panel h2 {
            margin-bottom: 15px;
            color: #4CAF50;
        }
        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        .status-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px;
            background: #1a1a1a;
            border-radius: 6px;
            cursor: pointer;
            transition: background 0.3s;
        }
        .status-item:hover {
            background: #252525;
        }
        .status-item.clickable {
            cursor: pointer;
        }
        .status-dot {
            width: 16px;
            height: 16px;
            border-radius: 50%;
            flex-shrink: 0;
            display: inline-block;
        }
        .status-dot.red { 
            background: #f44336 !important; 
            box-shadow: 0 0 8px #f44336 !important; 
        }
        .status-dot.orange { 
            background: #ff9800 !important; 
            box-shadow: 0 0 8px #ff9800 !important; 
        }
        .status-dot.green { 
            background: #4CAF50 !important; 
            box-shadow: 0 0 8px #4CAF50 !important; 
        }
        .status-dot.yellow { 
            background: #ffeb3b !important; 
            box-shadow: 0 0 8px #ffeb3b !important; 
        }
        .status-label {
            font-size: 14px;
            color: #888;
            min-width: 100px;
        }
        .status-value {
            font-size: 16px;
            font-weight: 600;
            flex: 1;
        }
        .control-panel {
            background: #2d2d2d;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .control-panel h2 {
            margin-bottom: 15px;
            color: #4CAF50;
        }
        .operation-mode-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            grid-template-rows: auto auto;
            gap: 10px;
            margin-bottom: 20px;
        }
        .operation-mode-row {
            display: contents;
        }
        .operation-mode-btn {
            padding: 15px 20px;
            background: #1a1a1a;
            border: 2px solid #444;
            border-radius: 8px;
            color: #ccc;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        .operation-mode-btn:hover:not(:disabled) {
            background: #252525;
            border-color: #666;
        }
        .operation-mode-btn.selected {
            border-color: #ff9800;
            color: #ff9800;
            background: #2a1a0a;
        }
        #modeCollect {
            grid-column: 1;
            grid-row: 1;
        }
        #modeProcess {
            grid-column: 2;
            grid-row: 1;
        }
        #modeFull {
            grid-column: 3;
            grid-row: 1;
        }
        #modeTarget {
            grid-column: 4;
            grid-row: 1 / 3;
        }
        #modeMap {
            grid-column: 5;
            grid-row: 1 / 3;
        }
        #modeAuto {
            grid-column: 1 / 4;
            grid-row: 2;
        }
        .operation-mode-spacer {
            display: none;
        }
        .operation-mode-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .operation-control-buttons {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            grid-template-rows: auto auto;
            gap: 10px;
            margin-top: 20px;
        }
        .operation-control-btn {
            grid-row: 1 / 3;
            padding: 20px;
            font-size: 16px;
            font-weight: 600;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
        }
        .operation-control-btn-verbose {
            background: #1a1a1a;
            border: 2px solid #444;
            color: #ccc;
        }
        .operation-control-btn-verbose:hover:not(:disabled) {
            background: #252525;
            border-color: #666;
        }
        .operation-control-btn-verbose.selected {
            border-color: #ff9800;
            color: #ff9800;
            background: #2a1a0a;
        }
        .operation-control-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .form-group {
            margin-bottom: 15px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #ccc;
            font-size: 14px;
        }
        .form-group input, .form-group select, .form-group textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #444;
            border-radius: 4px;
            background: #1a1a1a;
            color: #e0e0e0;
            font-size: 14px;
        }
        .form-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s;
        }
        .btn-primary {
            background: #4CAF50;
            color: white;
        }
        .btn-primary:hover { background: #45a049; }
        .btn-danger {
            background: #f44336;
            color: white;
        }
        .btn-danger:hover { background: #da190b; }
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .log-viewer {
            background: #1a1a1a;
            border: 1px solid #444;
            border-radius: 8px;
            padding: 15px;
            height: 400px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            line-height: 1.6;
        }
        .log-entry {
            margin-bottom: 4px;
            padding: 2px 0;
            white-space: pre-wrap;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.4;
        }
        .log-entry.error { 
            color: #f44336; 
        }
        .log-entry.warning { 
            color: #ff9800; 
        }
        .log-entry.success { 
            color: #4CAF50; 
        }
        .log-entry.info { 
            color: #2196F3; 
        }
        .log-timestamp {
            color: #888;
            margin-right: 8px;
        }
        .log-prefix {
            margin-right: 4px;
            font-weight: bold;
        }
        .log-entry.success .log-prefix {
            color: #4CAF50;
        }
        .log-entry.error .log-prefix {
            color: #f44336;
        }
        .log-entry.warning .log-prefix {
            color: #ff9800;
        }
        .log-entry.info .log-prefix {
            color: #2196F3;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>MiFi Control Panel</h1>
            <div class="header-right">
                <!-- Buttons column: GPS, Interface, TAK -->
                <div class="header-btn-col">
                    <button class="status-toggle-btn" onclick="toggleGPS()" title="Toggle GPS monitoring">
                        <span class="status-dot red" id="gpsDot"></span>
                        <span class="btn-label">GPS</span>
                        <span id="gpsStatusShort" class="btn-value">Off</span>
                    </button>
                    <button class="status-toggle-btn" onclick="toggleInterface()" title="Toggle monitor mode">
                        <span class="status-dot" id="interfaceDot"></span>
                        <span class="btn-label">Interface</span>
                        <span id="interfaceStatusShort" class="btn-value">Unknown</span>
                    </button>
                    <button class="status-toggle-btn" onclick="toggleTAKConnection()" title="Toggle TAK connection">
                        <span class="status-dot" id="takDot"></span>
                        <span class="btn-label">TAK</span>
                        <span id="takStatusShort" class="btn-value">Off</span>
                    </button>
                </div>
                <!-- Indicators column: Operation, Server, Internet -->
                <div class="header-ind-col">
                    <div class="header-indicator">
                        <span class="status-dot" id="operationDot"></span>
                        <span id="operationStatus">Idle</span>
                    </div>
                    <div class="header-indicator">
                        <span id="statusDot" class="status-dot red"></span>
                        <span id="statusText">Server</span>
                    </div>
                    <div class="header-indicator">
                        <span id="internetStatusDot" class="status-dot red"></span>
                        <span>Internet</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="tabs">
            <button class="tab active" onclick="switchTab('control', event)">Control</button>
            <button class="tab" onclick="switchTab('map', event)">Map</button>
            <button class="tab" onclick="switchTab('analysis', event)">Analysis</button>
            <button class="tab" onclick="switchTab('config', event)">Config</button>
        </div>

        <!-- Control Tab -->
        <div id="controlTab" class="tab-content active">
            <div class="control-panel">
                <h2>Operation Controls</h2>
                <div class="operation-mode-grid">
                    <button class="operation-mode-btn" id="modeCollect" data-mode="collect" onclick="selectOperationMode('collect')">Collect</button>
                    <button class="operation-mode-btn" id="modeTarget" data-mode="target" onclick="selectOperationMode('target')">Target</button>
                    <button class="operation-mode-btn" id="modeMap" data-mode="map" onclick="selectOperationMode('map')">Map</button>
                    <button class="operation-mode-btn" id="modeAuto" onclick="toggleAutoMode()" disabled>Auto</button>
                </div>

                <!-- Mode-specific options -->
                <div id="collectOptions" class="mode-options" style="display: none;">
                    <h3 style="margin-top: 20px; margin-bottom: 10px; color: #4CAF50;">Collect/Target Mode Options</h3>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Initial Scan Time (-IS, seconds)</label>
                            <input type="number" id="initialScan" value="30" min="1">
                        </div>
                        <div class="form-group">
                            <label>Target Scan Time (-TS, seconds)</label>
                            <input type="number" id="targetScan" value="60" min="1">
                        </div>
                        <div class="form-group">
                            <label>Deauth Packets (-p)</label>
                            <input type="number" id="deauthPackets" value="100" min="1">
                        </div>
                    </div>
                </div>

                <div id="targetOptions" class="mode-options" style="display: none;">
                    <h3 style="margin-top: 20px; margin-bottom: 10px; color: #4CAF50;">Target Mode Options</h3>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Target ESSID (-TID) *Required</label>
                            <input type="text" id="targetESSID" placeholder="Network name">
                        </div>
                        <div class="form-group">
                            <label>Target Search Attempts (-TSA)</label>
                            <input type="number" id="targetSearchAttempts" value="25" min="0">
                        </div>
                        <div class="form-group">
                            <label>Target Capture Attempts (-TA)</label>
                            <input type="number" id="targetAttempts" value="10" min="0">
                        </div>
                    </div>
                </div>

                <div id="mapOptions" class="mode-options" style="display: none;">
                    <h3 style="margin-top: 20px; margin-bottom: 10px; color: #4CAF50;">Map Mode Options</h3>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Max Scans (-MS)</label>
                            <input type="number" id="maxScans" value="25" min="1">
                        </div>
                        <div class="form-group">
                            <label>Scan Duration (-MSD, seconds)</label>
                            <input type="number" id="scanDuration" value="1" min="1" step="0.1">
                        </div>
                        <div class="form-group">
                            <label>GPS Source</label>
                            <input type="text" id="gpsPort" value="" readonly
                                   placeholder="Loading from config..."
                                   title="GPS source is configured in config/config.ini [GPS].">
                            <small style="color:#888">Configured via config/config.ini &mdash; read-only here.</small>
                        </div>
                        <div class="form-group">
                            <label>GPS Lock Attempts (-GLA)</label>
                            <input type="number" id="gpsLockAttempts" value="20" min="1">
                        </div>
                        <div class="form-group">
                            <label>GPS Lock Wait (-GLW, seconds)</label>
                            <input type="number" id="gpsLockWait" value="5" min="1">
                        </div>
                    </div>
                </div>

                <div class="operation-control-buttons">
                    <button class="operation-control-btn operation-control-btn-verbose" id="verboseBtn" onclick="toggleVerbose()">Verbose</button>
                    <button class="btn btn-primary operation-control-btn" id="executeBtn" onclick="executeOperation()">Execute</button>
                    <button class="btn btn-danger operation-control-btn" id="stopBtn" onclick="stopOperation()" disabled>Stop Operation</button>
                </div>
            </div>

            <div class="control-panel">
                <h2>Real-Time Logs</h2>
                <div class="log-viewer" id="logViewer"></div>
            </div>
        </div>

        <!-- Config Tab -->
        <div id="configTab" class="tab-content">
            <div class="control-panel">
                <h2>TAK Server Configuration</h2>
                <p style="color: #888; font-size: 0.9em; margin-bottom: 15px;">Enable/disable TAK connection via the status indicator on the Control tab.</p>
                <div class="form-row">
                    <div class="form-group">
                        <label>Host</label>
                        <input type="text" id="takHost" onchange="updateTAKConfig()" placeholder="tak.tk or IP">
                    </div>
                    <div class="form-group">
                        <label>Port</label>
                        <input type="number" id="takPort" onchange="updateTAKConfig()" value="8087">
                    </div>
                    <div class="form-group">
                        <label>Protocol</label>
                        <select id="takProtocol" onchange="updateTAKConfig()">
                            <option value="tcp">TCP</option>
                            <option value="udp">UDP</option>
                        </select>
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Client Certificate [.p12]</label>
                        <div style="display: flex; gap: 10px; align-items: center;">
                            <input type="text" id="takCert" onchange="updateTAKConfig()" placeholder="lab-field.p12" style="flex: 1;">
                            <input type="file" id="takCertUpload" accept=".p12,.pfx,.pem,.crt,.cer" style="display: none;" onchange="uploadCertificate('cert')">
                            <button type="button" class="btn btn-primary" onclick="document.getElementById('takCertUpload').click()" style="padding: 8px 12px; font-size: 0.85em;">Upload</button>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>CA Certificate [.pem]</label>
                        <div style="display: flex; gap: 10px; align-items: center;">
                            <input type="text" id="takCA" onchange="updateTAKConfig()" placeholder="ca.pem" style="flex: 1;">
                            <input type="file" id="takCAUpload" accept=".pem,.crt,.cer,.p12,.pfx" style="display: none;" onchange="uploadCertificate('ca')">
                            <button type="button" class="btn btn-primary" onclick="document.getElementById('takCAUpload').click()" style="padding: 8px 12px; font-size: 0.85em;">Upload</button>
                        </div>
                    </div>
                </div>
                <button class="btn btn-primary" onclick="saveTAKConfig()">Save TAK Configuration</button>
            </div>

            <div class="control-panel">
                <h2>Interface Configuration</h2>
                <div class="form-group">
                    <label>Known Interfaces (comma-separated)</label>
                    <input type="text" id="monitorCandidates" onchange="updateInterfaceConfig()" placeholder="wlan0,wlan1">
                </div>
                <button class="btn btn-primary" onclick="saveInterfaceConfig()">Save Interface Configuration</button>
            </div>
        </div>

        <!-- Analysis Tab -->
        <div id="analysisTab" class="tab-content">
            <div class="control-panel">
                <h2>Capture Inventory</h2>
                <div style="overflow-x:auto;">
                    <table class="data-table" id="capturesTable" style="width:100%;">
                        <thead>
                            <tr>
                                <th style="width:24px;"></th>
                                <th>ESSID</th>
                                <th>BSSID</th>
                                <th>Channel</th>
                                <th>Captured</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="capturesTableBody">
                            <tr><td colspan="7" style="text-align:center; color:#666;">Loading...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="control-panel">
                <h2>Process Selected Capture</h2>
                <div class="form-row">
                    <div class="form-group">
                        <label>Capture</label>
                        <input type="text" id="analysisSelectedCapture" readonly placeholder="Click a row above to select">
                    </div>
                    <div class="form-group">
                        <label>Tool</label>
                        <select id="analysisToolSelect">
                            <option value="aircrack">Aircrack-ng (wordlist, WPA2 only)</option>
                            <option value="jtr">John the Ripper</option>
                            <option value="hashcat">Hashcat (wordlist)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Wordlist Path</label>
                        <input type="text" id="analysisWordlist" value="config/rockyou.txt">
                    </div>
                </div>
                <div class="operation-control-buttons">
                    <button class="btn btn-primary operation-control-btn" id="analysisExecuteBtn" onclick="executeAnalysisProcess()" disabled>Run Tool</button>
                    <button class="btn btn-danger operation-control-btn" onclick="stopOperation()">Stop Operation</button>
                </div>
            </div>

            <div class="control-panel">
                <h2>Capture Locations</h2>
                <div id="analysisMap" style="height:350px; border-radius:4px;"></div>
                <div style="margin-top:8px; font-size:0.85em; color:#888;">
                    <span style="color:#f44336;">&#9679;</span> Uncracked
                    &nbsp;&nbsp;<span style="color:#ffb300;">&#9679;</span> Processing
                    &nbsp;&nbsp;<span style="color:#4CAF50;">&#9679;</span> Cracked
                </div>
            </div>

            <div class="control-panel">
                <h2>Real-Time Logs</h2>
                <div class="log-viewer" id="analysisLogViewer"></div>
            </div>
        </div>

        <!-- Map Tab -->
        <div id="mapTab" class="tab-content" style="flex-direction: column; padding: 0;">
            <div id="dashboardContainer" style="flex: 1; display: flex; flex-direction: column; width: 100%; background: #1a1a1a;">
                <div style="padding: 20px; text-align: center; color: #666;">
                    Loading dashboard...
                </div>
            </div>
        </div>
    </div>

    <script>
        let statusInterval;
        let logEventSource;
        let serverConnected = true;
        let connectionErrorCount = 0;
        // Control panel variables (different from dashboard)
        var controlPanelMap = null;
        var mapInitialized = false;
        let currentPromptId = null;

        function switchTab(tabName, evt) {
            // Hide all tab contents first
            document.querySelectorAll('.tab-content').forEach(t => {
                t.classList.remove('active');
                t.style.display = 'none';
            });
            
            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            
            if (evt && evt.target) {
                evt.target.classList.add('active');
            } else {
                // Fallback: find button by tab name
                document.querySelectorAll('.tab').forEach(btn => {
                    if (btn.textContent.trim().toLowerCase() === tabName.toLowerCase()) {
                        btn.classList.add('active');
                    }
                });
            }
            
            // Show the selected tab
            const tabElement = document.getElementById(tabName + 'Tab');
            if (tabElement) {
                tabElement.classList.add('active');
                // Ensure tab is visible (handle flex display for map tab)
                if (tabElement.style.flexDirection) {
                    tabElement.style.display = 'flex';
                } else {
                    tabElement.style.display = 'block';
                }
            }
            
            // Hide legend when not on map tab
            const legend = document.getElementById('legend');
            if (legend) {
                if (tabName === 'map') {
                    // Keep legend visibility state on map tab
                    // Don't force show/hide, just ensure it's in the right place
                } else {
                    // Hide legend on other tabs
                    legend.classList.remove('visible');
                    legend.style.display = 'none';
                }
            }
            
            if (tabName === 'config') {
                loadConfig();
            } else if (tabName === 'map') {
                // Show legend container on map tab if it was visible
                if (legend && window.dashboardLegendVisible) {
                    legend.style.display = 'block';
                    legend.classList.add('visible');
                }
                setTimeout(() => {
                    if (typeof loadDashboard === 'function') {
                        loadDashboard();
                    } else {
                        console.error('[ERROR] loadDashboard is not a function! Type:', typeof loadDashboard);
                    }
                }, 100);
            } else if (tabName === 'analysis') {
                loadCaptures();
            }
        }

        // Operation mode state
        let currentOperationMode = null;
        let autoModeEnabled = false;
        let verboseModeEnabled = false;
        
        function toggleVerbose() {
            verboseModeEnabled = !verboseModeEnabled;
            const verboseBtn = document.getElementById('verboseBtn');
            if (verboseBtn) {
                if (verboseModeEnabled) {
                    verboseBtn.classList.add('selected');
                } else {
                    verboseBtn.classList.remove('selected');
                }
            }
        }
        
        function selectOperationMode(mode) {
            // Remove selected class from all mode buttons
            document.querySelectorAll('.operation-mode-btn').forEach(btn => {
                btn.classList.remove('selected');
            });
            
            // Add selected class to clicked button
            const btn = document.getElementById('mode' + mode.charAt(0).toUpperCase() + mode.slice(1));
            if (btn) {
                btn.classList.add('selected');
            }
            
            currentOperationMode = mode;
            
            // Enable/disable Auto button based on mode
            const autoBtn = document.getElementById('modeAuto');
            if (autoBtn) {
                if (mode === 'collect') {
                    autoBtn.disabled = false;
                } else {
                    autoBtn.disabled = true;
                    autoBtn.classList.remove('selected');
                    autoModeEnabled = false;
                }
            }
            
            // Update mode options display
            updateModeOptions();
        }
        
        function toggleAutoMode() {
            if (autoModeEnabled) {
                autoModeEnabled = false;
                document.getElementById('modeAuto').classList.remove('selected');
            } else {
                if (currentOperationMode === 'collect') {
                    autoModeEnabled = true;
                    document.getElementById('modeAuto').classList.add('selected');
                }
            }
        }
        
        function getOperationMode() {
            if (!currentOperationMode) return null;
            // For target and map modes, return as-is (no -auto/-manual suffix)
            if (currentOperationMode === 'target' || currentOperationMode === 'map') {
                return currentOperationMode;
            }
            // For collect, process, full - append -auto or -manual
            if (autoModeEnabled) {
                return currentOperationMode + '-auto';
            }
            return currentOperationMode + '-manual';
        }
        
        function updateModeOptions() {
            if (!currentOperationMode) {
                document.querySelectorAll('.mode-options').forEach(el => el.style.display = 'none');
                return;
            }
            
            document.querySelectorAll('.mode-options').forEach(el => el.style.display = 'none');
            
            if (currentOperationMode === 'collect') {
                document.getElementById('collectOptions').style.display = 'block';
            } else if (currentOperationMode === 'target') {
                document.getElementById('collectOptions').style.display = 'block';
                document.getElementById('targetOptions').style.display = 'block';
            } else if (currentOperationMode === 'map') {
                document.getElementById('mapOptions').style.display = 'block';
            }
        }
        
        // Expose functions globally
        window.selectOperationMode = selectOperationMode;
        window.toggleAutoMode = toggleAutoMode;
        window.toggleVerbose = toggleVerbose;
        window.getOperationMode = getOperationMode;
        window.updateModeOptions = updateModeOptions;

        function loadDashboard() {
            
            // Ensure we're on the map tab before loading
            const mapTab = document.getElementById('mapTab');
            if (!mapTab || !mapTab.classList.contains('active')) {
                console.warn('[WARN] Cannot load dashboard - map tab is not active');
                return;
            }
            
            const container = document.getElementById('dashboardContainer');
            if (!container) {
                console.error('[ERROR] dashboardContainer not found!');
                return;
            }
            
            // Ensure container is within mapTab
            if (!mapTab.contains(container)) {
                console.error('[ERROR] dashboardContainer is not within mapTab!');
                return;
            }
            
            
            // Show loading state
            container.innerHTML = '<div style="padding: 20px; text-align: center; color: #666;"><div style="display: inline-block; width: 40px; height: 40px; border: 4px solid #f3f3f3; border-top: 4px solid #0066ff; border-radius: 50%; animation: spin 1s linear infinite;"></div><p style="margin-top: 20px;">Loading dashboard...</p></div>';
            
            // Reset dashboard state on each load to allow refresh
            window.dashboardLoaded = false;
            window.dashboardScriptInjected = false;
            window.dashboardInitialized = false;
            // Also clear any existing function references to force re-exposure
            delete window.refreshData;
            delete window.exportData;
            delete window.toggleLabels;
            delete window.toggleLegend;
            delete window.toggleDataTable;
            delete window.loadSessions;
            delete window.loadEssids;
            delete window.loadBssids;
            delete window.plotData;
            delete window.initDashboard;
            delete window.attachDashboardEventListeners;
            
            // Check if currently loading
            if (window.dashboardLoading) {
                return;
            }
            
            window.dashboardLoading = true;
            
            const fetchPromise = fetch('/dashboard', {
                method: 'GET',
                headers: {
                    'Accept': 'text/html',
                },
                credentials: 'same-origin',
                cache: 'no-cache'
            });
            const timeoutPromise = new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Dashboard fetch timeout after 10 seconds')), 10000)
            );
            
            Promise.race([fetchPromise, timeoutPromise])
                .then(r => {
                    if (!r.ok) {
                        console.error('[ERROR] Dashboard response not OK:', r.status, r.statusText);
                        return r.text().then(text => {
                            console.error('[ERROR] Dashboard error response body:', text.substring(0, 500));
                            throw new Error(`HTTP ${r.status}: ${r.statusText}`);
                        });
                    }
                    serverConnected = true;
                    connectionErrorCount = 0;
                    return r.text();
                })
                .then(html => {
                    if (!html || html.length === 0) {
                        throw new Error('Dashboard HTML is empty');
                    }
                    const parser = new DOMParser();
                    const doc = parser.parseFromString(html, 'text/html');
                    
                    // Extract and inject styles (only once)
                    const styles = doc.querySelectorAll('style');
                    styles.forEach(style => {
                        if (!document.head.querySelector('style[data-dashboard-style]')) {
                            const newStyle = document.createElement('style');
                            newStyle.setAttribute('data-dashboard-style', 'true');
                            newStyle.textContent = style.textContent;
                            document.head.appendChild(newStyle);
                        }
                    });
                    
                    // Extract and inject CSS links (only once)
                    const links = doc.querySelectorAll('link[rel="stylesheet"]');
                    links.forEach(link => {
                        const href = link.getAttribute('href');
                        if (href && !document.head.querySelector(`link[href="${href}"]`)) {
                            const newLink = link.cloneNode(true);
                            document.head.appendChild(newLink);
                        }
                    });
                    
                    // Extract and inject external scripts (only once)
                    const headScripts = doc.head.querySelectorAll('script[src]');
                    headScripts.forEach(script => {
                        const src = script.getAttribute('src');
                        if (src && !document.head.querySelector(`script[src="${src}"]`)) {
                            const newScript = document.createElement('script');
                            newScript.src = src;
                            newScript.async = false;
                            document.head.appendChild(newScript);
                        }
                    });
                    
                    // Extract body content (toolbar, map-container, etc.)
                    const bodyContent = doc.body ? doc.body.innerHTML : '';
                    if (!bodyContent || bodyContent.trim().length === 0) {
                        console.error('[ERROR] Dashboard body content is empty');
                        throw new Error('Dashboard HTML body is empty');
                    }
                    container.innerHTML = bodyContent;
                    
                    // Force dark theme on the container and document
                    document.documentElement.setAttribute('data-theme', 'dark');
                    container.setAttribute('data-theme', 'dark');
                    container.style.background = '#1a1a1a';
                    container.style.color = '#e0e0e0';
                    
                    // Wait for external scripts to load, then inject and execute dashboard JavaScript
                    function checkScriptsLoaded() {
                        const externalScripts = Array.from(headScripts).map(s => s.getAttribute('src'));
                        const allLoaded = externalScripts.every(src => {
                            if (!src) return true;
                            return document.querySelector(`script[src="${src}"]`)?.getAttribute('data-loaded') === 'true';
                        });
                        
                        if (!allLoaded && externalScripts.length > 0) {
                            // Check if scripts are loaded
                            headScripts.forEach(script => {
                                const src = script.getAttribute('src');
                                if (src) {
                                    const existing = document.querySelector(`script[src="${src}"]`);
                                    if (existing && !existing.getAttribute('data-loaded')) {
                                        existing.addEventListener('load', function() {
                                            existing.setAttribute('data-loaded', 'true');
                                            checkScriptsLoaded();
                                        });
                                        existing.addEventListener('error', function() {
                                            existing.setAttribute('data-loaded', 'true'); // Mark as attempted
                                            checkScriptsLoaded();
                                        });
                                    }
                                }
                            });
                            setTimeout(checkScriptsLoaded, 100);
                            return;
                        }
                        
                        // All scripts loaded, now inject dashboard JavaScript (only once)
                        if (window.dashboardScriptInjected) {
                            window.dashboardLoading = false;
                            return;
                        }
                        
                        setTimeout(function() {
                            const bodyScripts = doc.body.querySelectorAll('script:not([src])');
                            if (bodyScripts.length > 0 && !window.dashboardScriptInjected) {
                                // Force reset initialization flag so script executes
                                window.dashboardInitialized = false;
                                
                                // Inject scripts one by one
                                let scriptsInjected = 0;
                                const allScripts = Array.from(bodyScripts);
                                allScripts.forEach(function(script, index) {
                                    const newScript = document.createElement('script');
                                    let scriptContent = script.textContent;
                                    if (scriptContent && scriptContent.trim()) {
                                        // Remove the if wrapper and ensure functions are in global scope
                                        // First, remove the early return check that would be invalid at top level
                                        scriptContent = scriptContent.replace(
                                            /if\s*\(window\.dashboardInitialized\)\s*\{[^}]*console\.log\('Dashboard already initialized[^}]*return;[^}]*\}\s*/g,
                                            ''
                                        );
                                        // Now remove the main if wrapper
                                        scriptContent = scriptContent.replace(
                                            /if\s*\(typeof\s+window\.dashboardInitialized\s*===\s*['"]undefined['"]\s*\|\|\s*!window\.dashboardInitialized\)\s*\{/,
                                            'window.dashboardInitialized = true;'
                                        );
                                        
                                        // Add immediate function exposure at the end of the script
                                        // This runs after all function definitions to expose them to window
                                        const exposeCode = '; (function() { try { ' +
                                            'if (typeof refreshData !== "undefined" && typeof refreshData === "function") window.refreshData = refreshData; ' +
                                            'if (typeof exportData !== "undefined" && typeof exportData === "function") window.exportData = exportData; ' +
                                            'if (typeof toggleLabels !== "undefined" && typeof toggleLabels === "function") window.toggleLabels = toggleLabels; ' +
                                            'if (typeof toggleLegend !== "undefined" && typeof toggleLegend === "function") window.toggleLegend = toggleLegend; ' +
                                            'if (typeof toggleDataTable !== "undefined" && typeof toggleDataTable === "function") window.toggleDataTable = toggleDataTable; ' +
                                            'if (typeof loadSessions !== "undefined" && typeof loadSessions === "function") window.loadSessions = loadSessions; ' +
                                            'if (typeof loadEssids !== "undefined" && typeof loadEssids === "function") window.loadEssids = loadEssids; ' +
                                            'if (typeof loadBssids !== "undefined" && typeof loadBssids === "function") window.loadBssids = loadBssids; ' +
                                            'if (typeof plotData !== "undefined" && typeof plotData === "function") window.plotData = plotData; ' +
                                            'if (typeof clearFilters !== "undefined" && typeof clearFilters === "function") window.clearFilters = clearFilters; ' +
                                            'if (typeof showDeleteDialog !== "undefined" && typeof showDeleteDialog === "function") window.showDeleteDialog = showDeleteDialog; ' +
                                            'if (typeof closeDeleteDialog !== "undefined" && typeof closeDeleteDialog === "function") window.closeDeleteDialog = closeDeleteDialog; ' +
                                            'if (typeof confirmDelete !== "undefined" && typeof confirmDelete === "function") window.confirmDelete = confirmDelete; ' +
                                            'if (typeof toggleColorEditor !== "undefined" && typeof toggleColorEditor === "function") window.toggleColorEditor = toggleColorEditor; ' +
                                            'if (typeof updateLegend !== "undefined" && typeof updateLegend === "function") window.updateLegend = updateLegend; ' +
                                            'if (typeof makeLegendDraggable !== "undefined" && typeof makeLegendDraggable === "function") window.makeLegendDraggable = makeLegendDraggable; ' +
                                            'if (typeof initDashboard !== "undefined" && typeof initDashboard === "function") window.initDashboard = initDashboard; ' +
                                            'if (typeof attachDashboardEventListeners !== "undefined" && typeof attachDashboardEventListeners === "function") window.attachDashboardEventListeners = attachDashboardEventListeners; ' +
                                            'if (typeof toggleSelectAll !== "undefined" && typeof toggleSelectAll === "function") window.toggleSelectAll = toggleSelectAll; ' +
                                            'if (typeof switchTab !== "undefined" && typeof switchTab === "function") window.switchTab = switchTab; ' +
                                            '} catch(e) { console.error("[ERROR] Error exposing functions:", e); } })();';
                                        scriptContent = scriptContent + exposeCode;
                                        
                                        // For the last script, add additional exposure code after script execution
                                        if (index === allScripts.length - 1) {
                                            // Add exposure code after script execution with retries (single line to avoid newline issues)
                                            const exposeCode = ';(function() { const exposeFuncs = function() { try { if (typeof refreshData === "function") window.refreshData = refreshData; if (typeof exportData === "function") window.exportData = exportData; if (typeof toggleLabels === "function") window.toggleLabels = toggleLabels; if (typeof toggleLegend === "function") window.toggleLegend = toggleLegend; if (typeof toggleDataTable === "function") window.toggleDataTable = toggleDataTable; if (typeof loadSessions === "function") window.loadSessions = loadSessions; if (typeof loadEssids === "function") window.loadEssids = loadEssids; if (typeof loadBssids === "function") window.loadBssids = loadBssids; if (typeof plotData === "function") window.plotData = plotData; if (typeof clearFilters === "function") window.clearFilters = clearFilters; if (typeof showDeleteDialog === "function") window.showDeleteDialog = showDeleteDialog; if (typeof closeDeleteDialog === "function") window.closeDeleteDialog = closeDeleteDialog; if (typeof confirmDelete === "function") window.confirmDelete = confirmDelete; if (typeof toggleColorEditor === "function") window.toggleColorEditor = toggleColorEditor; if (typeof updateLegend === "function") window.updateLegend = updateLegend; if (typeof makeLegendDraggable === "function") window.makeLegendDraggable = makeLegendDraggable; if (typeof initDashboard === "function") window.initDashboard = initDashboard; if (typeof attachDashboardEventListeners === "function") window.attachDashboardEventListeners = attachDashboardEventListeners; if (typeof toggleSelectAll === "function") window.toggleSelectAll = toggleSelectAll; if (typeof switchTab === "function") window.switchTab = switchTab; } catch(e) { console.error("[ERROR] Error exposing functions:", e); } }; exposeFuncs(); setTimeout(exposeFuncs, 50); setTimeout(exposeFuncs, 200); setTimeout(exposeFuncs, 500); })();';
                                            scriptContent = scriptContent + exposeCode;
                                        }
                                        newScript.textContent = scriptContent;
                                        newScript.onerror = function(e) {
                                            console.error('[ERROR] Script', index + 1, 'execution error:', e);
                                        };
                                        container.appendChild(newScript);
                                        scriptsInjected++;
                                        
                                        // After the last script is injected, wait a bit and then expose all functions
                                        if (index === allScripts.length - 1) {
                                            setTimeout(function() {
                                                // Force exposure of all functions after all scripts are loaded
                                                const funcs = ['refreshData', 'exportData', 'toggleLabels', 'toggleLegend', 'toggleDataTable', 'loadSessions', 'loadEssids', 'loadBssids', 'plotData', 'clearFilters', 'showDeleteDialog', 'closeDeleteDialog', 'confirmDelete', 'toggleColorEditor', 'updateLegend', 'makeLegendDraggable', 'initDashboard', 'attachDashboardEventListeners', 'toggleSelectAll'];
                                                funcs.forEach(function(name) {
                                                    try {
                                                        // Try to get function from global scope
                                                        const func = eval('(typeof ' + name + ' !== "undefined" ? ' + name + ' : null)');
                                                        if (typeof func === 'function') {
                                                            window[name] = func;
                                                        }
                                                    } catch(e) {
                                                        // Function not in scope yet, will be exposed by the code in the script
                                                    }
                                                });
                                            }, 100);
                                        }
                                    }
                                });
                                
                                window.dashboardScriptInjected = true;
                                
                                // Use event delegation on the container - this works even if functions aren't global
                                // This is more reliable than individual listeners
                                if (!container.hasAttribute('data-delegation-attached')) {
                                    container.addEventListener('click', function(e) {
                                        const target = e.target.closest('button');
                                        if (!target) return;
                                        
                                        const id = target.id;
                                        let funcName = null;
                                        
                                        // Map button IDs to function names
                                        if (id === 'labelToggle') funcName = 'toggleLabels';
                                        else if (id === 'legendToggle') funcName = 'toggleLegend';
                                        else if (id === 'dataTableToggleBtn') funcName = 'toggleDataTable';
                                        else if (id === 'exportBtn') funcName = 'exportData';
                                        else if (id === 'refreshBtn') funcName = 'refreshData';
                                        
                                        if (funcName) {
                                            e.preventDefault();
                                            e.stopPropagation();
                                            
                                            // Try to call the function - check window first, then try to find it
                                            if (typeof window[funcName] === 'function') {
                                                window[funcName]();
                                            } else {
                                                // Try to find function in injected scripts
                                                try {
                                                    const func = eval(funcName);
                                                    if (typeof func === 'function') {
                                                        window[funcName] = func;
                                                        func();
                                                    } else {
                                                        console.error('[ERROR] Function', funcName, 'not found');
                                                    }
                                                } catch(err) {
                                                    console.error('[ERROR] Cannot access function', funcName, ':', err);
                                                }
                                            }
                                        }
                                    });
                                    container.setAttribute('data-delegation-attached', 'true');
                                }
                                
                                // After all scripts are injected, wait and expose functions again
                                setTimeout(function() {
                                    exposeDashboardFunctions();
                                }, 300);
                                
                                // Helper function to expose all dashboard functions - more aggressive approach
                                function exposeDashboardFunctions() {
                                    const funcs = ['refreshData', 'exportData', 'toggleLabels', 'toggleLegend', 'toggleDataTable', 
                                                  'loadSessions', 'loadEssids', 'loadBssids', 'plotData',
                                                  'clearFilters', 'showDeleteDialog', 'closeDeleteDialog', 'confirmDelete',
                                                  'toggleColorEditor', 'updateLegend', 'makeLegendDraggable', 'initDashboard',
                                                  'attachDashboardEventListeners', 'toggleSelectAll'];
                                    
                                    // Try multiple times with increasing delays
                                    let attempts = 0;
                                    const maxAttempts = 10;
                                    const exposeInterval = setInterval(function() {
                                        attempts++;
                                        let exposed = 0;
                                        funcs.forEach(function(name) {
                                            try {
                                                // Try direct access first
                                                if (typeof window[name] === 'function') {
                                                    exposed++;
                                                    return;
                                                }
                                                // Try eval
                                                try {
                                                    const func = eval(name);
                                                    if (typeof func === 'function') {
                                                        window[name] = func;
                                                        exposed++;
                                                    }
                                                } catch(e1) {
                                                    // Try accessing from container scope
                                                    try {
                                                        const containerScripts = container.querySelectorAll('script');
                                                        for (let script of containerScripts) {
                                                            try {
                                                                const func = new Function('return ' + name)();
                                                                if (typeof func === 'function') {
                                                                    window[name] = func;
                                                                    exposed++;
                                                                    break;
                                                                }
                                                            } catch(e2) {
                                                                // Continue
                                                            }
                                                        }
                                                    } catch(e3) {
                                                        // Continue
                                                    }
                                                }
                                            } catch(e) {
                                                // Function not available
                                            }
                                        });
                                        
                                        if (exposed === funcs.length || attempts >= maxAttempts) {
                                            clearInterval(exposeInterval);
                                            if (exposed === funcs.length) {
                                            } else {
                                                console.warn('[WARN] Some functions not exposed:', funcs.filter(f => typeof window[f] !== 'function'));
                                            }
                                        }
                                    }, 100);
                                }
                                
                                    // Expose ALL functions to window after scripts are injected
                                    setTimeout(function() {
                                        // Force dark theme
                                        document.documentElement.setAttribute('data-theme', 'dark');
                                        
                                        // Aggressively expose functions by checking multiple scopes
                                        const functionsToExpose = [
                                            'initDashboard', 'refreshData', 'toggleLabels', 'toggleLegend', 'toggleDataTable',
                                            'exportData', 'loadSessions', 'loadEssids',
                                            'loadBssids', 'plotData', 'clearFilters', 'showDeleteDialog',
                                            'closeDeleteDialog', 'confirmDelete', 'toggleColorEditor',
                                            'updateThresholdLow', 'updateThresholdHigh', 'updateThresholdColor',
                                            'removeThreshold', 'addColorThreshold', 'updateLegend',
                                            'makeLegendDraggable', 'clearMarkers', 'getSignalColor',
                                            'signalToHeat', 'signalToDistance', 'attachDashboardEventListeners'
                                        ];
                                        
                                        functionsToExpose.forEach(function(funcName) {
                                            if (typeof window[funcName] === 'function') {
                                                return; // Already exposed - this return is inside forEach callback, which is valid
                                            }
                                            // Try multiple methods to get the function
                                            try {
                                                if (typeof eval(funcName) === 'function') {
                                                    window[funcName] = eval(funcName);
                                                }
                                            } catch(e1) {
                                                try {
                                                    const func = window[funcName] || eval('window.' + funcName);
                                                    if (typeof func === 'function') {
                                                        window[funcName] = func;
                                                    }
                                                } catch(e2) {
                                                    // Function not available yet
                                                }
                                            }
                                        });
                                        
                                        // Direct assignment as fallback
                                        try {
                                            if (typeof refreshData === 'function') window.refreshData = refreshData;
                                            if (typeof exportData === 'function') window.exportData = exportData;
                                            if (typeof toggleLabels === 'function') window.toggleLabels = toggleLabels;
                                            if (typeof toggleLegend === 'function') window.toggleLegend = toggleLegend;
                                            if (typeof toggleDataTable === 'function') window.toggleDataTable = toggleDataTable;
                                            if (typeof loadSessions === 'function') window.loadSessions = loadSessions;
                                            if (typeof loadEssids === 'function') window.loadEssids = loadEssids;
                                            if (typeof loadBssids === 'function') window.loadBssids = loadBssids;
                                            if (typeof plotData === 'function') window.plotData = plotData;
                                            if (typeof initDashboard === 'function') window.initDashboard = initDashboard;
                                            if (typeof attachDashboardEventListeners === 'function') window.attachDashboardEventListeners = attachDashboardEventListeners;
                                        } catch(e) {
                                            // Some functions not in scope
                                        }
                                        
                                        // Re-attach event listeners for select elements and buttons
                                        setTimeout(function() {
                                            // Wait for functions to be available with polling
                                            let attempts = 0;
                                            const maxAttempts = 20;
                                            const checkAndAttach = setInterval(function() {
                                                attempts++;
                                                
                                                // Check if key functions are available
                                                const keyFunctions = ['refreshData', 'toggleLabels', 'toggleLegend', 'toggleDataTable', 'exportData'];
                                                const allAvailable = keyFunctions.every(f => typeof window[f] === 'function' || typeof eval('(function(){try{return typeof ' + f + ';}catch(e){return "undefined";}})()') === 'function');
                                                
                                                if (allAvailable || attempts >= maxAttempts) {
                                                    clearInterval(checkAndAttach);
                                                    
                                                    // Re-expose functions one more time
                                                    keyFunctions.forEach(function(funcName) {
                                                        try {
                                                            const func = eval('(function(){try{return ' + funcName + ';}catch(e){return null;}})()');
                                                            if (typeof func === 'function') {
                                                                window[funcName] = func;
                                                            }
                                                        } catch(e) {
                                                            // Ignore
                                                        }
                                                    });
                                                    
                                                    // Attach event listeners to buttons as fallback
                                                    const buttonHandlers = {
                                                        'labelToggle': 'toggleLabels',
                                                        'legendToggle': 'toggleLegend',
                                                        'dataTableToggleBtn': 'toggleDataTable',
                                                        'exportBtn': 'exportData'
                                                    };
                                                    
                                                    Object.keys(buttonHandlers).forEach(function(buttonId) {
                                                        const button = document.getElementById(buttonId);
                                                        const funcName = buttonHandlers[buttonId];
                                                        if (button && !button.hasAttribute('data-listener-attached')) {
                                                            button.addEventListener('click', function(e) {
                                                                e.preventDefault();
                                                                e.stopPropagation();
                                                                if (typeof window[funcName] === 'function') {
                                                                    window[funcName]();
                                                                } else {
                                                                    console.error('[ERROR] Function', funcName, 'not available');
                                                                }
                                                            });
                                                            button.setAttribute('data-listener-attached', 'true');
                                                        }
                                                    });
                                                    
                                                    // Attach refresh button
                                                    const refreshButtons = document.querySelectorAll('button[onclick*="refreshData"]');
                                                    refreshButtons.forEach(function(button) {
                                                        if (!button.hasAttribute('data-listener-attached')) {
                                                            button.addEventListener('click', function(e) {
                                                                e.preventDefault();
                                                                e.stopPropagation();
                                                                if (typeof window.refreshData === 'function') {
                                                                    window.refreshData();
                                                                } else {
                                                                    console.error('[ERROR] refreshData not available');
                                                                }
                                                            });
                                                            button.setAttribute('data-listener-attached', 'true');
                                                        }
                                                    });
                                                    
                                                    // Attach select element listeners
                                                    const displayModeSelect = document.getElementById('displayMode');
                                                    const mapStyleSelect = document.getElementById('mapStyle');
                                                    
                                                    if (displayModeSelect && !displayModeSelect.hasAttribute('data-listener-attached')) {
                                                        displayModeSelect.addEventListener('change', async function() {
                                                            let displayMode = this.value;
                                                            let essidSelect = document.getElementById('essidSelect');
                                                            if (essidSelect) {
                                                                essidSelect.disabled = displayMode === 'heatmap';
                                                            }
                                                            // Update legend when mode changes
                                                            if (typeof window.updateLegend === 'function') {
                                                                window.updateLegend();
                                                            }
                                                            if (typeof window.refreshData === 'function') {
                                                                await window.refreshData();
                                                            }
                                                        });
                                                        displayModeSelect.setAttribute('data-listener-attached', 'true');
                                                    }
                                                    
                                                    if (mapStyleSelect && !mapStyleSelect.hasAttribute('data-listener-attached')) {
                                                        mapStyleSelect.addEventListener('change', function() {
                                                            if (typeof window.dashboardMap !== 'undefined' && window.dashboardMap && typeof window.dashboardCurrentBaseLayer !== 'undefined') {
                                                                const map = window.dashboardMap;
                                                                const currentBaseLayer = window.dashboardCurrentBaseLayer;
                                                                if (currentBaseLayer) map.removeLayer(currentBaseLayer);
                                                                if (this.value === 'osm') {
                                                                    const osmLayer = window.dashboardOsmLayer;
                                                                    if (osmLayer) {
                                                                        osmLayer.addTo(map);
                                                                        window.dashboardCurrentBaseLayer = osmLayer;
                                                                    }
                                                                } else if (this.value === 'satellite') {
                                                                    const satLayer = window.dashboardSatLayer;
                                                                    if (satLayer) {
                                                                        satLayer.addTo(map);
                                                                        window.dashboardCurrentBaseLayer = satLayer;
                                                                    }
                                                                }
                                                            }
                                                        });
                                                        mapStyleSelect.setAttribute('data-listener-attached', 'true');
                                                    }
                                                }
                                            }, 100);
                                        }, 200);
                                    }, 100);
                            }
                            
                            // Mark as loaded
                            window.dashboardLoaded = true;
                            window.dashboardLoading = false;
                            
                            // Ensure map container is visible before initializing
                            const mapContainer = document.getElementById('map');
                            if (mapContainer) {
                                // Force visibility check
                                setTimeout(function() {
                                    
                                    // Trigger DOMContentLoaded if needed
                                    if (typeof document.dispatchEvent !== 'undefined') {
                                        const event = new Event('DOMContentLoaded');
                                        document.dispatchEvent(event);
                                    }
                                    
                                    // Also manually trigger map initialization if DOMContentLoaded handler didn't run
                                    setTimeout(function() {
                                        if (window.dashboardInitialized === false || window.dashboardInitialized === undefined) {
                                            
                                            // Wait a bit more for scripts to execute - increased attempts and delay
                                            let attempts = 0;
                                            const maxAttempts = 30; // Increased from 10
                                            const checkInit = setInterval(function() {
                                                attempts++;
                                                // Check both window.initDashboard and try to find it in the injected scripts
                                                if (typeof window.initDashboard === 'function') {
                                                    clearInterval(checkInit);
                                                    window.initDashboard();
                                                } else {
                                                    // Try to find initDashboard in the global scope
                                                    try {
                                                        if (typeof initDashboard === 'function') {
                                                            window.initDashboard = initDashboard;
                                                            clearInterval(checkInit);
                                                            window.initDashboard();
                                                        }
                                                    } catch(e) {
                                                        // Continue polling
                                                    }
                                                }
                                                
                                                if (attempts >= maxAttempts) {
                                                    console.error('[ERROR] initDashboard not found after', maxAttempts, 'attempts');
                                                    clearInterval(checkInit);
                                                    // Try to initialize map directly
                                                    if (document.getElementById('map') && typeof L !== 'undefined' && !document.getElementById('map')._leaflet_id) {
                                                        try {
                                                            const mapEl = document.getElementById('map');
                                                            if (mapEl && !mapEl._leaflet_id) {
                                                                const map = L.map('map', {maxZoom: 18}).setView([0,0], 2);
                                                                const osmLayer = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                                                                    attribution: '© OpenStreetMap contributors',
                                                                    maxZoom: 18
                                                                });
                                                                osmLayer.addTo(map);
                                                                window.dashboardMap = map;
                                                                window.dashboardInitialized = true;
                                                                // Try to load data - wait for functions to be available
                                                                setTimeout(function() {
                                                                    if (typeof loadSessions === 'function' && typeof refreshData === 'function') {
                                                                        (async function() {
                                                                            try {
                                                                                await loadSessions();
                                                                                await loadEssids();
                                                                                await loadBssids();
                                                                                await refreshData();
                                                                            } catch(e) {
                                                                                console.error('[ERROR] Error loading data:', e);
                                                                            }
                                                                        })();
                                                                    } else {
                                                                        console.error('[ERROR] Data loading functions not available');
                                                                    }
                                                                }, 1000);
                                                            }
                                                        } catch(e) {
                                                            console.error('[ERROR] Direct map initialization failed:', e);
                                                        }
                                                    }
                                                }
                                            }, 100);
                                        } else {
                                        }
                                    }, 500);
                                }, 300);
                            } else {
                                console.error('[ERROR] Map container not found!');
                                // Trigger DOMContentLoaded if needed
                                if (typeof document.dispatchEvent !== 'undefined') {
                                    const event = new Event('DOMContentLoaded');
                                    document.dispatchEvent(event);
                                }
                            }
                        }, 200);
                    }
                    
                    // Start checking for script loads
                    checkScriptsLoaded();
                })
                .catch(err => {
                    console.error('[ERROR] Dashboard load error:', err);
                    console.error('[ERROR] Error type:', err.constructor.name);
                    if (err.stack) console.error('[ERROR] Error stack:', err.stack);
                    serverConnected = false;
                    const errorMsg = err.message || err.toString();
                    console.error('[ERROR] Error message:', errorMsg);
                    if (errorMsg.includes('NetworkError') || errorMsg.includes('Failed to fetch') || errorMsg.includes('Network request failed')) {
                        container.innerHTML = '<div style="padding: 20px; color: #f44336; background: #fff; border-radius: 8px; margin: 20px; border: 2px solid #f44336;"><h3 style="margin-top: 0;">Connection Error</h3><p>Cannot connect to dashboard server. The server may be restarting.</p><p>Please wait a moment and refresh the page, or check the server logs.</p><p style="font-size: 0.9em; color: #666; margin-top: 10px;">Error: ' + errorMsg + '</p><button onclick="loadDashboard()" style="margin-top: 10px; padding: 8px 16px; background: #0066ff; color: white; border: none; border-radius: 4px; cursor: pointer;">Retry</button></div>';
                    } else {
                        container.innerHTML = '<div style="padding: 20px; color: #f44336; background: #fff; border-radius: 8px; margin: 20px; border: 2px solid #f44336;"><h3 style="margin-top: 0;">Error Loading Dashboard</h3><p>' + errorMsg + '</p><p style="font-size: 0.9em; color: #666; margin-top: 10px;">Check the browser console for more details.</p><button onclick="loadDashboard()" style="margin-top: 10px; padding: 8px 16px; background: #0066ff; color: white; border: none; border-radius: 4px; cursor: pointer;">Retry</button></div>';
                    }
                    window.dashboardLoading = false;
                });
        }

        // ===================== Analysis Tab =====================
        let analysisMapInstance = null;
        let analysisSelectedCaptureId = null;
        let analysisCapturesCache = [];

        function loadCaptures() {
            fetch('/api/captures')
                .then(r => r.json())
                .then(data => {
                    analysisCapturesCache = data;
                    renderCapturesTable(data);
                    renderAnalysisMap(data);
                })
                .catch(e => console.error('Failed to load captures:', e));
        }

        function statusBadge(status) {
            const map = {
                'cracked': ['success', 'Cracked'],
                'processing': ['warning', 'Processing'],
                'attempted': ['warning', 'Attempted'],
                'unprocessed': ['', 'Unprocessed']
            };
            const [cls, label] = map[status] || ['', status];
            return '<span class="status-badge ' + cls + '">' + label + '</span>';
        }

        function renderCapturesTable(grouped) {
            const tbody = document.getElementById('capturesTableBody');
            if (!grouped.length) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:#666; padding:20px;">No captures yet. Confirmed EAPOL handshakes will appear here after collection.</td></tr>';
                return;
            }
            let html = '';
            grouped.forEach((g, idx) => {
                const borderTop = idx > 0 ? 'border-top:2px solid #444;' : '';
                const caretId = 'caret-g-' + idx;
                const subId = 'subrows-g-' + idx;
                html += `<tr style="cursor:pointer; ${borderTop}" onclick="toggleCaptureRow('${subId}','${caretId}')">` +
                    `<td id="${caretId}" style="width:20px; color:#888;">&#9656;</td>` +
                    `<td style="font-weight:600;">${g.essid}</td>` +
                    `<td style="font-family:monospace; font-size:0.88em; color:#ccc;">${g.bssid}</td>` +
                    `<td style="text-align:center;">${g.captures.length} capture${g.captures.length !== 1 ? 's' : ''}</td>` +
                    `<td>${statusBadge(g.status)}${g.password ? ` <code style="margin-left:6px; color:#4CAF50;">${g.password}</code>` : ''}</td>` +
                    `<td></td></tr>`;

                html += `<tr id="${subId}" style="display:none;"><td></td><td colspan="5" style="padding:0 0 8px 12px; background:#1c1c1c;">`;
                g.captures.forEach((cap, cidx) => {
                    const capCaretId = 'caret-c-' + cap.id;
                    const capSubId = 'subrows-c-' + cap.id;
                    html += `<div style="margin:6px 0;">` +
                        `<div style="display:flex; align-items:center; gap:10px; cursor:pointer; padding:4px 0; border-top:${cidx > 0 ? '1px solid #2a2a2a' : 'none'};" onclick="toggleCaptureRow('${capSubId}','${capCaretId}')">` +
                        `<span id="${capCaretId}" style="color:#666; font-size:0.8em;">&#9656;</span>` +
                        `<span style="font-size:0.85em; color:#888; font-family:monospace;">${cap.captured_at}</span>` +
                        `<span style="font-size:0.82em; color:#666;">ch${cap.channel || '?'}</span>` +
                        `${statusBadge(cap.status)}` +
                        `<span style="margin-left:auto; display:flex; gap:6px;" onclick="event.stopPropagation();">` +
                            `<button class="btn btn-primary" style="padding:2px 8px; font-size:0.78em;" onclick="selectCaptureForProcessing(${cap.id},'${g.essid}')">Select</button>` +
                            `<button class="btn btn-danger" style="padding:2px 8px; font-size:0.78em;" data-delete-id="${cap.id}" onclick="deleteCaptureRow(${cap.id})">Delete</button>` +
                        `</span></div>` +
                        `<div id="${capSubId}" style="display:none; padding:2px 0 4px 16px;">`;

                    if (!cap.processing_runs.length) {
                        html += `<div style="color:#555; font-size:0.8em;">No processing attempts.</div>`;
                    } else {
                        cap.processing_runs.forEach((run, ridx) => {
                            const runStatus = run.status === 'cracked' ? 'cracked' : (run.status === 'running' ? 'processing' : 'attempted');
                            html += `<div style="display:flex; gap:12px; font-size:0.8em; color:#777; padding:2px 0; ${ridx > 0 ? 'border-top:1px dashed #252525;' : ''}">` +
                                `<span>${run.tool}</span>` +
                                `<span style="color:#555;">${run.attack_profile || ''}</span>` +
                                `<span style="color:#555;">${run.started_at}</span>` +
                                `<span>${statusBadge(runStatus)}</span>` +
                            `</div>`;
                        });
                    }
                    html += `</div></div>`;
                });
                html += `</td></tr>`;
            });
            tbody.innerHTML = html;
        }

        function toggleCaptureRow(subId, caretId) {
            const row = document.getElementById(subId);
            const caret = document.getElementById(caretId);
            if (!row) return;
            const isOpen = row.style.display !== 'none';
            row.style.display = isOpen ? 'none' : (row.tagName === 'TR' ? 'table-row' : 'block');
            if (caret) caret.innerHTML = isOpen ? '&#9656;' : '&#9662;';
        }


        function selectCaptureForProcessing(capId, essid) {
            analysisSelectedCaptureId = capId;
            document.getElementById('analysisSelectedCapture').value = essid + ' (capture #' + capId + ')';
            document.getElementById('analysisExecuteBtn').disabled = false;
        }


        function executeAnalysisProcess() {
            if (!analysisSelectedCaptureId) return;
            const tool = document.getElementById('analysisToolSelect').value;
            const wordlist = document.getElementById('analysisWordlist').value;
            document.getElementById('analysisExecuteBtn').disabled = true;

            fetch('/api/captures/' + analysisSelectedCaptureId + '/process', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({tool: tool, wordlist: wordlist})
            })
            .then(r => r.json())
            .then(data => {
                if (!data.success) {
                    addLog('Failed to start processing: ' + (data.error || 'unknown error'), 'error');
                    document.getElementById('analysisExecuteBtn').disabled = false;
                } else {
                    addLog('Processing started (tool=' + tool + ')', 'info');
                    // Reload the inventory once the operation completes (poll status)
                    const poll = setInterval(() => {
                        fetch('/api/status').then(r => r.json()).then(s => {
                            if (!s.running) {
                                clearInterval(poll);
                                document.getElementById('analysisExecuteBtn').disabled = false;
                                loadCaptures();
                            }
                        });
                    }, 3000);
                }
            })
            .catch(e => {
                addLog('Error starting processing: ' + e.message, 'error');
                document.getElementById('analysisExecuteBtn').disabled = false;
            });
        }

        function deleteCaptureRow(id) {
            const btn = document.querySelector(`button[data-delete-id="${id}"]`);
            if (!btn) return;
            if (btn.dataset.confirmPending === '1') {
                // Second click -- actually delete
                fetch('/api/captures/' + id + '/delete', {method: 'POST'})
                    .then(r => r.json())
                    .then(data => {
                        if (data.success) {
                            loadCaptures();
                        } else {
                            alert('Delete failed: ' + (data.error || 'unknown error'));
                        }
                    });
            } else {
                // First click -- arm the button
                btn.dataset.confirmPending = '1';
                btn.textContent = 'Confirm?';
                btn.style.background = '#ff6600';
                setTimeout(() => {
                    if (btn.dataset.confirmPending === '1') {
                        btn.dataset.confirmPending = '0';
                        btn.textContent = 'Delete';
                        btn.style.background = '';
                    }
                }, 3000);
            }
        }

        function renderAnalysisMap(grouped) {
            const el = document.getElementById('analysisMap');
            if (!el) return;
            if (!analysisMapInstance) {
                analysisMapInstance = L.map('analysisMap', {maxZoom: 18}).setView([0, 0], 2);
                L.tileLayer('http://10.0.1.3:8080/data/globe/{z}/{x}/{y}.png', {maxZoom: 18}).addTo(analysisMapInstance);
            }
            analysisMapInstance.eachLayer(layer => {
                if (layer instanceof L.CircleMarker) analysisMapInstance.removeLayer(layer);
            });
            const pts = grouped.filter(g => g.gps_lat && g.gps_lon);
            if (!pts.length) return;
            pts.forEach(g => {
                const color = g.status === 'cracked' ? '#4CAF50' : (g.status === 'processing' ? '#ffb300' : '#f44336');
                L.circleMarker([g.gps_lat, g.gps_lon], {
                    radius: 8, color, fillColor: color, fillOpacity: 0.8, weight: 2
                }).addTo(analysisMapInstance)
                  .bindPopup(`<b>${g.essid}</b><br>${g.bssid}<br>${g.captures.length} capture(s)`);
            });
            analysisMapInstance.fitBounds(L.latLngBounds(pts.map(g => [g.gps_lat, g.gps_lon])), {padding: [30, 30]});
        }


        function loadConfig() {
            fetch('/api/config')
                .then(r => r.json())
                .then(data => {
                    if (data.tak) {
                        document.getElementById('takHost').value = data.tak.host || '';
                        document.getElementById('takPort').value = data.tak.port || 8087;
                        document.getElementById('takProtocol').value = data.tak.protocol || 'tcp';
                        document.getElementById('takCert').value = data.tak.cert_file || '';
                        document.getElementById('takCA').value = data.tak.ca_file || '';
                    }
                    if (data.interface) {
                        document.getElementById('monitorCandidates').value = data.interface.candidates || '';
                    }
                    if (data.gps) {
                        const gpsField = document.getElementById('gpsPort');
                        if (gpsField) gpsField.value = data.gps.host + ':' + data.gps.port;
                    }
                });
        }

        // Check Internet connectivity
        function checkInternetConnectivity() {
            const internetDot = document.getElementById('internetStatusDot');
            if (!internetDot) return;
            
            // Try to fetch a small resource from a reliable CDN with a timeout
            const timeout = 3000; // 3 second timeout
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeout);
            
            fetch('https://www.google.com/favicon.ico', {
                method: 'HEAD',
                mode: 'no-cors',
                signal: controller.signal,
                cache: 'no-cache'
            })
            .then(() => {
                clearTimeout(timeoutId);
                // Connected - Green
                internetDot.className = 'status-dot green';
                internetDot.title = 'Internet Connected';
            })
            .catch(() => {
                clearTimeout(timeoutId);
                // Disconnected - Red
                internetDot.className = 'status-dot red';
                internetDot.title = 'Internet Disconnected';
            });
        }
        
        function updateStatus() {
            // Get status elements once at the start
            const statusDot = document.getElementById('statusDot');
            const statusText = document.getElementById('statusText');
            const stopBtn = document.getElementById('stopBtn');
            const executeBtn = document.getElementById('executeBtn');
            
            fetch('/api/status')
                .then(r => {
                    if (!r.ok) {
                        throw new Error(`HTTP ${r.status}: ${r.statusText}`);
                    }
                    // Server reconnected - reset error count and restore indicators
                    if (!serverConnected && connectionErrorCount > 0) {
                        addLog('✓ Server reconnected', 'success');
                    }
                    serverConnected = true;
                    connectionErrorCount = 0;
                    return r.json();
                })
                .then(data => {
                    // Only update status items if server is connected
                    // If server disconnected, indicators should stay red (set in catch block)
                    if (serverConnected) {
                        updateStatusItem('gps', data.gps_status || 'disabled');
                        updateStatusItem('interface', data.interface_status || 'unknown');
                        updateStatusItem('tak', data.tak_status || 'disabled', data.tak_connected || false);
                        updateStatusItem('operation', data.mode || 'None', data.running || false);
                    }
                    
                    // Check Internet connectivity
                    checkInternetConnectivity();
                    
                    // Update server status based on data
                    if (statusDot && statusText && stopBtn && executeBtn) {
                        // Check initialization status first
                        const initStatus = data.initialization_status || 'ready';
                        const initMessage = data.initialization_message || '';
                        
                        if (initStatus === 'initializing') {
                            // Yellow - Initializing
                            statusDot.className = 'status-dot yellow';
                            statusText.textContent = 'Initializing...';
                            stopBtn.disabled = true;
                            executeBtn.disabled = true;
                        } else if (initStatus === 'error') {
                            // Yellow - Error
                            statusDot.className = 'status-dot yellow';
                            statusText.textContent = initMessage || 'Error';
                            stopBtn.disabled = true;
                            executeBtn.disabled = true;
                        } else if (data.running) {
                            // Green - Server Connected and Running
                            statusDot.className = 'status-dot green';
                            statusText.textContent = `Running (PID: ${data.pid || 'N/A'})`;
                            stopBtn.disabled = false;
                            executeBtn.disabled = true;
                        } else {
                            // Green - Server Connected and Ready
                            statusDot.className = 'status-dot green';
                            statusText.textContent = 'Server Connected';
                            stopBtn.disabled = true;
                            executeBtn.disabled = false;
                        }
                    }
                })
                .catch(err => {
                    connectionErrorCount++;
                    serverConnected = false;
                    
                    // Turn all indicators red when server disconnects - do this immediately
                    const statusText = document.getElementById('statusText');
                    const statusDot = document.getElementById('statusDot');
                    if (statusText) {
                        statusText.textContent = 'Server Disconnected';
                    }
                    if (statusDot) {
                        statusDot.className = 'status-dot red';
                    }
                    
                    // Turn GPS indicator red
                    const gpsDot = document.querySelector('#gpsStatus .status-dot');
                    const gpsStatusText = document.querySelector('#gpsStatus .status-text');
                    if (gpsDot) {
                        gpsDot.className = 'status-dot red';
                    }
                    if (gpsStatusText) {
                        gpsStatusText.textContent = 'Server Disconnected';
                    }
                    
                    // Turn TAK indicator red
                    const takDot = document.querySelector('#takStatus .status-dot');
                    const takStatusText = document.querySelector('#takStatus .status-text');
                    if (takDot) {
                        takDot.className = 'status-dot red';
                    }
                    if (takStatusText) {
                        takStatusText.textContent = 'Server Disconnected';
                    }
                    
                    // Turn Interface indicator red
                    const interfaceDot = document.querySelector('#interfaceStatus .status-dot');
                    const interfaceStatusText = document.querySelector('#interfaceStatus .status-text');
                    if (interfaceDot) {
                        interfaceDot.className = 'status-dot red';
                    }
                    if (interfaceStatusText) {
                        interfaceStatusText.textContent = 'Server Disconnected';
                    }
                    
                    // Turn Operation indicator red
                    const operationDot = document.querySelector('#operationStatus .status-dot');
                    const operationStatusText = document.querySelector('#operationStatus .status-text');
                    if (operationDot) {
                        operationDot.className = 'status-dot red';
                    }
                    if (operationStatusText) {
                        operationStatusText.textContent = 'Server Disconnected';
                    }
                    
                    if (connectionErrorCount === 1) {
                        // Only log first error to avoid spam
                        addLog('⚠ Server connection lost. Waiting for server to restart...', 'warning');
                        
                        // Stop status updates temporarily
                        if (statusInterval) {
                            clearInterval(statusInterval);
                            statusInterval = null;
                        }
                        
                        // Try to reconnect after a delay
                        setTimeout(() => {
                            if (!serverConnected) {
                                addLog('Attempting to reconnect to server...', 'info');
                                updateStatus();
                                if (serverConnected && !statusInterval) {
                                    statusInterval = setInterval(updateStatus, 2000);
                                }
                            }
                        }, 5000);
                    }
                });
        }

        function updateStatusItem(type, status, connected = false) {
            const statusMap = {
                'gps': {
                    'disabled': 'GPS Disabled',
                    'no_modules': 'No GPS Modules',
                    'no_device': 'No USB Device',
                    'no_data': 'No GPS Data',
                    'searching': 'GPS Searching',
                    'locked': 'GPS Locked',
                    'unknown': 'Unknown'
                },
                'interface': {
                    'monitor_mode': 'Monitor Mode',
                    'managed_mode': 'Managed Mode',
                    'no_interface': 'No Interface',
                    'unknown': 'Unknown'
                },
                'tak': {
                    'connected': 'TAK Server Connected',
                    'enabled': 'TAK Server Enabled',
                    'disabled': 'TAK Server Disabled',
                    'unknown': 'TAK Server Unknown'
                },
                'operation': {
                    'None': 'Ready',
                    'collect': 'Collect',
                    'process': 'Process',
                    'full': 'Full',
                    'target': 'Target',
                    'map': 'Map'
                }
            };
            
            const dotId = type + 'Dot';
            const dot = document.getElementById(dotId);
            // Legacy full-text element (may not exist now that status is in header)
            const value = document.getElementById(type + 'Status');
            // Header short-label element
            const shortEl = document.getElementById(type + 'StatusShort');
            
            if (!dot) return;  // dot is required; value/shortEl are optional
            
            // Determine color based on status
            let color = 'red'; // Default to red for unknown/error states
            if (type === 'gps') {
                if (status === 'locked') {
                    color = 'green'; // Fully operational - valid coordinates within 15 seconds
                } else if (status === 'searching') {
                    color = 'yellow'; // Not valid coordinates within 15 seconds
                } else if (status === 'disabled') {
                    color = 'orange'; // GPS disabled by user
                } else if (status === 'no_device' || status === 'no_modules' || status === 'no_data') {
                    color = 'red'; // Error states - no GPS plugged in, no module installed, or no data
                } else {
                    color = 'red'; // Unknown or error
                }
            } else if (type === 'interface') {
                color = status === 'monitor_mode' ? 'green' : 'red'; // Green for operational, red for errors
            } else if (type === 'tak') {
                if (status === 'connected' && connected) {
                    color = 'green'; // Fully connected and operational
                } else if (status === 'disabled') {
                    color = 'orange'; // TAK disabled by user
                } else {
                    color = 'red'; // Connection errors or unknown
                }
            } else if (type === 'operation') {
                if (connected) {
                    color = 'yellow'; // Yellow during active operations
                } else {
                    color = 'green'; // Green when ready/standing by (not running)
                }
            }
            
            // Get display text -- short version for header badge, full for legacy panel
            const displayText = statusMap[type]?.[status] || status;
            const shortText = {
                'gps': {'disabled':'Off','no_modules':'Off','no_device':'Off',
                        'no_data':'No Data','searching':'Searching','locked':'Locked','unknown':'?'},
                'interface': {'monitor_mode':'Monitor','managed_mode':'Managed',
                              'no_interface':'None','unknown':'?'},
                'tak': {'connected':'Connected','enabled':'Enabled','disabled':'Off','unknown':'?'},
                'operation': {}
            }[type]?.[status] || status;

            // Update DOM
            dot.className = 'status-dot ' + color;
            if (value) { value.textContent = displayText; void value.offsetHeight; }
            if (shortEl) shortEl.textContent = shortText;

            // Force reflow
            void dot.offsetHeight;
        }

        function toggleGPS() {
            const gpsDot = document.getElementById('gpsDot');
            const gpsShort = document.getElementById('gpsStatusShort');
            const currentStatus = gpsShort ? gpsShort.textContent.trim() : 'unknown';
            const isCurrentlyEnabled = !['Off', 'unknown'].includes(currentStatus);
            
            addLog('Toggling GPS monitoring...', 'info');
            
            if (gpsDot) {
                gpsDot.style.opacity = '0.5';
                gpsDot.style.pointerEvents = 'none';
            }
            
            // Check if verbose mode is enabled (from any verbose checkbox in the UI)
            let verboseMode = false;
            const verboseCheckbox = document.getElementById('verbose') || document.querySelector('input[type="checkbox"][name*="verbose" i]');
            if (verboseCheckbox) {
                verboseMode = verboseCheckbox.checked;
            }
            fetch('/api/gps/toggle', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                credentials: 'same-origin',
                mode: 'same-origin',
                body: JSON.stringify({verbose: verboseMode})
            })
                .then(r => {
                    if (!r.ok) {
                        return r.json().then(data => {
                            throw new Error(data.error || `HTTP ${r.status}: ${r.statusText}`);
                        }).catch(() => {
                            throw new Error(`HTTP ${r.status}: ${r.statusText}`);
                        });
                    }
                    serverConnected = true;
                    connectionErrorCount = 0;
                    return r.json();
                })
                .then(data => {
                    if (data && data.success) {
                        if (data.enabled) {
                            addLog('✓ GPS monitoring enabled', 'success');
                            if (data.details) {
                                addLog('  Status: ' + (data.details.status || 'searching'), 'info');
                                if (data.details.devices && data.details.devices.length > 0) {
                                    addLog('  Devices: ' + data.details.devices.join(', '), 'info');
                                }
                                if (data.details.gpsd_running !== undefined) {
                                    addLog('  GPSD: ' + (data.details.gpsd_running ? 'Running' : 'Not running'), data.details.gpsd_running ? 'success' : 'warning');
                                }
                                if (data.details.message) {
                                    addLog('  ' + data.details.message, 'info');
                                }
                            }
                            addLog('  GPS status will update automatically as check completes', 'info');
                        } else {
                            addLog('✓ GPS monitoring disabled', 'info');
                            addLog('  GPS service stopped', 'info');
                        }
                        // Force immediate status update
                        updateStatus();
                        // Also update again in 3 seconds to catch background status change
                        setTimeout(() => {
                            updateStatus();
                        }, 3000);
                    } else {
                        // Handle failure case - might be no device or other error
                        if (data && data.details && data.details.status) {
                            // Update status indicator even on failure if we have status info
                            const status = data.details.status;
                            const message = data.details.message || data.error || 'Unknown error';
                            addLog('✗ ' + message, 'error');
                            // Force status update to show the error status (e.g., 'no_device')
                            updateStatus();
                        } else {
                            console.error('[ERROR] GPS toggle failed:', data);
                            addLog('✗ GPS toggle failed: ' + (data ? (data.error || 'Unknown error') : 'No response'), 'error');
                        }
                    }
                })
                .catch(err => {
                    const errorMsg = err.message || err.toString();
                    console.error('[ERROR] GPS toggle error:', err);
                    console.error('[ERROR] Error message:', errorMsg);
                    console.error('[ERROR] Error stack:', err.stack);
                    serverConnected = false;
                    if (errorMsg.includes('NetworkError') || errorMsg.includes('Failed to fetch')) {
                        addLog('✗ GPS toggle error: Server connection failed. Is the dashboard running?', 'error');
                        // Stop status updates if server is down
                        if (statusInterval) {
                            clearInterval(statusInterval);
                            statusInterval = null;
                        }
                    } else {
                        addLog('✗ GPS toggle error: ' + errorMsg, 'error');
                    }
                })
                .finally(() => {
                    if (gpsDot) {
                        gpsDot.style.opacity = '1';
                        gpsDot.style.pointerEvents = 'auto';
                    }
                });
        }

        function toggleInterface() {
            const statusEl = document.getElementById('interfaceStatusShort');
            const currentStatus = statusEl ? statusEl.textContent.trim() : '';
            
            fetch('/api/interface/toggle', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => response.json())
            .then(data => {
                
                if (data.success) {
                    if (data.prompt) {
                        // Prompt for interface name - will be handled by log stream
                    } else {
                        // Status updated successfully
                        // Status will be updated automatically by status polling
                        updateStatus();
                    }
                } else {
                    console.error('[ERROR] Interface toggle failed:', data.error);
                    addLog('Interface toggle failed: ' + (data.error || 'Unknown error'), 'error');
                }
            })
            .catch(error => {
                console.error('[ERROR] Interface toggle error:', error);
                addLog('Error toggling interface: ' + error.message, 'error');
            });
        }
        
        function toggleTAKConnection() {
            const takDot = document.getElementById('takDot');
            const takStatus = document.getElementById('takStatusShort');
            
            const currentStatus = takStatus ? takStatus.textContent.trim() : 'unknown';
            const isCurrentlyConnected = currentStatus === 'Connected';
            
            // Prevent multiple simultaneous requests
            if (takDot && takDot.style.pointerEvents === 'none') {
                return;
            }
            
            addLog('Toggling TAK connection...', 'info');
            
            if (takDot) {
                takDot.style.opacity = '0.5';
                takDot.style.pointerEvents = 'none';
            }
            
            fetch('/api/tak/toggle-connection', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                credentials: 'same-origin',
                mode: 'same-origin'
            })
                .then(r => {
                    if (!r.ok) {
                        return r.json().then(data => {
                            throw new Error(data.error || `HTTP ${r.status}: ${r.statusText}`);
                        }).catch(() => {
                            throw new Error(`HTTP ${r.status}: ${r.statusText}`);
                        });
                    }
                    serverConnected = true;
                    connectionErrorCount = 0;
                    return r.json();
                })
                .then(data => {
                    if (data && data.success) {
                        if (data.connecting) {
                            addLog('✓ TAK connection initiated', 'success');
                            if (data.details) {
                                addLog('  ' + (data.details.message || 'Connecting...'), 'info');
                            }
                            addLog('  TAK status will update automatically when connection completes', 'info');
                        } else if (data.connected) {
                            addLog('✓ TAK connection established', 'success');
                            if (data.details) {
                                addLog('  Server: ' + (data.details.host || 'Unknown') + ':' + (data.details.port || 'Unknown'), 'info');
                                addLog('  Protocol: ' + (data.details.protocol || 'tcp').toUpperCase(), 'info');
                                addLog('  Certificate: ' + (data.details.cert_file || 'Not specified'), 'info');
                                if (data.details.message) {
                                    addLog('  ' + data.details.message, 'info');
                                }
                            }
                        } else {
                            addLog('✓ TAK connection disconnected', 'info');
                            addLog('  TAK service stopped', 'info');
                        }
                        updateStatus();
                    } else {
                        addLog('✗ TAK toggle failed: ' + (data.error || 'Unknown error'), 'error');
                        if (data.details) {
                            addLog('  Server: ' + (data.details.host || 'Unknown') + ':' + (data.details.port || 'Unknown'), 'error');
                            addLog('  Protocol: ' + (data.details.protocol || 'tcp').toUpperCase(), 'error');
                            addLog('  Certificate: ' + (data.details.cert_file || 'Not specified'), 'error');
                            if (data.details.message) {
                                addLog('  ' + data.details.message, 'error');
                            }
                        }
                        if (data.error && data.error.includes('not configured')) {
                            addLog('  Please configure TAK settings in the Config tab', 'warning');
                        }
                    }
                })
                .catch(err => {
                    const errorMsg = err.message || err.toString();
                    console.error('[ERROR] TAK toggle error:', err);
                    console.error('[ERROR] Error message:', errorMsg);
                    console.error('[ERROR] Error stack:', err.stack);
                    serverConnected = false;
                    if (errorMsg.includes('NetworkError') || errorMsg.includes('Failed to fetch')) {
                        addLog('✗ TAK toggle error: Network connection failed', 'error');
                        addLog('  Check that the dashboard server is running', 'error');
                        // Stop status updates if server is down
                        if (statusInterval) {
                            clearInterval(statusInterval);
                            statusInterval = null;
                        }
                    } else {
                        addLog('✗ TAK toggle error: ' + errorMsg, 'error');
                    }
                })
                .finally(() => {
                    if (takDot) {
                        takDot.style.opacity = '1';
                        takDot.style.pointerEvents = 'auto';
                    }
                });
        }

        function executeOperation() {
            const mode = getOperationMode();
            if (!mode) {
                addLog('Please select an operation mode', 'error');
                return;
            }
            
            const params = {
                mode: mode,
                verbose: verboseModeEnabled
            };

            if (mode.startsWith('collect') || mode === 'target' || mode.startsWith('full')) {
                params.initial_scan = document.getElementById('initialScan').value;
                params.target_scan = document.getElementById('targetScan').value;
                params.deauth_packets = document.getElementById('deauthPackets').value;
            }

            if (mode === 'target') {
                const targetESSID = document.getElementById('targetESSID').value;
                if (!targetESSID) {
                    console.error('[ERROR] Target ESSID is required');
                    addLog('Target ESSID is required for target mode', 'error');
                    return;
                }
                params.target_essid = targetESSID;
                params.target_search_attempts = document.getElementById('targetSearchAttempts').value;
                params.target_attempts = document.getElementById('targetAttempts').value;
            }

            if (mode.startsWith('process') || mode.startsWith('full')) {
                params.wordlist = document.getElementById('wordlist').value;
            }

            if (mode === 'map') {
                params.max_scans = document.getElementById('maxScans').value;
                params.scan_duration = document.getElementById('scanDuration').value;
                // gps_port not sent -- backend uses .gps-stub
                params.gps_lock_attempts = document.getElementById('gpsLockAttempts').value;
                params.gps_lock_wait = document.getElementById('gpsLockWait').value;
            }

            // Don't log operation start - it's redundant with the operation status indicator
            
            fetch('/api/start', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(params)
            })
            .then(r => {
                return r.json();
            })
            .then(data => {
                if (data.success) {
                    // Don't log operation started - status indicator shows this
                    startLogStream();
                } else {
                    console.error('[ERROR] Failed to start operation:', data.error);
                    addLog('Failed to start: ' + data.error, 'error');
                }
            })
            .catch(err => {
                console.error('[ERROR] Error starting operation:', err);
                addLog('Error starting operation: ' + err, 'error');
            });
        }

        function stopOperation() {
            fetch('/api/stop', {method: 'POST'})
                .then(r => {
                    return r.json();
                })
                .then(data => {
                    if (data.success) {
                        addLog('Operation stopped (SIGINT sent)', 'info');
                        if (logEventSource) {
                            logEventSource.close();
                            logEventSource = null;
                        }
                        // Update status to refresh button states
                        updateStatus();
                    } else {
                        addLog('Failed to stop operation: ' + (data.error || 'Unknown error'), 'error');
                    }
                })
                .catch(err => {
                    console.error('[ERROR] Error stopping operation:', err);
                    addLog('Error stopping operation: ' + err, 'error');
                });
        }

        function updateTAKConfig() {
            // Auto-save on change
        }

        function saveTAKConfig() {
            const config = {
                tak: {
                    enabled: true,
                    host: document.getElementById('takHost').value,
                    port: parseInt(document.getElementById('takPort').value),
                    protocol: document.getElementById('takProtocol').value,
                    cert_file: document.getElementById('takCert').value,
                    ca_file: document.getElementById('takCA').value
                }
            };
            
            fetch('/api/config', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(config)
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    addLog('TAK configuration saved', 'success');
                }
            });
        }

        function uploadCertificate(type) {
            const input = type === 'cert' ? document.getElementById('takCertUpload') : document.getElementById('takCAUpload');
            const textInput = type === 'cert' ? document.getElementById('takCert') : document.getElementById('takCA');
            const file = input.files[0];
            if (!file) return;
            
            const formData = new FormData();
            formData.append('file', file);
            formData.append('type', type);
            
            fetch('/api/tak/upload-cert', {
                method: 'POST',
                body: formData
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    textInput.value = data.filename;
                    addLog(`Certificate uploaded: ${data.filename}`, 'success');
                    updateTAKConfig();
                } else {
                    addLog('Certificate upload failed: ' + (data.error || 'Unknown error'), 'error');
                }
            })
            .catch(err => {
                addLog('Certificate upload error: ' + err, 'error');
            });
        }

        function updateInterfaceConfig() {
            // Auto-save on change
        }

        function saveInterfaceConfig() {
            const config = {
                interface: {
                    candidates: document.getElementById('monitorCandidates').value
                }
            };
            
            fetch('/api/config', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(config)
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    addLog('Interface configuration saved', 'success');
                }
            });
        }

        function startLogStream() {
            if (logEventSource) {
                logEventSource.close();
                logEventSource = null;
            }
            
            try {
                logEventSource = new EventSource('/api/logs/stream');
                
                logEventSource.onopen = function() {
                };
                
                logEventSource.onmessage = function(event) {
                    try {
                        const data = JSON.parse(event.data);
                        
                        // Handle prompts FIRST - even if message is empty
                        if (data.prompt) {
                            
                            // Handle TAK password prompts with modal
                            if (data.tak_password_prompt || data.prompt.tak_password) {
                                showTakPasswordModal(data.prompt);
                                // Also add to log for reference
                                if (data.message && data.message.trim()) {
                                    // Calculate indentation from raw log line
                                    let indent = 0;
                                    if (data.raw) {
                                        const prefixMatch = data.raw.match(/^(\s+)/);
                                        if (prefixMatch) {
                                            indent = prefixMatch[1].length;
                                        }
                                    }
                                    addLog(data.message, data.level || 'info', data.prefix || '', null, data.timestamp, indent);
                                }
                                return; // Don't process as regular log message
                            }
                            
                            // Handle interface prompts - display inline in log
                            if (data.prompt && data.prompt.interface_prompt) {
                                // Use prompt message if available, otherwise use the data message
                                let promptMessage = data.prompt && data.prompt.message ? data.prompt.message : 
                                                  (data.message && data.message.trim() ? data.message : 'Enter interface name');
                                // Clean up the message - remove timestamp if present
                                promptMessage = promptMessage.replace(/\s+\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s*$/, '').trim();
                                promptMessage = promptMessage.replace(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s*/, '').trim();
                                addLog(promptMessage || 'Enter interface name', data.level || 'info', data.prefix || '', data.prompt);
                                return; // Don't process as regular log message
                            }
                            
                            // Handle other prompts (ESSID, etc.) - display inline in log
                            // Use prompt message if available, otherwise use the data message
                            let promptMessage = data.prompt && data.prompt.message ? data.prompt.message : 
                                                  (data.message && data.message.trim() ? data.message : 'Input required');
                            // Clean up the message - remove timestamp if present (at end or beginning)
                            promptMessage = promptMessage.replace(/\s+\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s*$/, '').trim();
                            promptMessage = promptMessage.replace(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s*/, '').trim();
                            addLog(promptMessage || 'Input required', data.level || 'info', data.prefix || '', data.prompt);
                            return; // Don't process as regular log message
                        }
                        
                        // Handle regular log messages (no prompts)
                        if (data.message && data.message.trim() && data.level !== 'keepalive') {
                            addLog(data.message, data.level || 'info', data.prefix);
                        }
                    } catch (e) {
                        console.error('Error parsing log message:', e, event.data);
                    }
                };
                
                logEventSource.onerror = function(e) {
                    // Only log error once to avoid spam
                    if (logEventSource && logEventSource.readyState === EventSource.CLOSED) {
                        if (connectionErrorCount === 0) {
                            addLog('Log stream disconnected. Server may have restarted.', 'warning');
                        }
                        // Close the connection to prevent repeated errors
                        if (logEventSource) {
                            logEventSource.close();
                            logEventSource = null;
                        }
                    } else if (logEventSource && logEventSource.readyState === EventSource.CONNECTING) {
                        // Connection is trying to reconnect - don't spam errors
                        return;
                    }
                };
            } catch (e) {
                console.error('Error creating log stream:', e);
                addLog('Failed to start log stream: ' + e.message, 'error');
            }
        }

        function addLog(message, level = 'info', prefix = '', promptData = null, timestamp = null, indent = 0) {
            // Allow prompts to be displayed even if message is empty
            if (!promptData && (!message || !message.trim())) return;
            
            const viewer = document.getElementById('logViewer');
            if (!viewer) return;
            
            const entry = document.createElement('div');
            entry.className = 'log-entry ' + level;
            
            // Add timestamp
            const timestampEl = document.createElement('span');
            timestampEl.className = 'log-timestamp';
            if (timestamp) {
                timestampEl.textContent = timestamp + ' ';
            } else {
                const now = new Date();
                const ts = now.getFullYear() + '-' + 
                    String(now.getMonth() + 1).padStart(2, '0') + '-' + 
                    String(now.getDate()).padStart(2, '0') + ' ' +
                    String(now.getHours()).padStart(2, '0') + ':' + 
                    String(now.getMinutes()).padStart(2, '0') + ':' + 
                    String(now.getSeconds()).padStart(2, '0');
                timestampEl.textContent = ts + ' ';
            }
            entry.appendChild(timestampEl);
            
            // Add prefix with proper icon
            const prefixStr = prefix || '';
            let prefixIcon = '';
            if (prefixStr) {
                const prefixEl = document.createElement('span');
                prefixEl.className = 'log-prefix';
                // Map prefix to icons
                if (prefixStr.includes('[✓]') || prefixStr.includes('[+]')) {
                    prefixIcon = '✓';
                } else if (prefixStr.includes('[✗]') || prefixStr.includes('[X]') || prefixStr.includes('[!]')) {
                    prefixIcon = '✗';
                } else if (prefixStr.includes('[▲]') || prefixStr.includes('[-]')) {
                    prefixIcon = '▲';
                } else if (prefixStr.includes('[•]') || prefixStr.includes('[*]') || prefixStr.includes('[→]') || prefixStr.includes('[←]')) {
                    prefixIcon = '•';
                } else {
                    prefixIcon = prefixStr;
                }
                prefixEl.textContent = prefixIcon + ' ';
                entry.appendChild(prefixEl);
            }
            
            // Add indentation if needed
            if (indent > 0) {
                const indentEl = document.createElement('span');
                indentEl.textContent = ' '.repeat(indent);
                entry.appendChild(indentEl);
            }
            
            if (promptData) {
                // Display the prompt message in the log entry
                const displayMessage = message && message.trim() ? message : (promptData.message || 'Input required');
                entry.appendChild(document.createTextNode(displayMessage));
                viewer.appendChild(entry);
                
                const promptDiv = document.createElement('div');
                promptDiv.className = 'log-entry prompt-entry';
                promptDiv.style.display = 'flex';
                promptDiv.style.gap = '10px';
                promptDiv.style.alignItems = 'center';
                promptDiv.style.marginTop = '5px';
                promptDiv.style.padding = '8px';
                promptDiv.style.background = '#2d2d2d';
                promptDiv.style.borderRadius = '4px';
                promptDiv.style.border = '2px solid #0066ff';
                promptDiv.dataset.promptId = promptData.id;
                
                const promptText = document.createElement('span');
                // Use prompt message, clean of any timestamp
                let promptMsg = promptData.message || displayMessage;
                promptMsg = promptMsg.replace(/\s+\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s*$/, '').trim();
                promptMsg = promptMsg.replace(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s*/, '').trim();
                promptText.textContent = promptMsg || 'Input required';
                promptText.style.flex = '1';
                promptText.style.fontWeight = '500';
                promptText.style.color = '#fff';
                
                const promptInput = document.createElement('input');
                promptInput.type = promptData.type === 'password' ? 'password' : 'text';
                promptInput.placeholder = 'Enter response...';
                promptInput.style.flex = '1';
                promptInput.style.padding = '6px';
                promptInput.style.background = '#1a1a1a';
                promptInput.style.border = '1px solid #444';
                promptInput.style.borderRadius = '4px';
                promptInput.style.color = '#e0e0e0';
                const isTakPassword = promptData.tak_password || false;
                const isInterfacePrompt = promptData.interface_prompt || false;
                promptInput.onkeypress = function(e) {
                    if (e.key === 'Enter') {
                        submitInlinePrompt(promptData.id, promptInput.value, isTakPassword, isInterfacePrompt);
                    }
                };
                
                const promptBtn = document.createElement('button');
                promptBtn.textContent = 'Submit';
                promptBtn.className = 'btn btn-primary';
                promptBtn.style.padding = '6px 12px';
                promptBtn.onclick = function() {
                    submitInlinePrompt(promptData.id, promptInput.value, isTakPassword, isInterfacePrompt);
                };
                
                promptDiv.appendChild(promptText);
                promptDiv.appendChild(promptInput);
                promptDiv.appendChild(promptBtn);
                
                const existingPrompts = viewer.querySelectorAll('.prompt-entry');
                existingPrompts.forEach(p => p.remove());
                
                viewer.appendChild(promptDiv);
                // Force scroll to bottom and ensure prompt is visible
                viewer.scrollTop = viewer.scrollHeight;
                promptDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                
                // Force visibility
                promptDiv.style.display = 'flex';
                promptDiv.style.visibility = 'visible';
                promptDiv.style.opacity = '1';
                
                setTimeout(() => {
                    promptInput.focus();
                    viewer.scrollTop = viewer.scrollHeight;
                }, 100);
            } else {
                entry.textContent = prefixStr + message;
                viewer.appendChild(entry);
                viewer.scrollTop = viewer.scrollHeight;
            }

            // Mirror into the Analysis tab's log viewer (if present) so
            // Analysis-tab-launched operations show output there too.
            const analysisViewer = document.getElementById('analysisLogViewer');
            if (analysisViewer) {
                analysisViewer.appendChild(entry.cloneNode(true));
                analysisViewer.scrollTop = analysisViewer.scrollHeight;
            }
        }

        let currentTakPasswordPrompt = null;
        
        function showTakPasswordModal(promptData) {
            currentTakPasswordPrompt = promptData;
            
            // Try to get modal elements - wait for DOM if needed
            function tryGetModalElements() {
                return {
                    modal: document.getElementById('takPasswordModal'),
                    messageEl: document.getElementById('takPasswordMessage'),
                    inputEl: document.getElementById('takPasswordInput'),
                    errorEl: document.getElementById('takPasswordError')
                };
            }
            
            function showModalContent(modal, messageEl, inputEl, errorEl) {
                // Only log debug if modal is found (to avoid spam)
                if (modal && messageEl && inputEl && errorEl) {
                } else {
                    // Silently use fallback - no error needed since fallback works
                    // Fallback: create a temporary password input modal
                const fallbackModal = document.createElement('div');
                fallbackModal.id = 'takPasswordModalFallback';
                fallbackModal.className = 'modal';
                fallbackModal.style.display = 'block';
                fallbackModal.style.position = 'fixed';
                fallbackModal.style.zIndex = '10000';
                fallbackModal.style.left = '0';
                fallbackModal.style.top = '0';
                fallbackModal.style.width = '100%';
                fallbackModal.style.height = '100%';
                fallbackModal.style.backgroundColor = 'rgba(0,0,0,0.8)';
                fallbackModal.style.display = 'flex';
                fallbackModal.style.alignItems = 'center';
                fallbackModal.style.justifyContent = 'center';
                
                const modalContent = document.createElement('div');
                modalContent.style.backgroundColor = '#1a1a1a';
                modalContent.style.padding = '20px';
                modalContent.style.borderRadius = '8px';
                modalContent.style.border = '1px solid #444';
                modalContent.style.minWidth = '400px';
                
                const header = document.createElement('div');
                header.textContent = 'TAK Certificate Password Required';
                header.style.fontSize = '18px';
                header.style.fontWeight = 'bold';
                header.style.marginBottom = '15px';
                header.style.color = '#fff';
                
                const message = document.createElement('p');
                message.textContent = promptData.message || 'Enter PKCS#12 certificate password:';
                message.style.marginBottom = '15px';
                message.style.color = '#ccc';
                
                const passwordInput = document.createElement('input');
                passwordInput.type = 'password';
                passwordInput.placeholder = 'Enter password...';
                passwordInput.style.width = '100%';
                passwordInput.style.padding = '10px';
                passwordInput.style.marginBottom = '15px';
                passwordInput.style.fontSize = '1em';
                passwordInput.style.border = '1px solid #444';
                passwordInput.style.borderRadius = '4px';
                passwordInput.style.backgroundColor = '#0a0a0a';
                passwordInput.style.color = '#fff';
                passwordInput.style.boxSizing = 'border-box';
                
                const errorDiv = document.createElement('p');
                errorDiv.id = 'takPasswordErrorFallback';
                errorDiv.style.color = '#f44336';
                errorDiv.style.marginBottom = '15px';
                errorDiv.style.display = 'none';
                
                const buttonDiv = document.createElement('div');
                buttonDiv.style.display = 'flex';
                buttonDiv.style.gap = '10px';
                buttonDiv.style.justifyContent = 'flex-end';
                
                const cancelBtn = document.createElement('button');
                cancelBtn.textContent = 'Cancel';
                cancelBtn.style.padding = '8px 16px';
                cancelBtn.style.backgroundColor = '#333';
                cancelBtn.style.color = '#fff';
                cancelBtn.style.border = '1px solid #555';
                cancelBtn.style.borderRadius = '4px';
                cancelBtn.style.cursor = 'pointer';
                cancelBtn.onclick = function() {
                    document.body.removeChild(fallbackModal);
                };
                
                const submitBtn = document.createElement('button');
                submitBtn.textContent = 'Submit';
                submitBtn.style.padding = '8px 16px';
                submitBtn.style.backgroundColor = '#0a7';
                submitBtn.style.color = '#fff';
                submitBtn.style.border = 'none';
                submitBtn.style.borderRadius = '4px';
                submitBtn.style.cursor = 'pointer';
                submitBtn.onclick = function() {
                    if (!passwordInput.value.trim()) {
                        errorDiv.textContent = 'Please enter a password';
                        errorDiv.style.display = 'block';
                        return;
                    }
                    submitTakPasswordDirectly(passwordInput.value);
                    document.body.removeChild(fallbackModal);
                };
                
                passwordInput.onkeypress = function(e) {
                    if (e.key === 'Enter') {
                        submitBtn.click();
                    }
                };
                
                modalContent.appendChild(header);
                modalContent.appendChild(message);
                modalContent.appendChild(passwordInput);
                modalContent.appendChild(errorDiv);
                buttonDiv.appendChild(cancelBtn);
                buttonDiv.appendChild(submitBtn);
                modalContent.appendChild(buttonDiv);
                fallbackModal.appendChild(modalContent);
                document.body.appendChild(fallbackModal);
                
                    setTimeout(() => passwordInput.focus(), 100);
                    return;
                }
                
                // Modal elements found - use them
                if (messageEl) {
                    messageEl.textContent = promptData.message || 'Enter PKCS#12 certificate password:';
                }
                if (inputEl) {
                    inputEl.value = '';
                    inputEl.disabled = false;
                    setTimeout(() => inputEl.focus(), 100);
                }
                if (errorEl) {
                    errorEl.style.display = 'none';
                    errorEl.textContent = '';
                }
                if (modal) {
                    modal.style.display = 'block';
                }
            }
            
            // Get modal elements
            let elements = tryGetModalElements();
            let modal = elements.modal;
            let messageEl = elements.messageEl;
            let inputEl = elements.inputEl;
            let errorEl = elements.errorEl;
            
            // If modal not found, try waiting a bit for DOM to be ready (with retry limit)
            if (!modal || !messageEl || !inputEl || !errorEl) {
                // First check if document is ready
                if (document.readyState === 'loading') {
                    // Wait for DOMContentLoaded
                    document.addEventListener('DOMContentLoaded', function() {
                        setTimeout(() => {
                            elements = tryGetModalElements();
                            modal = elements.modal;
                            messageEl = elements.messageEl;
                            inputEl = elements.inputEl;
                            errorEl = elements.errorEl;
                            showModalContent(modal, messageEl, inputEl, errorEl);
                        }, 100);
                    });
                    return;
                }
                
                let retryCount = 0;
                const maxRetries = 50; // 5 seconds max wait (50 * 100ms)
                const checkInterval = setInterval(() => {
                    retryCount++;
                    elements = tryGetModalElements();
                    modal = elements.modal;
                    messageEl = elements.messageEl;
                    inputEl = elements.inputEl;
                    errorEl = elements.errorEl;
                    
                    if (modal && messageEl && inputEl && errorEl) {
                        clearInterval(checkInterval);
                        showModalContent(modal, messageEl, inputEl, errorEl);
                    } else if (retryCount >= maxRetries) {
                        clearInterval(checkInterval);
                        // Use fallback modal
                        showModalContent(null, null, null, null);
                    }
                }, 100);
                return;
            }
            
            // Modal elements found immediately - show it
            showModalContent(modal, messageEl, inputEl, errorEl);
        }
        
        function submitTakPasswordDirectly(password) {
            fetch('/api/tak/password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({password: password})
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    addLog('Password submitted successfully', 'success');
                } else {
                    addLog('Password submission failed: ' + (data.error || 'Unknown error'), 'error');
                }
            })
            .catch(err => {
                console.error('Error submitting password:', err);
                addLog('Error submitting password: ' + err.message, 'error');
            });
        }
        
        function closeTakPasswordModal() {
            const modal = document.getElementById('takPasswordModal');
            const inputEl = document.getElementById('takPasswordInput');
            const errorEl = document.getElementById('takPasswordError');
            
            if (modal) {
                modal.style.display = 'none';
            }
            if (inputEl) {
                inputEl.value = '';
            }
            if (errorEl) {
                errorEl.style.display = 'none';
                errorEl.textContent = '';
            }
            currentTakPasswordPrompt = null;
        }
        
        function submitTakPassword() {
            const inputEl = document.getElementById('takPasswordInput');
            const errorEl = document.getElementById('takPasswordError');
            
            if (!inputEl || !inputEl.value.trim()) {
                if (errorEl) {
                    errorEl.textContent = 'Please enter a password';
                    errorEl.style.display = 'block';
                }
                return;
            }
            
            const password = inputEl.value.trim();
            
            // Disable input while submitting
            inputEl.disabled = true;
            if (errorEl) {
                errorEl.style.display = 'none';
            }
            
            fetch('/api/tak/password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({password: password})
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    addLog('Password submitted successfully', 'success');
                    closeTakPasswordModal();
                } else {
                    if (errorEl) {
                        errorEl.textContent = data.error || 'Invalid password. Please try again.';
                        errorEl.style.display = 'block';
                    }
                    inputEl.disabled = false;
                    inputEl.focus();
                    inputEl.select();
                }
            })
            .catch(err => {
                console.error('Error submitting password:', err);
                if (errorEl) {
                    errorEl.textContent = 'Error submitting password. Please try again.';
                    errorEl.style.display = 'block';
                }
                inputEl.disabled = false;
                inputEl.focus();
            });
        }
        
        // Allow Enter key to submit password
        document.addEventListener('DOMContentLoaded', function() {
            const inputEl = document.getElementById('takPasswordInput');
            if (inputEl) {
                inputEl.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') {
                        submitTakPassword();
                    }
                });
            }
            
            // Close modal when clicking outside
            const modal = document.getElementById('takPasswordModal');
            if (modal) {
                modal.addEventListener('click', function(e) {
                    if (e.target === modal) {
                        closeTakPasswordModal();
                    }
                });
            }
        });
        
        function submitInlinePrompt(promptId, response, isTakPassword = false, isInterfacePrompt = false) {
            const promptEntry = document.querySelector(`[data-prompt-id="${promptId}"]`);
            if (promptEntry) {
                promptEntry.remove();
            }
            
            let endpoint, body;
            if (isTakPassword) {
                endpoint = '/api/tak/password';
                body = {password: response};
            } else if (isInterfacePrompt) {
                endpoint = '/api/interface/prompt';
                body = {prompt_id: promptId, interface: response};
            } else {
                endpoint = '/api/prompt/response';
                body = {id: promptId, response: response, tak_password: isTakPassword};
            }
            
            fetch(endpoint, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(body)
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    if (isInterfacePrompt) {
                        addLog('✓ Interface name submitted: ' + response, 'success');
                        // Status will update automatically
                        updateStatus();
                    }
                    // Don't log password submissions or responses - they're already shown in the prompt
                    // Only log errors
                } else {
                    addLog('Failed to submit response: ' + (data.error || 'Unknown error'), 'error');
                }
            })
            .catch(err => {
                addLog('Error submitting response: ' + err.message, 'error');
            });
        }

        // Initialize system on page load
        async function initializeApp() {
            // Wait a bit for DOM to be ready
            setTimeout(() => {
                // Removed verbose initialization messages - status indicator shows system state
                
                fetch('/api/initialize', { method: 'POST' })
                    .then(response => {
                        if (!response.ok) {
                            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                        }
                        return response.json();
                    })
                    .then(data => {
                        if (!data.success) {
                            addLog('✗ System initialization failed', 'error');
                            addLog('✗ ' + (data.message || 'Unknown error'), 'error');
                            addLog('Please run ./start.sh to create required directories', 'warning');
                        }
                        // Success case - no verbose logging, status indicator shows ready state
                        
                        // Start status updates
                        updateStatus();
                        if (!statusInterval) {
                            statusInterval = setInterval(updateStatus, 2000);
                        }
                        // Check Internet connectivity on initial load
                        checkInternetConnectivity();
                        // Check Internet connectivity every 10 seconds
                        setInterval(checkInternetConnectivity, 10000);
                        loadConfig();
                        updateModeOptions();
                        
                        // Start log stream immediately to receive TAK password prompts and other messages
                        startLogStream();
                        
                        // Also check if operation is running (for backward compatibility)
                        setTimeout(() => {
                            fetch('/api/status')
                                .then(r => r.json())
                                .then(data => {
                                    // Log stream is already started above, so we don't need to start it again
                                })
                                .catch(err => console.error('[ERROR] Error checking status:', err));
                        }, 1000);
                    })
                    .catch(err => {
                        console.error('[ERROR] Initialization error:', err);
                        addLog('✗ Initialization error: ' + err.message, 'error');
                        
                        // Still start status updates even if initialization fails
                        updateStatus();
                        if (!statusInterval) {
                            statusInterval = setInterval(updateStatus, 2000);
                        }
                        // Check Internet connectivity on initial load
                        checkInternetConnectivity();
                        // Check Internet connectivity every 10 seconds
                        setInterval(checkInternetConnectivity, 10000);
                        loadConfig();
                        updateModeOptions();
                    });
            }, 100);
        }
        
        // Reset global state on page load to allow refresh
        window.dashboardLoaded = false;
        window.dashboardLoading = false;
        window.dashboardScriptInjected = false;
        window.dashboardInitialized = false;
        
        // Run initialization when page loads
        // Check Internet connectivity immediately on page load
        if (typeof checkInternetConnectivity === 'function') {
            setTimeout(checkInternetConnectivity, 500);
        }
        
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initializeApp);
        } else {
            initializeApp();
        }
    </script>
</body>
</html>'''
    return render_template_string(control_panel_template)

# Initialize system on startup
initialize_system()

if __name__ == '__main__':
    # Disable reloader to prevent global state loss on code changes
    # Set debug=True for error pages but use_reloader=False to preserve state
    app.run(debug=True, use_reloader=False, host='0.0.0.0', port=5000) 