# TAK Server 5.6 Setup for MiFi Integration

This guide explains how to configure TAK Server 5.6 to receive and display WiFi network data from MiFi.

## Overview

**TAK Server 5.6 natively supports receiving CoT (Cursor on Target) messages** on ports 8087 (TCP) and 8088 (UDP). **No plugin is required** - this functionality is built into TAK Server.

MiFi sends WiFi network data as CoT messages in standard XML format, which TAK Server will automatically receive and display on the map.

## Prerequisites

- TAK Server 5.6 installed and running
- Network connectivity between MiFi device and TAK Server
- Client certificates (if using certificate-based authentication)
- Certificates placed in `MiFi/tak/` folder:
  - `.p12` file (PKCS#12 format - contains both certificate and key)
  - `.pem` file (CA certificate)

## TAK Server Configuration

### 1. Verify TAK Server is Running

```bash
sudo systemctl status takserver
```

If not running, start it:
```bash
sudo systemctl start takserver
```

### 2. Check TAK Server Ports

TAK Server listens on:
- **TCP Port 8087**: For CoT input (must be configured)
- **UDP Port 8088**: Alternative CoT input (must be configured)
- **Port 8443**: HTTPS web interface
- **Port 8444**: WebSocket connections

**IMPORTANT**: Port 8087 is NOT enabled by default in TAK Server 5.6. You must configure it.

Verify ports are open:
```bash
sudo ss -tlnp | grep -E '8087|8088|8443|8444'
# Or with netstat:
sudo netstat -tlnp | grep -E '8087|8088|8443|8444'
```

**If port 8087 is NOT showing**, you need to configure TAK Server to accept CoT input (see Configuration section below).

### 3. Firewall Configuration

Ensure firewall allows connections to TAK Server ports:

```bash
# For UFW
sudo ufw allow 8087/tcp
sudo ufw allow 8088/udp
sudo ufw allow 8443/tcp
sudo ufw allow 8444/tcp

# For iptables
sudo iptables -A INPUT -p tcp --dport 8087 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 8088 -j ACCEPT
```

### 4. Configure CoT Input (REQUIRED)

**TAK Server 5.6 does NOT automatically accept CoT messages on port 8087 by default.** You must configure it.

#### Option A: Configure via TAK Server Web Interface

1. **Access TAK Server Web Interface**: `https://tak-server-ip:8443`
2. **Navigate to Configuration** → **Inputs** or **Streams**
3. **Add New Input**:
   - **Type**: CoT (Cursor on Target)
   - **Protocol**: TCP
   - **Port**: 8087
   - **Name**: "CoT Input" or "MiFi Input"
   - **Enabled**: Yes
4. **Save Configuration**
5. **Restart TAK Server**:
   ```bash
   sudo systemctl restart takserver
   ```

#### Option B: Configure via CoreConfig.xml

1. **Edit TAK Server Configuration**:
   ```bash
   sudo nano /opt/tak/CoreConfig.xml
   # Or wherever your TAK Server config is located
   ```

2. **Add Input Configuration**:
   ```xml
   <configuration>
       <input>
           <streams>
               <stream>
                   <name>CoT Input</name>
                   <protocol>tcp</protocol>
                   <port>8087</port>
                   <readOnly>false</readOnly>
               </stream>
           </streams>
       </input>
   </configuration>
   ```

3. **Restart TAK Server**:
   ```bash
   sudo systemctl restart takserver
   ```

4. **Verify Port is Listening**:
   ```bash
   sudo ss -tlnp | grep 8087
   # Should show TAK Server listening on port 8087
   ```

#### Option C: Check Existing Configuration

If TAK Server is already configured, check:
- Configuration file location (varies by installation)
- Input/Stream settings in web interface
- Whether authentication is required for CoT input

### 5. Check TAK Server Logs

Monitor TAK Server logs to see incoming connections:

```bash
# TAK Server log location (typical)
sudo tail -f /opt/tak/logs/takserver.log
# Or
sudo journalctl -u takserver -f
```

## Client Authentication

### Certificate-Based Authentication

TAK Server 5.6 supports certificate-based authentication for CoT connections:

1. **Generate client certificates** using TAK Server's certificate management:
   ```bash
   cd /opt/tak/utils
   sudo ./makeCert.sh client MiFi-Scanner
   ```

2. **Export certificates** for use with MiFi:
   ```bash
   # PKCS#12 format (recommended - contains both cert and key)
   sudo openssl pkcs12 -export \
     -in /opt/tak/certs/files/MiFi-Scanner.pem \
     -inkey /opt/tak/certs/files/MiFi-Scanner.key \
     -out /opt/tak/certs/files/MiFi-Scanner.p12 \
     -name "MiFi-Scanner" \
     -passout pass:your_password_here
   ```

3. **Copy certificates to MiFi device**:
   ```bash
   # Copy to MiFi tak folder
   scp /opt/tak/certs/files/MiFi-Scanner.p12 user@mifi-device:/path/to/MiFi/tak/
   scp /opt/tak/certs/files/ca.pem user@mifi-device:/path/to/MiFi/tak/ca.pem
   ```

4. **Configure MiFi** to use certificates (in `config/config.ini`):
   ```ini
   [TAK]
   enabled = true
   host = tak.tk
   port = 8087
   protocol = tcp
   cert_file = MiFi-Scanner.p12
   ca_file = ca.pem
   ```

   **Note**: Certificate file paths in `config/config.ini` are relative to the `tak/` folder. The password will be prompted when connecting.

### No Authentication (Testing Only)

For testing, TAK Server can be configured to accept unauthenticated connections (not recommended for production):

1. Edit TAK Server configuration (location varies by installation)
2. Disable certificate validation for CoT input
3. **Warning**: This is insecure and should only be used in isolated test environments

## CoT Message Format

MiFi sends CoT messages in standard XML format compatible with TAK Server 5.6:

- **Protocol**: TCP with 4-byte big-endian length prefix + XML payload
- **Format**: CoT XML version 2.0
- **Event Types**: 
  - `t-x-c-t` for client presence messages (registration)
  - `a-f-G-E-V-C` for WiFi network equipment markers
- **Coordinates**: GPS coordinates in decimal degrees
- **Timestamps**: UTC in ISO 8601 format

### Example CoT Message Structure

```xml
<event version="2.0" uid="mifi-aa1122334455" type="a-f-G-E-V-C" 
      how="m-g" time="2025-01-07T12:00:00.000Z" 
      start="2025-01-07T12:00:00.000Z" stale="2025-01-08T12:00:00.000Z">
  <point lat="47.07733591" lon="-122.56836355" hae="100.0" ce="50.0" le="50.0"/>
  <detail>
    <contact callsign="NetworkName" endpoint="*:-1:stcp"/>
    <status battery="75"/>
    <track course="0.0" speed="0.0"/>
    <remarks>WiFi Network: NetworkName
BSSID: aa:11:22:33:44:55
Channel: 6
Signal: -65 dBm
Coordinates: 47.077336, -122.568364
Timestamp: 2025-01-07T12:00:00Z</remarks>
    <usericon iconsetpath="COT_MAPPING_2525C/a-f-G-E-V-C"/>
  </detail>
</event>
```

## Verifying Connection

### 1. Check TAK Server Web Interface

1. Access TAK Server web interface: `https://tak-server-ip:8443`
2. Navigate to **Clients** or **Connections** section
3. Look for client named "MiFi-Scanner" or check for incoming CoT messages

### 2. Monitor TAK Server Logs

```bash
sudo tail -f /opt/tak/logs/takserver.log | grep -i "mifi\|cot\|connection"
```

You should see log entries like:
```
INFO: Received CoT message from client
INFO: Processing CoT event: mifi-aa1122334455
INFO: Client connected: MiFi-Scanner
```

### 3. Check for CoT Messages

In TAK Server web interface:
- Go to **Map** view
- Look for markers appearing from MiFi device
- Check **Events** or **Messages** panel for incoming CoT data
- WiFi networks should appear as equipment markers on the map

### 4. Test with MiFi Verbose Mode

Run MiFi with verbose logging to see TAK activity:

```bash
sudo python3 mifi.py --mode map -tak -v -MS 5
```

You should see:
- "Connected to TAK server at [host]:[port] via TCP"
- "TAK connection verified - presence message sent"
- "Sent TAK presence message to register client"
- "Sent TAK CoT message #1 for [ESSID]..."

### 5. Test Network Connectivity

From the MiFi device, test basic connectivity:

```bash
# Test TCP connection
nc -zv tak-server-ip 8087

# Or with telnet
telnet tak-server-ip 8087
# If connection succeeds, TAK Server is reachable
```

## Troubleshooting

### Client Not Appearing in TAK Server

1. **Check network connectivity**:
   ```bash
   # From MiFi device
   ping tak-server-ip
   nc -zv tak-server-ip 8087
   ```

2. **Verify certificates**:
   - Ensure certificates are valid and not expired
   - Check certificate permissions (should be readable: `chmod 600 tak/*.p12 tak/*.pem`)
   - Verify CA certificate matches TAK Server's CA
   - Check certificate file paths in `config/config.ini` are correct

3. **Check TAK Server logs** for errors:
   ```bash
   sudo tail -100 /opt/tak/logs/takserver.log | grep -i error
   ```

4. **Verify CoT message format**:
   - TAK Server expects valid CoT XML
   - Check MiFi logs for CoT message content (with `-v` flag)
   - Ensure GPS coordinates are valid (not 0,0)

5. **Verify port 8087 is configured**:
   ```bash
   sudo ss -tlnp | grep 8087
   # Should show TAK Server listening
   ```

### CoT Messages Not Displaying

1. **Check CoT message format**:
   - Ensure GPS coordinates are valid (not 0,0)
   - Verify event type is recognized by TAK Server
   - Check that stale time is in the future

2. **Verify TAK Server is processing messages**:
   - Check TAK Server logs for CoT parsing errors
   - Verify messages are being received (check message count in web interface)

3. **Check map view settings**:
   - Ensure map is zoomed to correct area
   - Check if filters are hiding the markers
   - Verify icon set is loaded

### Connection Refused Errors

1. **TAK Server not running**:
   ```bash
   sudo systemctl start takserver
   sudo systemctl status takserver
   ```

2. **Port not accessible**:
   - Check firewall rules
   - Verify TAK Server is listening on port 8087
   - Check if nginx reverse proxy is configured correctly (if using)

3. **Certificate authentication failing**:
   - Verify client certificate is trusted by TAK Server
   - Check TAK Server certificate validation settings
   - Ensure CA certificate matches
   - Verify certificate password is correct

### Connection Test Fails

If MiFi reports connection failure:

1. **Verify TAK Server is accessible**:
   ```bash
   # From MiFi device
   nc -zv tak-server-ip 8087
   telnet tak-server-ip 8087
   ```

2. **Check TAK Server connection logs**:
   ```bash
   sudo tail -f /opt/tak/logs/takserver.log
   ```

3. **Verify certificate paths** in `config/config.ini`:
   - Ensure paths are correct (relative to `tak/` folder)
   - Check file permissions (should be readable)
   - Verify files exist: `ls -la tak/*.p12 tak/*.pem`

4. **Check MiFi logs** for detailed error messages:
   ```bash
   tail -f logs/YYYY-MM-DD_HH-MM-SS.log
   ```

## Nginx Reverse Proxy Setup

If using nginx as a reverse proxy, see `nginx_tak_stream.conf` for TCP stream configuration. **HTTP/HTTPS proxies cannot handle raw TCP CoT connections** - you must use nginx stream module.

### Nginx Stream Configuration

1. **Enable stream module** in nginx:
   ```bash
   # Check if stream module is available
   nginx -V 2>&1 | grep -o with-stream
   ```

2. **Add stream block** to `/etc/nginx/nginx.conf`:
   ```nginx
   stream {
       include /etc/nginx/stream.d/*.conf;
   }
   ```

3. **Create stream configuration** using `nginx_tak_stream.conf`:
   ```bash
   sudo cp tak/nginx_tak_stream.conf /etc/nginx/stream.d/tak.conf
   sudo nginx -t
   sudo systemctl reload nginx
   ```

4. **Verify nginx is proxying**:
   ```bash
   sudo ss -tlnp | grep 8087
   # Should show nginx listening and forwarding to TAK Server
   ```

## MiFi Configuration

### config.ini Setup

Configure TAK connection in `MiFi/config/config.ini`:

```ini
[TAK]
enabled = true
host = your-tak-server.com
port = 8087
protocol = tcp
cert_file = your-certificate.p12
ca_file = ca.pem
```

**Important Notes**:
- Certificate file paths are **relative to the `tak/` folder**
- The certificate password will be prompted when connecting via dashboard
- For CLI usage, password can be provided interactively

### Dashboard Usage

1. **Enable TAK in dashboard**: Toggle the TAK connection button
2. **Enter certificate password** when prompted
3. **Monitor connection status**: Green indicator means connected
4. **Start map mode**: TAK will automatically send CoT messages for detected networks

### CLI Usage

```bash
# Enable TAK and run map mode
sudo python3 mifi.py --mode map -tak -MS 25

# With verbose logging
sudo python3 mifi.py --mode map -tak -v -MS 25
```

## Summary

- **No plugin required** for basic CoT message reception
- TAK Server 5.6 natively supports CoT on ports 8087/8088
- **Port 8087 must be configured** in TAK Server (not enabled by default)
- Configure client certificates for authentication
- Place certificates (`.p12` and `.pem`) in `tak/` folder
- Monitor TAK Server logs to verify connections
- Use TAK Server web interface to view incoming data
- MiFi sends standard CoT XML format compatible with TAK Server 5.6

For detailed MiFi configuration, see the main README or `config/config.ini` comments.
