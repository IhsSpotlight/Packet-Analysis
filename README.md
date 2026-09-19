# SENTINEL Enterprise IDS

> **Research-grade, Real-time Hybrid Network Intrusion Detection System**

SENTINEL Enterprise is a lightweight, distributed Hybrid Network Intrusion Detection System (IDS) designed for multi-network enterprise environments. It combines rule-based signature detection, statistical behavioral baselining, and unsupervised machine learning anomaly detection into a unified platform.

---

## Key Features

* **Multi-Engine Detection System:**
  * **Rule-Based & Signatures:** Detects Port Scans (SYN/FIN/NULL/XMAS), DoS/SYN Floods, Open Port drift, TTL anomalies, ARP spoofing (mid-session MAC swap), TCP Sequence Injection, RST storms, and Duplicate ACK storms.
  * **Behavioral Baseline:** Computes hourly Z-score deviations ($Z \ge 3.0$) over a 7-day rolling window per network.
  * **ML Anomaly Engine:** Uses an Isolation Forest trained across 17 bidirectional flow-level features with per-feature Z-score deviation explanations.
* **Alert Correlation & Risk Scoring:** Intelligently groups multi-signal alerts from the same source IP into single incident objects assigned a composite Risk Score ($0\text{--}100$).
* **Asset Discovery & Registry:** Periodic ARP sweeping auto-detects unknown or rogue devices on local subnets.
* **Role-Based Access Control (RBAC):** Centralized SOC dashboard with granular user scoping (`senior_user` restricted to single network view; `soc_admin` full visibility).
* **IP Intelligence & Enrichment:** Enriches alerts in real-time with Reverse DNS, ASN, GeoIP/Location, ISP, and common service identification (Google, Cloudflare, Akamai, GitHub, etc.).

---

## Architecture Overview

```
                        +-------------------------------------+
                        |          SOC Central Server         |
                        |      (Flask, SQLite, ML Engine)     |
                        +-------------------------------------+
                                   ^              ^
                       REST Ingest |              | REST Ingest
                      (Bearer Auth)|              | (Bearer Auth)
                                   |              |
         +-------------------------+              +-------------------------+
         |                                                                  |
+------------------+                                              +------------------+
| Sensor: hr-net   |                                              | Sensor: dev-net  |
| (Python Agent)   |                                              | (Python Agent)   |
+------------------+                                              +------------------+
| - Live Packet    |                                              | - Live Packet    |
|   Capture        |                                              |   Capture        |
| - Scan Detector  |                                              | - Scan Detector  |
| - Hijack Engine  |                                              | - Hijack Engine  |
| - Local SocketIO |                                              | - Local SocketIO |
+------------------+                                              +------------------+
```

---

## System Requirements

### Sensor Machine
* **OS:** Windows 10 / Ubuntu 20.04 / macOS 12 (Recommended: Ubuntu 22.04 LTS)
* **Python:** 3.10+ (Recommended: 3.12+)
* **RAM:** 512 MB minimum (Recommended: 2 GB)
* **Disk:** 500 MB minimum (Recommended: 5 GB for logs)
* **Privileges:** Admin / root for live capture (Dedicated service account recommended)

### SOC Server Machine
* **OS:** Any Python 3.10+ platform (Recommended: Ubuntu 22.04 LTS)
* **Python:** 3.10+ (Recommended: 3.12+)
* **RAM:** 1 GB minimum (Recommended: 4 GB)
* **Disk:** 2 GB minimum (Recommended: 20 GB as SQLite grows with traffic)
* **Network:** Reachable by all sensors (Dedicated internal IP recommended)

> **Note for Windows Sensor Deployments:**  
> Live capture on Windows requires [Npcap](https://npcap.com). When installing, ensure **"Install Npcap in WinPcap API-compatible mode"** is checked. Reboot after installation and verify using `list_interfaces.py`.

---

## Quick Start Guide

### 1. Installation

Clone the repository and install the dependencies for both components:

```bash
git clone https://github.com/your-username/sentinel-enterprise-ids.git
cd sentinel-enterprise-ids

# Install Sensor dependencies
pip install -r requirements.txt

# Linux note if pip complains about externally-managed environment:
# pip install -r requirements.txt --break-system-packages

# Install SOC Server dependencies
cd soc_server
pip install -r requirements.txt
cd ..
```

---

### 2. Demo Run (No Admin/Root Needed)

Verify installation using synthetic network traffic with zero privileges required:

```bash
python3 main.py --demo
```

Open your browser to `http://127.0.0.1:5000`. Demo alerts will begin populating within ~15 seconds.

---

### 3. Production Multi-Network Setup

#### Step 3.1: Start the Central SOC Server

```bash
cd soc_server
python3 app.py --db soc.db --host 0.0.0.0 --port 6000
cd ..
```
*Tip: Use `--host 0.0.0.0` so sensors on other machines can reach it. If running on one machine, `127.0.0.1` is safer.*

#### Step 3.2: Provision Sensor API Keys & Users

Generate dedicated API keys for sensors and administrative dashboard users:

```bash
# Provision Sensor API Keys (SAVE THE KEY OUTPUT - IT IS SHOWN ONLY ONCE)
python3 soc_server/provision_sensor.py --db soc_server/soc.db --network hr-net --hostname hr-laptop
python3 soc_server/provision_sensor.py --db soc_server/soc.db --network dev-net --hostname dev-server
python3 soc_server/provision_sensor.py --db soc_server/soc.db --network sec-net --hostname sec-laptop
python3 soc_server/provision_sensor.py --db soc_server/soc.db --network smm-net --hostname smm-laptop

# Provision single-network operators (senior_user)
python3 soc_server/provision_user.py --db soc_server/soc.db --username alice --role senior_user --network hr-net
python3 soc_server/provision_user.py --db soc_server/soc.db --username bob --role senior_user --network dev-net

# Provision a global Security Admin (soc_admin)
python3 soc_server/provision_user.py --db soc_server/soc.db --username ceo --role soc_admin
```
*Passwords are prompted interactively.*

#### Step 3.3: Identify Live Network Interface

```bash
python3 list_interfaces.py
```

Locate and copy the exact target interface name under the `Name` column (e.g., `wlan0`, `eth0`, `"Wi-Fi"`, or `"Ethernet 2"`).

#### Step 3.4: Launch the Live Sensor Agent

**Linux / macOS (Requires Root):**
```bash
sudo python3 main.py \
  --iface wlan0 \
  --network-id hr-net \
  --subnet 192.168.1.0/24 \
  --soc-url http://<SOC_SERVER_IP>:6000 \
  --soc-api-key <YOUR_PROVISIONED_API_KEY>
```

**Windows (Administrator Command Prompt):**
```cmd
python main.py --iface "Wi-Fi" --network-id hr-net --subnet 192.168.1.0/24 --soc-url http://<SOC_SERVER_IP>:6000 --soc-api-key <YOUR_PROVISIONED_API_KEY>
```

---

## Application Access & Dashboards

| Application | URL | Authentication | Capabilities |
| :--- | :--- | :--- | :--- |
| **Local Sensor WebUI** | `http://<SENSOR_IP>:5000` | Unauthenticated (Local) | Real-time SocketIO live packet stream, severity bars, modules armed, & alert detail diagnostics. |
| **Central SOC Dashboard** | `http://<SOC_SERVER_IP>:6000` | RBAC Credentials | Central incident aggregation, risk scores, ML flow analysis, behavioral baselines, asset tracking, & sensor health. |

### Dashboard Role Behavior

* **`senior_user`**: Restricted to viewing their assigned network's alerts and assets. Network switcher and sensor management panels are hidden.
* **`soc_admin`**: Full access across all provisioned networks, full sensor list with heartbeat status, and network filtering capabilities.

---

## Detection Signals Reference

| Signal Identifier | Engine | Severity | Primary Attack Type / Cause |
| :--- | :--- | :--- | :--- |
| `PORT_SCAN` | `scan_detector` | **HIGH** | Sequential or stealth probes hitting 15+ ports in 5 seconds (SYN, FIN, NULL, XMAS). |
| `SYN_FLOOD` | `scan_detector` | **CRITICAL** | Volumetric DoS / 50+ half-open TCP connections in 10 seconds. |
| `UNEXPECTED_OPEN_PORT`| `scan_detector` | **MEDIUM** | Unwhitelisted open listening port detected on host. |
| `TTL_ANOMALY` | `hijack_detector` | **HIGH** | Packet TTL shifted >5 hops mid-session (possible IP spoofing). |
| `MAC_SWAP` | `hijack_detector` | **CRITICAL** | Mid-session MAC swap (strong indicator of ARP spoofing). |
| `SEQ_ANOMALY` | `hijack_detector` | **HIGH** | Sequence number jump outside expected window (packet injection). |
| `RST_STORM` | `hijack_detector` | **HIGH** | 5+ RST packets on one session within 5 seconds (hijack race). |
| `DUP_ACK_STORM` | `hijack_detector` | **MEDIUM** | Same ACK repeated 4+ times in 5 seconds (hijack race or lossy Wi-Fi). |
| `UNREGISTERED_DEVICE` | `discovery` | **MEDIUM** | ARP sweep found a device not listed in the asset registry. |
| `BEHAVIORAL_SPIKE` | `behavioral` | **HIGH** | Hourly alert rate statistical anomaly ($Z \ge 3.0$). |
| `ML_FLOW_ANOMALY` | `ml_anomaly` | **HIGH** | Isolation Forest multivariate outlier across 17 flow features. |

---

## Asset Discovery & Management

When `--subnet` is provided to a sensor running with live capture (`--iface`), it performs an ARP sweep every 5 minutes and flags unknown devices.

### Sensor Local API

```bash
# List assets
curl http://127.0.0.1:5000/api/assets

# Register a device
curl -X POST http://127.0.0.1:5000/api/assets \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.50","mac":"AA:BB:CC:DD:EE:FF","label":"Alice laptop"}'

# Remove an asset
curl -X DELETE http://127.0.0.1:5000/api/assets/AA:BB:CC:DD:EE:FF
```

### SOC Central API

```bash
# View registered + discovered devices with diff flag
GET /api/assets?network=hr-net

# Register asset (soc_admin must append ?network=, senior_user is auto-scoped)
POST /api/assets?network=hr-net
Body: {"ip":"...","mac":"...","label":"..."}

# Remove asset
DELETE /api/assets/AA:BB:CC:DD:EE:FF?network=hr-net
```

---

## Incidents & Risk Scoring Formula

Alerts originating from the same source IP within 5 minutes are aggregated into a single Incident object with an overall Risk Score ($0\text{--}100$).

$$\text{Risk Score} = \min(\text{Severity Weight} + \text{Corroboration Weight}, 100)$$

* **Severity Weight (Max 70):** Sum of weights for the top 3 alerts in the group (`CRITICAL` = 40, `HIGH` = 25, `MEDIUM` = 12, `LOW` = 5).
* **Corroboration Weight (Max 30):** $(\text{Distinct Alert Types} - 1) \times 15$. Multiple independent detectors agreeing boosts the risk score.

---

## Advanced Detection Engines

### Behavioral Baseline Engine
Tracks hourly alert counts per network over a 7-day rolling window and evaluates:

$$Z = \frac{\text{current\_hour\_count} - \text{baseline\_mean}}{\max(\text{baseline\_stdev}, 1.0)}$$

Flags an anomaly when $Z \ge 3.0$ and at least 3 hours of historical data are present.

### Machine Learning Flow Anomaly Engine
Once a sensor forwards $\ge 20$ flow snapshots to the SOC server, an **Isolation Forest** model evaluates flows against 17 features:
* **Volume:** `total_packets`, `total_bytes`, forward/reverse packet and byte counts.
* **Rate:** `packets_per_second`, `bytes_per_second`, `avg_packet_size`.
* **TCP Flags:** `syn`, `synack`, `ack`, `rst`, `fin` counts.
* **Reliability:** Forward and reverse retransmit counts.
* **Temporal:** `duration_seconds`.

Flagged flows detail their top deviating features ordered by Z-score.

---

## CLI Reference Guide

### `main.py` (Sensor Options)

| Flag | Description | Default / Example |
| :--- | :--- | :--- |
| `--demo` | Enables synthetic traffic generation (no NIC or root required) | `--demo` |
| `--iface <name>` | Specifies interface for live capture (requires admin/root) | `--iface "Wi-Fi"` |
| `--network-id <id>` | Department or network tag | `--network-id hr-net` |
| `--subnet <CIDR>` | Subnet CIDR for periodic ARP discovery scans | `--subnet 192.168.1.0/24` |
| `--soc-url <url>` | Central SOC server base URL | `--soc-url http://soc:6000` |
| `--soc-api-key <key>`| Sensor API authentication key | `--soc-api-key abc...` |
| `--host <ip>` | Dashboard binding address | Default: `127.0.0.1` |
| `--port <n>` | Dashboard listening port | Default: `5000` |

### `soc_server/app.py` (SOC Server Options)

| Flag | Description | Default |
| :--- | :--- | :--- |
| `--db <path>` | SQLite database path (created on initial launch) | `soc.db` |
| `--host <ip>` | Server bind IP address | `127.0.0.1` |
| `--port <n>` | Server listening port | `6000` |
| `--secret-key <s>`| Session cookie signing secret key | `sentinel-soc-dev` |

---

## Testing Framework

SENTINEL Enterprise includes 133 automated unit and integration tests. None require elevated privileges or active network interfaces.

```bash
# Run Sensor Tests (64 Tests)
python3 capture/test_session_table.py
python3 capture/test_discovery.py
python3 detectors/test_scan_detector.py
python3 detectors/test_hijack_detector.py
python3 reporting/test_alert_manager.py
python3 reporting/test_ip_lookup.py
python3 reporting/test_forwarder.py

# Run SOC Server Tests (69 Tests)
cd soc_server
python3 test_db.py
python3 test_auth.py
python3 test_app.py
python3 test_behavioral.py
python3 test_ml_anomaly.py
python3 test_correlation.py
```

---

## Detection Threshold Tuning

Tunable parameters are located near the top of the detector source files:

| Target File | Constant Name | Default | Effect of Increasing Value |
| :--- | :--- | :--- | :--- |
| `scan_detector.py` | `PORT_SCAN_THRESHOLD` | `15` | Decreases port scan alert sensitivity |
| `scan_detector.py` | `SYNFLOOD_THRESHOLD` | `50` | Requires higher volume to trigger SYN flood alert |
| `hijack_detector.py` | `TTL_VARIANCE_THRESHOLD` | `5` | Tolerates greater route/VPN hop variance |
| `hijack_detector.py` | `DUP_ACK_THRESHOLD` | `4` | Decreases false positives on noisy wireless networks |
| `behavioral.py` | `DEFAULT_Z_THRESHOLD` | `3.0` | Requires larger statistical volume spikes to flag |
| `ml_anomaly.py` | `DEFAULT_CONTAMINATION` | `0.05` | Lowers the proportion of flows flagged as anomalous |

---

## Troubleshooting & FAQ

* **`ValueError: Interface not found`**: Ensure the interface name matches the exact string shown by `python3 list_interfaces.py`.
* **`Static CSS / JS return 404`**: Verify that the `dashboard/` directory resides directly inside the root folder alongside `main.py`.
* **`SOC server returns 401 on ingest`**: API key is missing or invalid. Re-run `provision_sensor.py` to issue a fresh key.
* **`ML anomalies: Need at least 20 flows`**: Ensure both `--soc-url` and `--soc-api-key` are supplied to `main.py`. Flow snapshots forward every 60 seconds.
* **`soc.db locked error`**: Multiple instances of `app.py` are attempting to write to `soc.db`. Ensure only one server process is running.
* **Firewall connectivity issues**: Verify TCP port `6000` is open for inbound connections on the SOC host machine.

---

## Deployment Notes & Security

1. **Host-Based Scope:** SENTINEL monitors traffic to/from the host machine on which the sensor is installed. On home NAT networks, WAN-targeted scans are filtered at the router.
2. **TLS Configuration:** Native TLS is not enabled out of the box. For production deployments, run a reverse proxy (e.g., Nginx or Caddy) in front of the SOC server to terminate TLS, or configure `ssl_context` in `soc_server/app.py`. Do not send API keys or passwords unencrypted over open channels.

---

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.