# SENTINEL Enterprise IDS — Complete Project Structure

```
antihijack-scanner/
│
│   # ── SENSOR ENTRY POINT ─────────────────────────────────────────────
├── main.py                         Sensor entry point. Wires all modules together,
│                                   starts the local Flask+SocketIO dashboard.
│                                   CLI flags:
│                                     --demo           synthetic traffic, no NIC needed
│                                     --iface <name>   live capture (needs root)
│                                     --network-id     e.g. hr-net, dev-net
│                                     --subnet <CIDR>  ARP discovery scanning
│                                     --soc-url        central SOC server URL
│                                     --soc-api-key    issued by provision_sensor.py
│                                     --host / --port  dashboard bind address
│
├── list_interfaces.py              Run this first on Windows/Mac to find the exact
│                                   interface name scapy expects (not "wlan0").
│
├── requirements.txt                Sensor dependencies:
│                                     flask, flask-socketio, python-socketio,
│                                     scapy, eventlet
│
│   # ── CAPTURE ──────────────────────────────────────────────────────────
├── capture/
│   ├── session_table.py            Core flow tracker. Maintains bidirectional
│   │                               Session objects keyed by canonical 5-tuple.
│   │                               Tracks fwd/rev packets+bytes, duration, pps/bps,
│   │                               min/max/avg packet size, TCP flag counts,
│   │                               retransmission indicators, per-direction TTL/MAC
│   │                               baselines, connection-reuse detection (generation
│   │                               bumping), and network_id stamping. flow_stats()
│   │                               exposes the full feature vector for forwarding.
│   │
│   ├── sniffer.py                  scapy live capture. Parses packets into
│   │                               PacketRecord, feeds SessionTable. Needs
│   │                               root / CAP_NET_RAW / Npcap on Windows.
│   │                               start_sniffing(iface, table, on_packet)
│   │
│   ├── discovery.py                Subnet scanning and asset registration.
│   │                               AssetRegistry: persistent JSON-backed approved-
│   │                               device list, matched by MAC (survives DHCP churn).
│   │                               DiscoveryScanner: ARP sweep via scapy.arping,
│   │                               diffs result against registry, emits
│   │                               UNREGISTERED_DEVICE alerts for unknown devices.
│   │                               start_discovery_thread(scanner, cidr, on_hosts)
│   │
│   ├── test_session_table.py       14 tests — bidirectional flow identity, fwd/rev
│   │                               accounting, retransmit detection, handshake
│   │                               success/failure, network_id propagation,
│   │                               connection-reuse reset.
│   │
│   └── test_discovery.py           7 tests — registry persistence, MAC-based
│                                   deduplication, UNREGISTERED_DEVICE firing,
│                                   cooldown suppression.
│
│   # ── DETECTORS ─────────────────────────────────────────────────────────
├── detectors/
│   ├── scan_detector.py            Module 2: port scan + SYN flood + open-port exposure.
│   │                               ScanDetector.on_packet(session, key, rec):
│   │                                 PORT_SCAN          — sliding-window unique-port count
│   │                                                      per source IP; classifies SYN/FIN/
│   │                                                      NULL/XMAS scan types from flags
│   │                                 SYN_FLOOD          — half-open connection count per
│   │                                                      source within a time window
│   │                                 ALERT_COOLDOWN     — per (src_ip, type) to avoid spam
│   │                               OpenPortMonitor.check():
│   │                                 UNEXPECTED_OPEN_PORT — periodic connect() scan of
│   │                                                        localhost against a whitelist
│   │
│   ├── hijack_detector.py          Module 1: session hijack / spoofing detection.
│   │                               HijackDetector.on_packet(session, key, rec):
│   │                                 TTL_ANOMALY        — per-direction baseline; drift > 5
│   │                                 MAC_SWAP           — per-direction baseline; mid-session
│   │                                                      source MAC change (ARP spoofing)
│   │                                 SEQ_ANOMALY        — forward jump > 500k or backward
│   │                                                      jump > 5k (not retransmit)
│   │                                 RST_STORM          — 5+ RSTs in 5s on one session
│   │                                 DUP_ACK_STORM      — same ACK value 4+ times in 5s
│   │                               Generation-scoped internal state (keyed by
│   │                               (session_key, generation)) so port-reuse false
│   │                               positives cannot occur.
│   │
│   ├── test_scan_detector.py       8 tests — normal traffic silence, port scan
│   │                               detection, SYN flood detection, completed-
│   │                               handshake negative case, flag classification,
│   │                               cooldown, open-port whitelist.
│   │
│   └── test_hijack_detector.py     12 tests — each signal independently, normal
│                                   traffic silence, retransmit negative case,
│                                   connection-reuse regression, direction-blind
│                                   MAC/TTL regression, cooldown.
│
│   # ── REPORTING (sensor-side pipeline) ─────────────────────────────────
├── reporting/
│   ├── alert.py                    Alert dataclass — alert_type, src_ip, severity
│   │                               (LOW/MEDIUM/HIGH/CRITICAL), message, details dict,
│   │                               timestamp, network_id. to_dict() for wire format.
│   │
│   ├── alert_manager.py            Central alert hub (sensor-side). Rolling history,
│   │                               per-type/severity stats, JSON-lines log, subscriber
│   │                               broadcast. A broken subscriber (e.g. network blip)
│   │                               cannot crash the detection pipeline.
│   │
│   ├── ip_lookup.py                IP enrichment: reverse DNS + org/ASN/ISP/country
│   │                               via ip-api.com (free, no key). derive_service_name()
│   │                               matches known services (Google, Facebook, Microsoft,
│   │                               Amazon, Cloudflare, Akamai, Apple, Netflix, GitHub,
│   │                               etc). Private/loopback IPs short-circuit without a
│   │                               network call. Server-side + client-side caching.
│   │
│   ├── forwarder.py                Ships alerts/flows/discovery to the SOC server.
│   │                               Three independent channels — an outage on the flow
│   │                               endpoint doesn't block alert delivery. Buffers to
│   │                               disk on failure; survives process restarts. Exposes:
│   │                                 .enqueue(alert)          — alert_mgr.subscribe(this)
│   │                                 .enqueue_flows(list)     — called by snapshot thread
│   │                                 .enqueue_discovery(list) — called by discovery thread
│   │
│   ├── test_alert_manager.py       6 tests
│   ├── test_ip_lookup.py           7 tests — service-name matching, private-IP short-
│   │                               circuit, cache, graceful failure.
│   └── test_forwarder.py           10 tests — all 3 channels, independence on failure,
│                                   persistence across restarts, batch size.
│
│   # ── SENSOR LOCAL DASHBOARD ────────────────────────────────────────────
├── dashboard/
│   ├── templates/
│   │   └── index.html              Cyber-green terminal UI. Boot-sequence typewriter
│   │                               on load. Live SocketIO feed — data comes from the
│   │                               running sensor process, not the DB.
│   └── static/
│       ├── css/style.css           Tokens: --bg #060a06, --signal #39ff14 (phosphor
│       │                           green), --critical #ff3b3b, --medium #ffb000.
│       │                           JetBrains Mono throughout. Grid-background texture.
│       │                           Alert detail overlay + IP intelligence card.
│       └── js/dashboard.js         Boot typewriter, SocketIO wiring, alert feed +
│                                   detail card, service-name annotation (async, cached),
│                                   severity/type stat bars, open/close on click/Esc.
│
│   # ── SOC SERVER (central aggregation) ────────────────────────────────
└── soc_server/
    │
    │   # ── SOC CORE ────────────────────────────────────────────────────
    ├── app.py                      Central Flask app. Two independent auth systems:
    │                               INGESTION API (sensor API-key auth, Bearer token):
    │                                 POST /api/heartbeat
    │                                 POST /api/ingest/alerts
    │                                 POST /api/ingest/flow-snapshot
    │                                 POST /api/ingest/discovery
    │                               DASHBOARD API (session cookie, RBAC-scoped):
    │                                 POST /api/login  /api/logout  GET /api/me
    │                                 GET  /api/networks             — soc_admin: all networks + status
    │                                 GET  /api/sensors              — soc_admin: all sensors + heartbeat
    │                                 GET  /api/assets               — registered + discovered diff, scoped
    │                                 POST /api/assets               — register a device (RBAC-scoped)
    │                                 DELETE /api/assets/<mac>       — remove a registered device
    │                                 GET  /api/stats                — severity/type counts, scoped
    │                                 GET  /api/behavioral           — per-network baseline check
    │                                 GET  /api/ml-anomalies         — Isolation Forest results
    │                                 GET  /api/incidents            — correlated alert groups
    │                               RBAC enforcement: network_id pulled from the
    │                               authenticated session, never from the request
    │                               parameter, for senior_user.
    │
    ├── db.py                       SQLite schema + queries. Tables:
    │                                 networks, sensors, users,
    │                                 alerts, flow_snapshots,
    │                                 discovered_hosts, registered_assets
    │                               registered_assets is the central, persistent
    │                               approved-device list — same concept as the
    │                               sensor's local assets.json but queryable via
    │                               GET /api/assets with the discovery diff baked in.
    │
    ├── auth.py                     Two separate hashing schemes (intentional):
    │                                 hash_api_key()  — SHA-256 (sensor tokens are
    │                                                   high-entropy; fast hash is right)
    │                                 hash_password() — werkzeug scrypt/pbkdf2 (human
    │                                                   passwords are low-entropy; slow
    │                                                   hash is required)
    │                               extract_bearer_token() for ingestion API auth.
    │
    ├── behavioral.py               Per-network hourly alert-rate baseline (Step 7,
    │                               slice 1). Z-score check of current hour vs rolling
    │                               7-day history. Three safety properties:
    │                                 1. Current hour excluded from own baseline
    │                                 2. Min 3 sample hours before flagging
    │                                 3. Stdev floor = 1.0 (no hypersensitivity)
    │                               Fully explainable output (mean, stdev, z_score,
    │                               human-readable reasons).
    │
    ├── ml_anomaly.py               Isolation Forest over 17 flow-level features (Step 7,
    │                               slice 2). Operates on flow_snapshots ingested from
    │                               sensors. Features: duration, packets, bytes, fwd/rev
    │                               split, pps, bps, avg_packet_size, TCP flag counts,
    │                               retransmit counts. Explainability: top deviating
    │                               features by z-score (lightweight, no SHAP dependency).
    │                               Requires MIN_FLOWS_FOR_MODEL (default 20) before
    │                               training — degrades gracefully with a clear message.
    │
    ├── correlation.py              Alert grouping into incidents (Section 13 of spec).
    │                               Groups alerts from the same (network_id, src_ip)
    │                               within a 5-minute sliding window. Composite risk score
    │                               (0-100): severity mix + multi-signal corroboration
    │                               (different alert types from different detectors
    │                               agreeing scores higher than repeats of one type).
    │                               Output: incidents sorted by risk_score descending.
    │
    │   # ── SOC CLI TOOLS ────────────────────────────────────────────────
    ├── provision_sensor.py         Onboards a new sensor. Creates network if needed,
    │                               generates API key, stores only its hash, prints
    │                               the plaintext key ONCE. Usage:
    │                                 python3 provision_sensor.py \
    │                                   --db soc.db --network hr-net \
    │                                   --hostname hr-sensor-01
    │
    ├── provision_user.py           Creates a dashboard login. Prompts for password
    │                               interactively (never a CLI arg). Enforces:
    │                                 senior_user requires --network
    │                                 soc_admin must NOT have --network
    │                               Usage:
    │                                 python3 provision_user.py \
    │                                   --db soc.db --username alice \
    │                                   --role senior_user --network hr-net
    │
    │   # ── SOC TESTS ────────────────────────────────────────────────────
    ├── test_db.py                  11 tests — network/sensor/user CRUD, alert +
    │                               flow + discovery ingestion, upsert semantics.
    ├── test_auth.py                8 tests — API key generation, hashing, bearer
    │                               extraction, password verify, scheme separation.
    ├── test_app.py                 20 tests — login, wrong-password rejection,
    │                               RBAC scoping (including parameter-tampering
    │                               regression), session management, all 5 read
    │                               endpoints scoped correctly, ingestion independence.
    ├── test_behavioral.py          7 tests — baseline computation, current-hour
    │                               exclusion, spike detection, normal-traffic silence,
    │                               insufficient-history guard, stdev floor.
    ├── test_ml_anomaly.py          5 tests — insufficient-data guard, planted outlier
    │                               detection, explainable reasons, lookback window.
    └── test_correlation.py         9 tests — grouping, time-window split, source
    │                               separation, multi-signal scoring, severity dominance,
    │                               risk cap, sort order, summary text, empty input.
    │
    │   # ── SOC DASHBOARD ────────────────────────────────────────────────
    ├── templates/
    │   └── index.html              SOC dashboard shell. Login screen → RBAC-aware
    │                               3-panel layout: alert feed | incidents | sidebar
    │                               (severity bars, alert types, behavioral, ML
    │                               anomalies, network list). Network switcher visible
    │                               only to soc_admin. Data-driven via REST polling
    │                               (no SocketIO — reads from DB, not a live stream).
    ├── static/
    │   ├── css/style.css           Same cyber-green tokens as sensor dashboard, plus
    │   │                           login card, network switcher, logout button.
    │   └── js/dashboard.js         Login/logout flow, session restore on page load,
    │                               polling refresh (5s), RBAC-aware network switcher,
    │                               renders: alerts, incidents, severity bars, type list,
    │                               behavioral panel, ML anomalies panel, networks list.
    │
    └── requirements.txt            SOC server dependencies (separate from sensor):
                                      flask, scikit-learn
                                    (werkzeug, sqlite3, hashlib, secrets are stdlib
                                    or Flask transitive — no explicit pin needed)
```

---

## Runtime files created automatically (do not commit)

```
antihijack-scanner/
├── logs/
│   ├── alerts.log                  JSON-lines — every alert the sensor has seen
│   ├── assets.json                 Registered device list for this sensor's subnet
│   └── forwarder_buffer.json       Alerts/flows/discovery queued but not yet sent
│
└── soc_server/
    └── soc.db                      Central SQLite database (all networks combined)
```

---

## How to run

### Sensor (one per department network)
```bash
pip install -r requirements.txt         # first time only

# smoke test with no NIC/root needed:
python3 main.py --demo

# live capture + forwarding to a SOC server:
sudo python3 main.py \
  --iface "Wi-Fi" \
  --network-id hr-net \
  --subnet 192.168.1.0/24 \
  --soc-url http://soc-host:6000 \
  --soc-api-key <key from provision_sensor.py>
```

### SOC server (one central instance)
```bash
cd soc_server
pip install -r requirements.txt         # first time only

# onboard a sensor:
python3 provision_sensor.py --db soc.db --network hr-net --hostname hr-01

# create dashboard users:
python3 provision_user.py --db soc.db --username alice --role senior_user --network hr-net
python3 provision_user.py --db soc.db --username ceo   --role soc_admin

# start the server:
python3 app.py --db soc.db --host 0.0.0.0 --port 6000
```

---

## Test suite (133 tests total, all passing)

```bash
# from antihijack-scanner/

# sensor-side (no root needed)
python3 capture/test_session_table.py       # 14
python3 capture/test_discovery.py           # 7
cd detectors && python3 test_scan_detector.py    # 8
cd detectors && python3 test_hijack_detector.py  # 12
cd reporting && python3 test_alert_manager.py    # 6
cd reporting && python3 test_ip_lookup.py        # 7
cd reporting && python3 test_forwarder.py        # 10

# SOC server-side
cd soc_server && python3 test_db.py          # 11
cd soc_server && python3 test_auth.py        # 8
cd soc_server && python3 test_app.py         # 20
cd soc_server && python3 test_behavioral.py  # 7
cd soc_server && python3 test_ml_anomaly.py  # 5
cd soc_server && python3 test_correlation.py # 9
```
