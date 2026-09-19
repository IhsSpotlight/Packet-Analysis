# SENTINEL Enterprise — System Design

Multi-network, role-based Hybrid IDS platform. Extends the existing single-host
SENTINEL build (session/flow tracking, scan + hijack detectors, cyber-green
dashboard) into the architecture sketched: several department networks, each
with a senior-user view, rolling up into one CEO/SOC dashboard.

---

## 1. Goals

- Monitor several distinct networks (HR, Developer, Security Testers, SMM, ...)
  independently, each with its own local detection.
- Give each department's senior user a dashboard scoped to **only their
  network**.
- Give the CEO/SOC role a dashboard aggregating **all networks**, with
  drill-down into any one of them.
- Let a senior user **discover devices on their subnet** and maintain a
  registry of known/authorized assets, so unregistered devices get flagged.
- Keep everything that already works (flow tracking, scan/hijack detection,
  alert pipeline) as the detection core — this is an extension, not a rewrite.

---

## 2. High-level architecture

```
 HR net        Dev net        Security net     SMM net
   |              |                |               |
[Sensor]       [Sensor]        [Sensor]        [Sensor]
   |              |                |               |
   +------ auth'd HTTPS ingestion (alerts, flows, heartbeats) ------+
                              |
                       +-------------+
                       |  SOC server  |
                       |  (central)   |
                       +-------------+
                       /      |       \
                  Postgres  Auth/RBAC  Dashboard (web)
                  (storage)  (users)   scoped by role
```

**Sensor** = today's SENTINEL (`sniffer.py` → `SessionTable` → `ScanDetector`
+ `HijackDetector` → `AlertManager`) plus a new **Discovery module** and a new
**Forwarder** that ships alerts/flow-stats to the SOC server instead of (or in
addition to) serving its own local dashboard.

**SOC server** is new: ingestion API, auth, a real database, and a dashboard
that queries the DB instead of listening to a live SocketIO feed from one
sensor.

---

## 3. Components

### 3.1 Sensor (one per network)

Runs on a machine with visibility into that department's subnet (e.g. a small
box on the HR switch, or a laptop on that Wi-Fi segment). Unchanged core:

- `sniffer.py` — packet capture
- `session_table.py` — bidirectional flow tracking
- `scan_detector.py`, `hijack_detector.py` — detection
- `alert_manager.py` — local buffering, log

New pieces:

- **`network_id`** — a fixed identifier baked into the sensor's config,
  stamped onto every alert/flow it produces (e.g. `"hr-net"`).
- **Discovery module** — periodic ARP scan (`scapy.arping` or a ping sweep +
  ARP table read) of the sensor's subnet. Produces a live host list: IP, MAC,
  vendor (OUI lookup), first-seen, last-seen. Diffed against a **registered
  asset list** (see 4.3) — anything present but not registered is flagged as
  `UNREGISTERED_DEVICE`.
- **Forwarder** — batches alerts + periodic flow-stat snapshots and POSTs
  them to the SOC server's ingestion API, authenticated with a per-sensor API
  key. Retries/buffers locally (SQLite or just the existing JSON log) if the
  SOC server is unreachable, so a network blip doesn't lose alerts.

### 3.2 SOC server (central, new)

- **Ingestion API** — receives batched alerts/flows/heartbeats from sensors,
  authenticated by sensor API key, writes to the central DB.
- **Auth & RBAC** — user accounts, each tied to a role and (for non-SOC
  roles) a `network_id`. Session-based or JWT.
- **Query API** — dashboard calls this, scoped automatically by the caller's
  role: a senior user's queries are implicitly filtered to their
  `network_id`; SOC/CEO queries span all networks.
- **Dashboard** — same cyber-green visual language as today, but now
  data-driven from the DB/API instead of a live local SocketIO feed. A
  network switcher for the CEO/SOC view; none needed for a scoped senior-user
  view.

### 3.3 Discovery & asset registry

- `discovered_hosts` — what a scan actually found (transient, refreshed each
  scan cycle).
- `registered_assets` — what a senior user has explicitly approved for their
  network (persistent, user-managed via the dashboard: "add device").
- A host present in `discovered_hosts` but absent from `registered_assets`
  for that `network_id` → `UNREGISTERED_DEVICE` alert, same severity/alert
  pipeline as scan/hijack alerts.

---

## 4. Data model

```
networks
  id (pk), name, created_at

users
  id (pk), username, password_hash, role, network_id (nullable — null for SOC/CEO)
  role ∈ { "senior_user", "soc_admin" }

sensors
  id (pk), network_id (fk), api_key_hash, hostname, last_heartbeat_at

alerts
  id (pk), network_id (fk), sensor_id (fk), alert_type, severity, src_ip,
  message, details (json), timestamp

flow_snapshots                      -- periodic, not per-packet
  id (pk), network_id (fk), sensor_id (fk), flow_key, stats (json), timestamp

registered_assets
  id (pk), network_id (fk), ip, mac, label, added_by (fk users), added_at

discovered_hosts
  id (pk), network_id (fk), ip, mac, vendor, first_seen, last_seen
```

`network_id` is the tenancy boundary — it's on every table that a senior
user's view needs to be filtered by. This is the one column that makes RBAC
scoping mechanical rather than ad hoc.

---

## 5. API surface (sketch)

**Sensor → server (ingestion, API-key auth):**
```
POST /api/ingest/alerts        batch of Alert dicts + network_id (from key)
POST /api/ingest/flow-snapshot batch of flow_stats() dicts
POST /api/ingest/discovery     batch of discovered_hosts rows
POST /api/heartbeat            sensor liveness ping
```

**Dashboard → server (user auth, RBAC-scoped):**
```
POST /api/login
GET  /api/alerts               senior_user: auto-filtered to own network_id
                                soc_admin: optional ?network_id= filter, else all
GET  /api/networks             soc_admin only — list of all networks + status
GET  /api/assets               registered + discovered, diffed, for current scope
POST /api/assets               register a discovered host (senior_user, own network only)
GET  /api/stats                severity/type counts, scoped
```

Enforcement rule: every query handler pulls `network_id` from the
authenticated session, not from a client-supplied parameter, for
`senior_user`. `soc_admin` is the only role allowed to pass an explicit
`network_id` filter or omit it entirely.

---

## 6. Roles

| Role | Sees | Can register assets | Can add sensors |
|---|---|---|---|
| `senior_user` | own `network_id` only | own network only | no |
| `soc_admin` (CEO/SOC) | all networks, aggregated + per-network drill-down | any network | yes |

Simple two-role model is enough for the sketch (four senior users + one
SOC/CEO). Can extend to per-department admin vs. read-only viewer later if
needed — not worth building now.

---

## 7. Deployment topology

- Each **sensor** runs where it can see its department's traffic — physically
  on that subnet/VLAN, same capture constraints as the current single-host
  build (needs to be on-path for the traffic it should see; NAT/Wi-Fi
  isolation caveats from before still apply per-sensor).
- **SOC server** runs centrally — a small VM/box reachable by all sensors
  over the internal network (or VPN if departments are geographically
  split). Not internet-facing.
- Sensors reach the SOC server outbound only (POST requests) — no inbound
  connections needed to sensors, simplifying firewall rules.

---

## 8. Security considerations

- Sensor API keys: one per sensor, revocable, never shared across networks.
- All sensor→server and dashboard→server traffic over TLS.
- Password hashing (bcrypt/argon2) for user accounts — never plaintext.
- `network_id` scoping enforced server-side on every query, not trusted from
  client input.
- Discovery module only does passive ARP table reads / lightweight active
  scans of the sensor's **own** subnet — never scans across network
  boundaries (that would itself look like the reconnaissance behavior we're
  trying to detect).

---

## 9. Migration path from current build

1. **Now**: single-host SENTINEL (done) — sniffer, flow table, scan +
   hijack detectors, local dashboard.
2. **Add `network_id`** to `Alert` and `Session.flow_stats()` output — one
   config value per sensor deployment, threaded through.
3. **Build Discovery module** — standalone, testable without the rest
   (ARP scan + registered-asset diff + `UNREGISTERED_DEVICE` alert type).
4. **Stand up SOC server** — DB schema above, ingestion API, minimal auth.
5. **Build Forwarder** on the sensor side — ships alerts to the ingestion
   API. Keep local dashboard working in parallel during transition.
6. **Build RBAC dashboard** on the SOC server, retire the per-sensor
   dashboard once the central one covers the same ground (or keep both —
   local dashboard is still useful for a senior user working directly on
   their sensor box).
7. **Feed into the earlier Hybrid IDS roadmap** (behavioral baselining, ML
   layer, risk scoring) at the SOC server level, since that's where
   cross-network correlation and enough data volume for baselining actually
   live.

This keeps every existing detector, test, and the current dashboard fully
intact — nothing here requires touching `scan_detector.py` or
`hijack_detector.py` internals.
