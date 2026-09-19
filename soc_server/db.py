"""
db.py
-----
Central SOC server storage. SQLite — no separate DB server needed for a
research deployment with a handful of sensors; swap the connection helper
for Postgres later if this ever needs to scale beyond one machine (the
schema below is plain SQL, not ORM-coupled, so that swap is mechanical).

Schema matches the data model in sentinel-enterprise-system-design.md
Section 4, minus `users` (that's Step 6 — RBAC dashboard, not built yet).
`registered_assets` also stays out for now: asset registration currently
lives on the sensor itself (main.py's /api/assets) and centralizing it is
part of the RBAC dashboard work, not the ingestion pipeline.
"""

import sqlite3
import threading
import time


SCHEMA = """
CREATE TABLE IF NOT EXISTS networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sensors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id INTEGER NOT NULL REFERENCES networks(id),
    hostname TEXT,
    api_key_hash TEXT UNIQUE NOT NULL,
    created_at REAL NOT NULL,
    last_heartbeat_at REAL
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id INTEGER NOT NULL REFERENCES networks(id),
    sensor_id INTEGER NOT NULL REFERENCES sensors(id),
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    message TEXT NOT NULL,
    details TEXT,           -- JSON blob
    event_timestamp REAL NOT NULL,   -- when the sensor generated it
    received_at REAL NOT NULL        -- when the SOC server ingested it
);
CREATE INDEX IF NOT EXISTS idx_alerts_network ON alerts(network_id, event_timestamp);

CREATE TABLE IF NOT EXISTS flow_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id INTEGER NOT NULL REFERENCES networks(id),
    sensor_id INTEGER NOT NULL REFERENCES sensors(id),
    flow_key TEXT NOT NULL,
    stats TEXT NOT NULL,     -- JSON blob (Session.flow_stats() output)
    event_timestamp REAL NOT NULL,
    received_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flows_network ON flow_snapshots(network_id, event_timestamp);

CREATE TABLE IF NOT EXISTS discovered_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id INTEGER NOT NULL REFERENCES networks(id),
    sensor_id INTEGER NOT NULL REFERENCES sensors(id),
    ip TEXT NOT NULL,
    mac TEXT NOT NULL,
    vendor TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    UNIQUE(network_id, mac)
);

CREATE TABLE IF NOT EXISTS registered_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id INTEGER NOT NULL REFERENCES networks(id),
    ip TEXT NOT NULL,
    mac TEXT NOT NULL,
    label TEXT,
    added_by INTEGER REFERENCES users(id),
    added_at REAL NOT NULL,
    UNIQUE(network_id, mac)
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,                          -- 'senior_user' | 'soc_admin'
    network_id INTEGER REFERENCES networks(id),  -- NULL for soc_admin (sees everything)
    created_at REAL NOT NULL
);
"""

_lock = threading.Lock()


def connect(db_path: str) -> sqlite3.Connection:
    """One connection per call — SQLite handles concurrent access fine at
    this scale; a real multi-process deployment would want a connection
    pool, not needed yet for a handful of sensors."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: str):
    conn = connect(db_path)
    with _lock:
        conn.executescript(SCHEMA)
        conn.commit()
    conn.close()


def get_or_create_network(conn: sqlite3.Connection, name: str) -> int:
    with _lock:
        row = conn.execute("SELECT id FROM networks WHERE name = ?", (name,)).fetchone()
        if row:
            return row["id"]
        cur = conn.execute(
            "INSERT INTO networks (name, created_at) VALUES (?, ?)",
            (name, time.time()),
        )
        conn.commit()
        return cur.lastrowid


def create_sensor(conn: sqlite3.Connection, network_id: int, api_key_hash: str, hostname: str = "") -> int:
    with _lock:
        cur = conn.execute(
            "INSERT INTO sensors (network_id, hostname, api_key_hash, created_at) VALUES (?, ?, ?, ?)",
            (network_id, hostname, api_key_hash, time.time()),
        )
        conn.commit()
        return cur.lastrowid


def get_sensor_by_key_hash(conn: sqlite3.Connection, api_key_hash: str):
    return conn.execute(
        "SELECT * FROM sensors WHERE api_key_hash = ?", (api_key_hash,)
    ).fetchone()


def touch_sensor_heartbeat(conn: sqlite3.Connection, sensor_id: int):
    with _lock:
        conn.execute(
            "UPDATE sensors SET last_heartbeat_at = ? WHERE id = ?",
            (time.time(), sensor_id),
        )
        conn.commit()


def insert_alerts(conn: sqlite3.Connection, network_id: int, sensor_id: int, alerts: list[dict]):
    with _lock:
        conn.executemany(
            """INSERT INTO alerts
               (network_id, sensor_id, alert_type, severity, src_ip, message, details,
                event_timestamp, received_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (network_id, sensor_id, a["alert_type"], a["severity"], a["src_ip"], a["message"],
                 _json_or_none(a.get("details")), a["timestamp"], time.time())
                for a in alerts
            ],
        )
        conn.commit()


def insert_flow_snapshots(conn: sqlite3.Connection, network_id: int, sensor_id: int, flows: list[dict]):
    with _lock:
        conn.executemany(
            """INSERT INTO flow_snapshots
               (network_id, sensor_id, flow_key, stats, event_timestamp, received_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [
                (network_id, sensor_id, str(f.get("flow_key")), _json_or_none(f), time.time(), time.time())
                for f in flows
            ],
        )
        conn.commit()


def upsert_discovered_hosts(conn: sqlite3.Connection, network_id: int, sensor_id: int, hosts: list[dict]):
    """Insert new, or bump last_seen on an existing (network_id, mac) row —
    matches the design doc's first_seen/last_seen semantics for a
    periodically-refreshed discovery scan."""
    now = time.time()
    with _lock:
        for h in hosts:
            existing = conn.execute(
                "SELECT id FROM discovered_hosts WHERE network_id = ? AND mac = ?",
                (network_id, h["mac"]),
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE discovered_hosts SET ip = ?, vendor = ?, last_seen = ? WHERE id = ?",
                    (h["ip"], h.get("vendor"), now, existing["id"]),
                )
            else:
                conn.execute(
                    """INSERT INTO discovered_hosts
                       (network_id, sensor_id, ip, mac, vendor, first_seen, last_seen)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (network_id, sensor_id, h["ip"], h["mac"], h.get("vendor"), now, now),
                )
        conn.commit()


def _json_or_none(value):
    import json
    return json.dumps(value) if value is not None else None


# ---------------- users (Step 6: RBAC) ----------------

def create_user(conn: sqlite3.Connection, username: str, password_hash: str, role: str,
                 network_id: int | None) -> int:
    """network_id must be None for role='soc_admin' (sees everything) and
    a real network id for role='senior_user' (scoped to just that
    network) — enforced by the caller (provision_user.py), not here."""
    with _lock:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role, network_id, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, password_hash, role, network_id, time.time()),
        )
        conn.commit()
        return cur.lastrowid


def get_user_by_username(conn: sqlite3.Connection, username: str):
    return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: int):
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


# ---------------- registered assets (central registry) ----------------

def get_registered_assets(conn: sqlite3.Connection, network_id: int) -> list:
    return conn.execute(
        "SELECT * FROM registered_assets WHERE network_id = ? ORDER BY added_at DESC",
        (network_id,)
    ).fetchall()


def register_asset(conn: sqlite3.Connection, network_id: int, ip: str, mac: str,
                    label: str, added_by: int) -> int:
    mac = mac.lower()
    with _lock:
        existing = conn.execute(
            "SELECT id FROM registered_assets WHERE network_id = ? AND mac = ?",
            (network_id, mac)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE registered_assets SET ip = ?, label = ?, added_by = ?, added_at = ? WHERE id = ?",
                (ip, label, added_by, time.time(), existing["id"])
            )
            conn.commit()
            return existing["id"]
        cur = conn.execute(
            "INSERT INTO registered_assets (network_id, ip, mac, label, added_by, added_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (network_id, ip, mac, label, added_by, time.time())
        )
        conn.commit()
        return cur.lastrowid


def remove_registered_asset(conn: sqlite3.Connection, network_id: int, mac: str) -> bool:
    mac = mac.lower()
    with _lock:
        cur = conn.execute(
            "DELETE FROM registered_assets WHERE network_id = ? AND mac = ?",
            (network_id, mac)
        )
        conn.commit()
        return cur.rowcount > 0


def get_assets_with_discovery_diff(conn: sqlite3.Connection, network_id: int) -> dict:
    """Returns registered assets and discovered hosts together, with a
    flag marking which discovered hosts are NOT in the registered list —
    this is the GET /api/assets payload the dashboard shows."""
    registered = {r["mac"]: dict(r) for r in get_registered_assets(conn, network_id)}
    discovered_rows = conn.execute(
        "SELECT * FROM discovered_hosts WHERE network_id = ? ORDER BY last_seen DESC",
        (network_id,)
    ).fetchall()
    discovered = []
    for row in discovered_rows:
        d = dict(row)
        d["is_registered"] = d["mac"] in registered
        discovered.append(d)
    return {"registered": list(registered.values()), "discovered": discovered}


# ---------------- sensors (list for soc_admin) ----------------

def get_all_sensors(conn: sqlite3.Connection) -> list:
    return conn.execute(
        "SELECT sensors.*, networks.name as network_name FROM sensors "
        "JOIN networks ON sensors.network_id = networks.id ORDER BY sensors.id"
    ).fetchall()
