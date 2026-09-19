"""
test_db.py
----------
Run: python3 test_db.py
"""

import os
import tempfile
import time

import db


def make_test_db():
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "test.db")
    db.init_db(path)
    return db.connect(path)


def test_get_or_create_network_is_idempotent():
    conn = make_test_db()
    id1 = db.get_or_create_network(conn, "hr-net")
    id2 = db.get_or_create_network(conn, "hr-net")
    assert id1 == id2
    print("PASS: test_get_or_create_network_is_idempotent")


def test_create_and_lookup_sensor():
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "dev-net")
    sensor_id = db.create_sensor(conn, net_id, "somehash123", hostname="dev-sensor-01")

    row = db.get_sensor_by_key_hash(conn, "somehash123")
    assert row is not None
    assert row["id"] == sensor_id
    assert row["network_id"] == net_id
    assert row["hostname"] == "dev-sensor-01"
    print("PASS: test_create_and_lookup_sensor")


def test_lookup_unknown_key_hash_returns_none():
    conn = make_test_db()
    assert db.get_sensor_by_key_hash(conn, "nonexistent") is None
    print("PASS: test_lookup_unknown_key_hash_returns_none")


def test_insert_and_query_alerts():
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "hr-net")
    sensor_id = db.create_sensor(conn, net_id, "hashA")

    alerts = [
        {"alert_type": "PORT_SCAN", "severity": "high", "src_ip": "10.0.0.66",
         "message": "scan detected", "details": {"ports": [1, 2, 3]}, "timestamp": time.time()},
        {"alert_type": "SYN_FLOOD", "severity": "critical", "src_ip": "10.0.0.77",
         "message": "flood detected", "details": {}, "timestamp": time.time()},
    ]
    db.insert_alerts(conn, net_id, sensor_id, alerts)

    rows = conn.execute("SELECT * FROM alerts WHERE network_id = ?", (net_id,)).fetchall()
    assert len(rows) == 2
    assert {r["alert_type"] for r in rows} == {"PORT_SCAN", "SYN_FLOOD"}
    print("PASS: test_insert_and_query_alerts")


def test_insert_flow_snapshots():
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "hr-net")
    sensor_id = db.create_sensor(conn, net_id, "hashB")

    flows = [{"flow_key": ["10.0.0.1", 51000, "10.0.0.2", 443, "TCP"], "total_packets": 42}]
    db.insert_flow_snapshots(conn, net_id, sensor_id, flows)

    rows = conn.execute("SELECT * FROM flow_snapshots WHERE network_id = ?", (net_id,)).fetchall()
    assert len(rows) == 1
    print("PASS: test_insert_flow_snapshots")


def test_upsert_discovered_hosts_inserts_new():
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "hr-net")
    sensor_id = db.create_sensor(conn, net_id, "hashC")

    hosts = [{"ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Dell"}]
    db.upsert_discovered_hosts(conn, net_id, sensor_id, hosts)

    rows = conn.execute("SELECT * FROM discovered_hosts WHERE network_id = ?", (net_id,)).fetchall()
    assert len(rows) == 1
    assert rows[0]["ip"] == "192.168.1.50"
    print("PASS: test_upsert_discovered_hosts_inserts_new")


def test_upsert_discovered_hosts_updates_existing_mac():
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "hr-net")
    sensor_id = db.create_sensor(conn, net_id, "hashD")

    db.upsert_discovered_hosts(conn, net_id, sensor_id,
                                [{"ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:ff"}])
    first_seen = conn.execute(
        "SELECT first_seen, last_seen FROM discovered_hosts WHERE mac = ?", ("aa:bb:cc:dd:ee:ff",)
    ).fetchone()

    time.sleep(0.05)
    # same device, DHCP handed it a new IP — should update, not duplicate
    db.upsert_discovered_hosts(conn, net_id, sensor_id,
                                [{"ip": "192.168.1.99", "mac": "aa:bb:cc:dd:ee:ff"}])

    rows = conn.execute("SELECT * FROM discovered_hosts WHERE mac = ?", ("aa:bb:cc:dd:ee:ff",)).fetchall()
    assert len(rows) == 1, "same MAC should update the existing row, not insert a duplicate"
    assert rows[0]["ip"] == "192.168.1.99"
    assert rows[0]["first_seen"] == first_seen["first_seen"], "first_seen must not change on update"
    assert rows[0]["last_seen"] > first_seen["last_seen"]
    print("PASS: test_upsert_discovered_hosts_updates_existing_mac")


def test_touch_sensor_heartbeat():
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "hr-net")
    sensor_id = db.create_sensor(conn, net_id, "hashE")

    before = conn.execute("SELECT last_heartbeat_at FROM sensors WHERE id = ?", (sensor_id,)).fetchone()
    assert before["last_heartbeat_at"] is None

    db.touch_sensor_heartbeat(conn, sensor_id)
    after = conn.execute("SELECT last_heartbeat_at FROM sensors WHERE id = ?", (sensor_id,)).fetchone()
    assert after["last_heartbeat_at"] is not None
    print("PASS: test_touch_sensor_heartbeat")


def test_create_and_lookup_user():
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "hr-net")
    user_id = db.create_user(conn, "alice", "hashedpw", "senior_user", net_id)

    row = db.get_user_by_username(conn, "alice")
    assert row is not None
    assert row["id"] == user_id
    assert row["role"] == "senior_user"
    assert row["network_id"] == net_id
    print("PASS: test_create_and_lookup_user")


def test_soc_admin_user_has_null_network_id():
    conn = make_test_db()
    user_id = db.create_user(conn, "ceo", "hashedpw", "soc_admin", None)

    row = db.get_user_by_id(conn, user_id)
    assert row["role"] == "soc_admin"
    assert row["network_id"] is None
    print("PASS: test_soc_admin_user_has_null_network_id")


def test_lookup_unknown_username_returns_none():
    conn = make_test_db()
    assert db.get_user_by_username(conn, "nobody") is None
    print("PASS: test_lookup_unknown_username_returns_none")


def test_register_and_list_assets():
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "hr-net")
    user_id = db.create_user(conn, "alice", "pw", "senior_user", net_id)

    asset_id = db.register_asset(conn, net_id, "192.168.1.50", "AA:BB:CC:DD:EE:FF", "Laptop", user_id)
    assets = db.get_registered_assets(conn, net_id)
    assert len(assets) == 1
    assert assets[0]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert assets[0]["label"] == "Laptop"
    print("PASS: test_register_and_list_assets")


def test_register_asset_updates_on_duplicate_mac():
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "hr-net")
    user_id = db.create_user(conn, "alice", "pw", "senior_user", net_id)

    db.register_asset(conn, net_id, "192.168.1.50", "aa:bb:cc:dd:ee:ff", "Old label", user_id)
    db.register_asset(conn, net_id, "192.168.1.99", "aa:bb:cc:dd:ee:ff", "New label", user_id)
    assets = db.get_registered_assets(conn, net_id)
    assert len(assets) == 1, "same MAC should update, not duplicate"
    assert assets[0]["ip"] == "192.168.1.99"
    assert assets[0]["label"] == "New label"
    print("PASS: test_register_asset_updates_on_duplicate_mac")


def test_remove_registered_asset():
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "hr-net")
    user_id = db.create_user(conn, "alice", "pw", "senior_user", net_id)

    db.register_asset(conn, net_id, "192.168.1.50", "aa:bb:cc:dd:ee:ff", "", user_id)
    assert db.remove_registered_asset(conn, net_id, "aa:bb:cc:dd:ee:ff") is True
    assert db.get_registered_assets(conn, net_id) == []
    assert db.remove_registered_asset(conn, net_id, "aa:bb:cc:dd:ee:ff") is False
    print("PASS: test_remove_registered_asset")


def test_assets_diff_shows_unregistered_discovered():
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "hr-net")
    sensor_id = db.create_sensor(conn, net_id, "hashX")
    user_id = db.create_user(conn, "alice", "pw", "senior_user", net_id)

    db.upsert_discovered_hosts(conn, net_id, sensor_id, [
        {"ip": "192.168.1.10", "mac": "aa:aa:aa:aa:aa:aa"},
        {"ip": "192.168.1.11", "mac": "bb:bb:bb:bb:bb:bb"},
    ])
    db.register_asset(conn, net_id, "192.168.1.10", "aa:aa:aa:aa:aa:aa", "Known", user_id)

    diff = db.get_assets_with_discovery_diff(conn, net_id)
    discovered = {d["mac"]: d for d in diff["discovered"]}
    assert discovered["aa:aa:aa:aa:aa:aa"]["is_registered"] is True
    assert discovered["bb:bb:bb:bb:bb:bb"]["is_registered"] is False
    print("PASS: test_assets_diff_shows_unregistered_discovered")


if __name__ == "__main__":
    test_get_or_create_network_is_idempotent()
    test_create_and_lookup_sensor()
    test_lookup_unknown_key_hash_returns_none()
    test_insert_and_query_alerts()
    test_insert_flow_snapshots()
    test_upsert_discovered_hosts_inserts_new()
    test_upsert_discovered_hosts_updates_existing_mac()
    test_touch_sensor_heartbeat()
    test_create_and_lookup_user()
    test_soc_admin_user_has_null_network_id()
    test_lookup_unknown_username_returns_none()
    test_register_and_list_assets()
    test_register_asset_updates_on_duplicate_mac()
    test_remove_registered_asset()
    test_assets_diff_shows_unregistered_discovered()
    print("\nAll db tests passed.")
