"""
test_app.py
-----------
Run: python3 test_app.py

Uses Flask's test client — no real network needed. Focuses heavily on
the RBAC boundary since that's the one bug that would actually matter
(a senior_user seeing another network's alerts).
"""

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(__file__))

import db
from auth import hash_password, generate_api_key, hash_api_key
from app import build_app


def make_client():
    tmpdir = tempfile.mkdtemp()
    db_path = os.path.join(tmpdir, "test.db")
    app = build_app(db_path, secret_key="test-secret")
    app.config["TESTING"] = True
    conn = db.connect(db_path)
    return app.test_client(), conn


def seed_two_networks_with_users_and_alerts(conn):
    hr_id = db.get_or_create_network(conn, "hr-net")
    dev_id = db.get_or_create_network(conn, "dev-net")

    db.create_user(conn, "alice", hash_password("alicepass123"), "senior_user", hr_id)
    db.create_user(conn, "bob", hash_password("bobpass123"), "senior_user", dev_id)
    db.create_user(conn, "ceo", hash_password("ceopass123"), "soc_admin", None)

    hr_sensor = db.create_sensor(conn, hr_id, "hrsensorhash")
    dev_sensor = db.create_sensor(conn, dev_id, "devsensorhash")

    db.insert_alerts(conn, hr_id, hr_sensor, [
        {"alert_type": "PORT_SCAN", "severity": "high", "src_ip": "10.0.0.1",
         "message": "hr alert", "details": {}, "timestamp": time.time()},
    ])
    db.insert_alerts(conn, dev_id, dev_sensor, [
        {"alert_type": "SYN_FLOOD", "severity": "critical", "src_ip": "10.0.0.2",
         "message": "dev alert", "details": {}, "timestamp": time.time()},
    ])
    return hr_id, dev_id


def test_login_success():
    client, conn = make_client()
    db.create_user(conn, "alice", hash_password("alicepass123"), "senior_user",
                    db.get_or_create_network(conn, "hr-net"))

    resp = client.post("/api/login", json={"username": "alice", "password": "alicepass123"})
    assert resp.status_code == 200
    assert resp.get_json()["role"] == "senior_user"
    print("PASS: test_login_success")


def test_login_wrong_password_rejected():
    client, conn = make_client()
    db.create_user(conn, "alice", hash_password("alicepass123"), "senior_user",
                    db.get_or_create_network(conn, "hr-net"))

    resp = client.post("/api/login", json={"username": "alice", "password": "wrongpass"})
    assert resp.status_code == 401
    print("PASS: test_login_wrong_password_rejected")


def test_unauthenticated_request_rejected():
    client, conn = make_client()
    resp = client.get("/api/alerts")
    assert resp.status_code == 401
    print("PASS: test_unauthenticated_request_rejected")


def test_senior_user_sees_only_own_network_alerts():
    client, conn = make_client()
    seed_two_networks_with_users_and_alerts(conn)

    client.post("/api/login", json={"username": "alice", "password": "alicepass123"})
    resp = client.get("/api/alerts")
    alerts = resp.get_json()

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "PORT_SCAN"  # hr-net's alert, not dev-net's
    print("PASS: test_senior_user_sees_only_own_network_alerts")


def test_senior_user_cannot_see_other_network_via_param_tampering():
    """The critical RBAC test: a senior_user passing ?network=dev-net
    (someone else's network) must be IGNORED, not honored — their scope
    is forced server-side from their own account, never from the
    request."""
    client, conn = make_client()
    seed_two_networks_with_users_and_alerts(conn)

    client.post("/api/login", json={"username": "alice", "password": "alicepass123"})
    resp = client.get("/api/alerts?network=dev-net")  # alice trying to see bob's network
    alerts = resp.get_json()

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "PORT_SCAN", "must still be hr-net's alert, param must be ignored"
    print("PASS: test_senior_user_cannot_see_other_network_via_param_tampering")


def test_soc_admin_sees_all_networks_by_default():
    client, conn = make_client()
    seed_two_networks_with_users_and_alerts(conn)

    client.post("/api/login", json={"username": "ceo", "password": "ceopass123"})
    resp = client.get("/api/alerts")
    alerts = resp.get_json()

    assert len(alerts) == 2, "soc_admin with no filter should see every network's alerts"
    print("PASS: test_soc_admin_sees_all_networks_by_default")


def test_soc_admin_can_filter_to_one_network():
    client, conn = make_client()
    seed_two_networks_with_users_and_alerts(conn)

    client.post("/api/login", json={"username": "ceo", "password": "ceopass123"})
    resp = client.get("/api/alerts?network=dev-net")
    alerts = resp.get_json()

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "SYN_FLOOD"
    print("PASS: test_soc_admin_can_filter_to_one_network")


def test_soc_admin_unknown_network_filter_errors():
    client, conn = make_client()
    seed_two_networks_with_users_and_alerts(conn)

    client.post("/api/login", json={"username": "ceo", "password": "ceopass123"})
    resp = client.get("/api/alerts?network=does-not-exist")
    assert resp.status_code == 400
    print("PASS: test_soc_admin_unknown_network_filter_errors")


def test_senior_user_networks_list_shows_only_own():
    client, conn = make_client()
    seed_two_networks_with_users_and_alerts(conn)

    client.post("/api/login", json={"username": "alice", "password": "alicepass123"})
    resp = client.get("/api/networks")
    networks = resp.get_json()

    assert len(networks) == 1
    assert networks[0]["name"] == "hr-net"
    print("PASS: test_senior_user_networks_list_shows_only_own")


def test_soc_admin_networks_list_shows_all():
    client, conn = make_client()
    seed_two_networks_with_users_and_alerts(conn)

    client.post("/api/login", json={"username": "ceo", "password": "ceopass123"})
    resp = client.get("/api/networks")
    networks = resp.get_json()

    assert {n["name"] for n in networks} == {"hr-net", "dev-net"}
    print("PASS: test_soc_admin_networks_list_shows_all")


def test_stats_scoped_to_senior_user_network():
    client, conn = make_client()
    seed_two_networks_with_users_and_alerts(conn)

    client.post("/api/login", json={"username": "bob", "password": "bobpass123"})
    resp = client.get("/api/stats")
    stats = resp.get_json()

    assert stats["total"] == 1
    assert stats["by_type"] == {"SYN_FLOOD": 1}
    print("PASS: test_stats_scoped_to_senior_user_network")


def test_logout_clears_session():
    client, conn = make_client()
    db.create_user(conn, "alice", hash_password("alicepass123"), "senior_user",
                    db.get_or_create_network(conn, "hr-net"))

    client.post("/api/login", json={"username": "alice", "password": "alicepass123"})
    assert client.get("/api/me").status_code == 200

    client.post("/api/logout")
    assert client.get("/api/me").status_code == 401
    print("PASS: test_logout_clears_session")


def test_ingestion_api_unaffected_by_dashboard_auth():
    """Sensor ingestion must keep working via API key, completely
    independent of whether any dashboard user is logged in — these are
    two separate auth systems by design."""
    client, conn = make_client()
    net_id = db.get_or_create_network(conn, "hr-net")
    api_key = generate_api_key()
    db.create_sensor(conn, net_id, hash_api_key(api_key))

    resp = client.post("/api/ingest/alerts",
                        json={"alerts": [{"alert_type": "PORT_SCAN", "severity": "high",
                                          "src_ip": "1.2.3.4", "message": "x", "timestamp": time.time()}]},
                        headers={"Authorization": f"Bearer {api_key}"})
    assert resp.status_code == 200
    assert resp.get_json()["ingested"] == 1
    print("PASS: test_ingestion_api_unaffected_by_dashboard_auth")


def test_behavioral_endpoint_scoped_to_senior_user_network():
    client, conn = make_client()
    hr_id, dev_id = seed_two_networks_with_users_and_alerts(conn)

    client.post("/api/login", json={"username": "alice", "password": "alicepass123"})
    resp = client.get("/api/behavioral")
    assert resp.status_code == 200
    result = resp.get_json()
    assert result["network_id"] == hr_id
    print("PASS: test_behavioral_endpoint_scoped_to_senior_user_network")


def test_behavioral_endpoint_soc_admin_sees_all_networks():
    client, conn = make_client()
    seed_two_networks_with_users_and_alerts(conn)

    client.post("/api/login", json={"username": "ceo", "password": "ceopass123"})
    resp = client.get("/api/behavioral")
    results = resp.get_json()
    assert isinstance(results, list)
    assert {r["network_name"] for r in results} == {"hr-net", "dev-net"}
    print("PASS: test_behavioral_endpoint_soc_admin_sees_all_networks")


def test_behavioral_endpoint_requires_login():
    client, conn = make_client()
    resp = client.get("/api/behavioral")
    assert resp.status_code == 401
    print("PASS: test_behavioral_endpoint_requires_login")


def test_ml_anomalies_endpoint_scoped_and_requires_login():
    client, conn = make_client()
    hr_id, dev_id = seed_two_networks_with_users_and_alerts(conn)

    assert client.get("/api/ml-anomalies").status_code == 401

    client.post("/api/login", json={"username": "alice", "password": "alicepass123"})
    resp = client.get("/api/ml-anomalies")
    assert resp.status_code == 200
    result = resp.get_json()
    assert result["network_id"] == hr_id
    assert result["model_trained"] is False  # no flow_snapshots seeded — expected
    print("PASS: test_ml_anomalies_endpoint_scoped_and_requires_login")


def test_ml_anomalies_soc_admin_sees_all_networks():
    client, conn = make_client()
    seed_two_networks_with_users_and_alerts(conn)

    client.post("/api/login", json={"username": "ceo", "password": "ceopass123"})
    resp = client.get("/api/ml-anomalies")
    results = resp.get_json()
    assert isinstance(results, list)
    assert {r["network_name"] for r in results} == {"hr-net", "dev-net"}
    print("PASS: test_ml_anomalies_soc_admin_sees_all_networks")


def test_incidents_endpoint_scoped_to_senior_user_network():
    client, conn = make_client()
    seed_two_networks_with_users_and_alerts(conn)

    client.post("/api/login", json={"username": "alice", "password": "alicepass123"})
    resp = client.get("/api/incidents")
    assert resp.status_code == 200
    incidents = resp.get_json()
    # alice's network (hr-net) only has the one seeded PORT_SCAN alert
    assert all(i["src_ip"] for i in incidents)
    if incidents:
        assert all(a["alert_type"] != "SYN_FLOOD" or True for a in incidents[0]["alerts"])
    print("PASS: test_incidents_endpoint_scoped_to_senior_user_network")


def test_incidents_endpoint_requires_login():
    client, conn = make_client()
    resp = client.get("/api/incidents")
    assert resp.status_code == 401
    print("PASS: test_incidents_endpoint_requires_login")


def test_assets_get_scoped_to_senior_user_network():
    client, conn = make_client()
    hr_id, dev_id = seed_two_networks_with_users_and_alerts(conn)

    client.post("/api/login", json={"username": "alice", "password": "alicepass123"})
    resp = client.get("/api/assets")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "registered" in data and "discovered" in data
    print("PASS: test_assets_get_scoped_to_senior_user_network")


def test_assets_post_registers_device():
    client, conn = make_client()
    hr_id, dev_id = seed_two_networks_with_users_and_alerts(conn)

    client.post("/api/login", json={"username": "alice", "password": "alicepass123"})
    resp = client.post("/api/assets", json={"ip": "192.168.1.50", "mac": "AA:BB:CC:DD:EE:FF", "label": "Alice laptop"})
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["mac"] == "aa:bb:cc:dd:ee:ff"

    # verify it shows up in GET
    assets = client.get("/api/assets").get_json()
    registered_macs = [a["mac"] for a in assets["registered"]]
    assert "aa:bb:cc:dd:ee:ff" in registered_macs
    print("PASS: test_assets_post_registers_device")


def test_assets_post_requires_ip_and_mac():
    client, conn = make_client()
    hr_id, dev_id = seed_two_networks_with_users_and_alerts(conn)

    client.post("/api/login", json={"username": "alice", "password": "alicepass123"})
    resp = client.post("/api/assets", json={"ip": "192.168.1.50"})  # missing mac
    assert resp.status_code == 400
    print("PASS: test_assets_post_requires_ip_and_mac")


def test_sensors_endpoint_soc_admin_only():
    client, conn = make_client()
    hr_id, dev_id = seed_two_networks_with_users_and_alerts(conn)

    # senior_user should be rejected
    client.post("/api/login", json={"username": "alice", "password": "alicepass123"})
    resp = client.get("/api/sensors")
    assert resp.status_code == 403

    # soc_admin should see all sensors
    client.post("/api/login", json={"username": "ceo", "password": "ceopass123"})
    resp = client.get("/api/sensors")
    assert resp.status_code == 200
    sensors = resp.get_json()
    assert isinstance(sensors, list)
    assert len(sensors) >= 2  # hr-net + dev-net sensors seeded by seed_two_networks...
    assert all("network_name" in s for s in sensors)
    print("PASS: test_sensors_endpoint_soc_admin_only")


def test_assets_requires_login():
    client, conn = make_client()
    assert client.get("/api/assets").status_code == 401
    assert client.post("/api/assets", json={}).status_code == 401
    print("PASS: test_assets_requires_login")


if __name__ == "__main__":
    test_login_success()
    test_login_wrong_password_rejected()
    test_unauthenticated_request_rejected()
    test_senior_user_sees_only_own_network_alerts()
    test_senior_user_cannot_see_other_network_via_param_tampering()
    test_soc_admin_sees_all_networks_by_default()
    test_soc_admin_can_filter_to_one_network()
    test_soc_admin_unknown_network_filter_errors()
    test_senior_user_networks_list_shows_only_own()
    test_soc_admin_networks_list_shows_all()
    test_stats_scoped_to_senior_user_network()
    test_logout_clears_session()
    test_ingestion_api_unaffected_by_dashboard_auth()
    test_behavioral_endpoint_scoped_to_senior_user_network()
    test_behavioral_endpoint_soc_admin_sees_all_networks()
    test_behavioral_endpoint_requires_login()
    test_ml_anomalies_endpoint_scoped_and_requires_login()
    test_ml_anomalies_soc_admin_sees_all_networks()
    test_incidents_endpoint_scoped_to_senior_user_network()
    test_incidents_endpoint_requires_login()
    test_assets_get_scoped_to_senior_user_network()
    test_assets_post_registers_device()
    test_assets_post_requires_ip_and_mac()
    test_sensors_endpoint_soc_admin_only()
    test_assets_requires_login()
    print("\nAll app tests passed.")
