"""
test_behavioral.py
-------------------
Run: python3 test_behavioral.py
"""

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(__file__))

import db
import behavioral


def make_test_db():
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "test.db")
    db.init_db(path)
    return db.connect(path)


def seed_alerts_at_hour(conn, network_id, sensor_id, hour_bucket: int, count: int):
    """Seeds `count` alerts all timestamped within the given hour bucket."""
    ts_base = hour_bucket * 3600 + 60  # a minute into that hour
    alerts = [
        {"alert_type": "PORT_SCAN", "severity": "high", "src_ip": "10.0.0.1",
         "message": "x", "details": {}, "timestamp": ts_base + i}
        for i in range(count)
    ]
    db.insert_alerts(conn, network_id, sensor_id, alerts)


def test_baseline_reflects_historical_average():
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "hr-net")
    sensor_id = db.create_sensor(conn, net_id, "hash1")

    now = time.time()
    current_hour = int(now // 3600)
    # 5 historical hours with a steady ~3 alerts/hour, current hour empty
    for h in range(1, 6):
        seed_alerts_at_hour(conn, net_id, sensor_id, current_hour - h, 3)

    baseline = behavioral.compute_baseline(conn, net_id, now=now)
    assert baseline["sample_hours"] == 5
    assert abs(baseline["mean"] - 3.0) < 0.01
    print("PASS: test_baseline_reflects_historical_average")


def test_current_hour_excluded_from_baseline():
    """The in-progress current hour must never pollute its own baseline —
    otherwise a spike would partially baseline itself away."""
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "hr-net")
    sensor_id = db.create_sensor(conn, net_id, "hash2")

    now = time.time()
    current_hour = int(now // 3600)
    seed_alerts_at_hour(conn, net_id, sensor_id, current_hour - 1, 3)
    seed_alerts_at_hour(conn, net_id, sensor_id, current_hour, 100)  # today's spike, in progress

    baseline = behavioral.compute_baseline(conn, net_id, now=now)
    assert baseline["sample_hours"] == 1
    assert baseline["mean"] == 3.0, "current hour's spike must not appear in its own baseline"
    print("PASS: test_current_hour_excluded_from_baseline")


def test_spike_detected_as_anomaly():
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "hr-net")
    sensor_id = db.create_sensor(conn, net_id, "hash3")

    now = time.time()
    current_hour = int(now // 3600)
    for h in range(1, 8):
        seed_alerts_at_hour(conn, net_id, sensor_id, current_hour - h, 3)  # steady baseline
    seed_alerts_at_hour(conn, net_id, sensor_id, current_hour, 50)          # today: way above normal

    result = behavioral.check_current_rate(conn, net_id, now=now)
    assert result["is_anomaly"] is True
    assert result["current_hour_count"] == 50
    assert result["z_score"] > behavioral.DEFAULT_Z_THRESHOLD
    assert len(result["reasons"]) == 1
    assert "standard deviations above" in result["reasons"][0]
    print("PASS: test_spike_detected_as_anomaly")


def test_normal_rate_not_flagged():
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "hr-net")
    sensor_id = db.create_sensor(conn, net_id, "hash4")

    now = time.time()
    current_hour = int(now // 3600)
    for h in range(1, 8):
        seed_alerts_at_hour(conn, net_id, sensor_id, current_hour - h, 3)
    seed_alerts_at_hour(conn, net_id, sensor_id, current_hour, 4)  # close to baseline, not a spike

    result = behavioral.check_current_rate(conn, net_id, now=now)
    assert result["is_anomaly"] is False
    assert result["reasons"] == []
    print("PASS: test_normal_rate_not_flagged")


def test_insufficient_history_never_flags_even_on_spike():
    """A brand-new network with almost no history must not be flagged
    just because ITS FIRST real hour happens to have a lot of alerts —
    there's no baseline yet to compare against."""
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "hr-net")
    sensor_id = db.create_sensor(conn, net_id, "hash5")

    now = time.time()
    current_hour = int(now // 3600)
    seed_alerts_at_hour(conn, net_id, sensor_id, current_hour - 1, 2)  # only 1 hour of history
    seed_alerts_at_hour(conn, net_id, sensor_id, current_hour, 500)     # huge spike

    result = behavioral.check_current_rate(conn, net_id, now=now)
    assert result["is_anomaly"] is False, "must not flag without enough history to trust the baseline"
    assert "Not enough history" in result["reasons"][0]
    print("PASS: test_insufficient_history_never_flags_even_on_spike")


def test_stdev_floor_prevents_hypersensitivity():
    """A perfectly quiet, perfectly consistent network (stdev=0) must not
    treat its 4th-ever alert in an hour as an infinite-sigma anomaly."""
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "hr-net")
    sensor_id = db.create_sensor(conn, net_id, "hash6")

    now = time.time()
    current_hour = int(now // 3600)
    for h in range(1, 6):
        seed_alerts_at_hour(conn, net_id, sensor_id, current_hour - h, 2)  # exactly 2 every hour, stdev=0
    seed_alerts_at_hour(conn, net_id, sensor_id, current_hour, 3)  # one more than usual — not a real spike

    result = behavioral.check_current_rate(conn, net_id, now=now)
    assert result["baseline_stdev"] == 0.0
    assert result["is_anomaly"] is False, "the stdev floor should prevent a false anomaly here"
    print("PASS: test_stdev_floor_prevents_hypersensitivity")


def test_empty_network_no_crash():
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "empty-net")

    result = behavioral.check_current_rate(conn, net_id)
    assert result["is_anomaly"] is False
    assert result["current_hour_count"] == 0
    print("PASS: test_empty_network_no_crash")


if __name__ == "__main__":
    test_baseline_reflects_historical_average()
    test_current_hour_excluded_from_baseline()
    test_spike_detected_as_anomaly()
    test_normal_rate_not_flagged()
    test_insufficient_history_never_flags_even_on_spike()
    test_stdev_floor_prevents_hypersensitivity()
    test_empty_network_no_crash()
    print("\nAll behavioral tests passed.")
