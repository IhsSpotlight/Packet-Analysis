"""
test_ml_anomaly.py
-------------------
Run: python3 test_ml_anomaly.py
"""

import os
import random
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(__file__))

import db
import ml_anomaly


def make_test_db():
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "test.db")
    db.init_db(path)
    return db.connect(path)


def normal_flow_stats(seed=0):
    """A plausible, unremarkable web-browsing-ish flow, with mild jitter
    so the feature matrix isn't degenerate (all-identical rows make
    Isolation Forest's behavior undefined/arbitrary)."""
    rnd = random.Random(seed)
    packets = rnd.randint(8, 20)
    return {
        "duration_seconds": rnd.uniform(0.5, 3.0),
        "total_packets": packets,
        "total_bytes": packets * rnd.randint(200, 800),
        "fwd_packets": packets // 2,
        "rev_packets": packets - packets // 2,
        "fwd_bytes": packets * rnd.randint(100, 300),
        "rev_bytes": packets * rnd.randint(100, 500),
        "avg_packet_size": rnd.uniform(200, 600),
        "packets_per_second": rnd.uniform(3, 15),
        "bytes_per_second": rnd.uniform(500, 3000),
        "syn_count": 1, "synack_count": 1, "ack_count": rnd.randint(3, 8),
        "rst_count": 0, "fin_count": rnd.choice([0, 1]),
        "fwd_retransmit_count": 0, "rev_retransmit_count": 0,
    }


def extreme_flow_stats():
    """A flow that looks nothing like normal browsing — huge volume,
    huge rate, no clean handshake completion. Should stick out clearly."""
    return {
        "duration_seconds": 8.0,
        "total_packets": 50000,
        "total_bytes": 40_000_000,
        "fwd_packets": 49000, "rev_packets": 1000,
        "fwd_bytes": 39_000_000, "rev_bytes": 1_000_000,
        "avg_packet_size": 800,
        "packets_per_second": 6250,
        "bytes_per_second": 5_000_000,
        "syn_count": 4000, "synack_count": 2, "ack_count": 10,
        "rst_count": 200, "fin_count": 0,
        "fwd_retransmit_count": 300, "rev_retransmit_count": 0,
    }


def seed_flows(conn, network_id, sensor_id, flows_with_keys):
    payload = [
        {"flow_key": key, **stats}
        for key, stats in flows_with_keys
    ]
    db.insert_flow_snapshots(conn, network_id, sensor_id, payload)


def test_insufficient_flows_no_model_trained():
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "hr-net")
    sensor_id = db.create_sensor(conn, net_id, "hash1")

    seed_flows(conn, net_id, sensor_id, [(f"flow-{i}", normal_flow_stats(i)) for i in range(5)])

    result = ml_anomaly.detect_flow_anomalies(conn, net_id, min_flows=20)
    assert result["model_trained"] is False
    assert result["anomalies"] == []
    assert "Need at least" in result["reason"]
    print("PASS: test_insufficient_flows_no_model_trained")


def test_empty_network_handles_gracefully():
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "empty-net")

    result = ml_anomaly.detect_flow_anomalies(conn, net_id)
    assert result["model_trained"] is False
    assert result["flows_analyzed"] == 0
    print("PASS: test_empty_network_handles_gracefully")


def test_planted_outlier_detected():
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "hr-net")
    sensor_id = db.create_sensor(conn, net_id, "hash2")

    normal_flows = [(f"normal-{i}", normal_flow_stats(i)) for i in range(29)]
    seed_flows(conn, net_id, sensor_id, normal_flows + [("THE-OUTLIER", extreme_flow_stats())])

    result = ml_anomaly.detect_flow_anomalies(conn, net_id, min_flows=20)
    assert result["model_trained"] is True
    assert result["flows_analyzed"] == 30
    assert result["anomalies_found"] >= 1

    flagged_keys = [a["flow_key"] for a in result["anomalies"]]
    assert "THE-OUTLIER" in flagged_keys, "the extreme flow must be caught"
    # it should be the single most anomalous flow, given how extreme it is
    assert result["anomalies"][0]["flow_key"] == "THE-OUTLIER"
    print("PASS: test_planted_outlier_detected")


def test_outlier_reasons_reference_exaggerated_features():
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "hr-net")
    sensor_id = db.create_sensor(conn, net_id, "hash3")

    normal_flows = [(f"normal-{i}", normal_flow_stats(i)) for i in range(29)]
    seed_flows(conn, net_id, sensor_id, normal_flows + [("THE-OUTLIER", extreme_flow_stats())])

    result = ml_anomaly.detect_flow_anomalies(conn, net_id, min_flows=20)
    outlier = next(a for a in result["anomalies"] if a["flow_key"] == "THE-OUTLIER")

    assert len(outlier["reasons"]) > 0
    # at least one reason should reference one of the wildly exaggerated fields
    joined = " ".join(outlier["reasons"])
    assert any(k in joined for k in ("total_bytes", "packets_per_second", "total_packets", "syn_count")), \
        f"expected reasons to reference an exaggerated feature, got: {outlier['reasons']}"
    print("PASS: test_outlier_reasons_reference_exaggerated_features")


def test_lookback_window_excludes_old_flows():
    conn = make_test_db()
    net_id = db.get_or_create_network(conn, "hr-net")
    sensor_id = db.create_sensor(conn, net_id, "hash4")

    now = time.time()
    old_payload = [{"flow_key": f"old-{i}", **normal_flow_stats(i)} for i in range(25)]
    db.insert_flow_snapshots(conn, net_id, sensor_id, old_payload)
    # manually push their event_timestamp far into the past
    conn.execute("UPDATE flow_snapshots SET event_timestamp = ?", (now - 100 * 3600,))
    conn.commit()

    result = ml_anomaly.detect_flow_anomalies(conn, net_id, now=now, lookback_hours=24, min_flows=20)
    assert result["flows_analyzed"] == 0, "flows older than the lookback window must be excluded"
    print("PASS: test_lookback_window_excludes_old_flows")


if __name__ == "__main__":
    test_insufficient_flows_no_model_trained()
    test_empty_network_handles_gracefully()
    test_planted_outlier_detected()
    test_outlier_reasons_reference_exaggerated_features()
    test_lookback_window_excludes_old_flows()
    print("\nAll ml_anomaly tests passed.")
