"""
test_alert_manager.py
-----------------------
Run: python3 test_alert_manager.py
"""

import os
import json
import tempfile

from alert import Alert, Severity
from alert_manager import AlertManager


def make_alert(alert_type="PORT_SCAN", src_ip="10.0.0.9", severity=Severity.HIGH):
    return Alert(alert_type=alert_type, src_ip=src_ip, severity=severity, message="test")


def test_ingest_and_recent_order():
    mgr = AlertManager()
    mgr.ingest(make_alert(alert_type="A"))
    mgr.ingest(make_alert(alert_type="B"))
    mgr.ingest(make_alert(alert_type="C"))

    recent = mgr.recent(10)
    assert [a.alert_type for a in recent] == ["C", "B", "A"], "expected newest-first order"
    print("PASS: test_ingest_and_recent_order")


def test_stats_counts():
    mgr = AlertManager()
    mgr.ingest(make_alert(alert_type="PORT_SCAN", severity=Severity.HIGH))
    mgr.ingest(make_alert(alert_type="PORT_SCAN", severity=Severity.HIGH))
    mgr.ingest(make_alert(alert_type="SYN_FLOOD", severity=Severity.CRITICAL))

    stats = mgr.stats()
    assert stats["total"] == 3
    assert stats["by_type"]["PORT_SCAN"] == 2
    assert stats["by_type"]["SYN_FLOOD"] == 1
    assert stats["by_severity"]["high"] == 2
    assert stats["by_severity"]["critical"] == 1
    print("PASS: test_stats_counts")


def test_subscriber_broadcast():
    mgr = AlertManager()
    received = []
    mgr.subscribe(lambda a: received.append(a))

    mgr.ingest(make_alert(alert_type="MAC_SWAP"))
    assert len(received) == 1
    assert received[0].alert_type == "MAC_SWAP"
    print("PASS: test_subscriber_broadcast")


def test_broken_subscriber_does_not_crash_ingest():
    mgr = AlertManager()
    good_received = []

    def bad_subscriber(a):
        raise RuntimeError("dashboard is on fire")

    mgr.subscribe(bad_subscriber)
    mgr.subscribe(lambda a: good_received.append(a))

    mgr.ingest(make_alert())  # should not raise despite bad_subscriber
    assert len(good_received) == 1
    print("PASS: test_broken_subscriber_does_not_crash_ingest")


def test_history_size_bound():
    mgr = AlertManager(history_size=5)
    for i in range(10):
        mgr.ingest(make_alert(alert_type=f"TYPE_{i}"))

    recent = mgr.recent(100)
    assert len(recent) == 5, f"expected history capped at 5, got {len(recent)}"
    # newest 5 should be TYPE_5..TYPE_9
    assert [a.alert_type for a in recent] == ["TYPE_9", "TYPE_8", "TYPE_7", "TYPE_6", "TYPE_5"]
    print("PASS: test_history_size_bound")


def test_log_persistence():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "alerts.log")
        mgr = AlertManager(log_path=log_path)
        mgr.ingest(make_alert(alert_type="RST_STORM"))
        mgr.ingest(make_alert(alert_type="TTL_ANOMALY"))

        assert os.path.exists(log_path)
        with open(log_path) as f:
            lines = [json.loads(line) for line in f if line.strip()]
        assert len(lines) == 2
        assert lines[0]["alert_type"] == "RST_STORM"
        assert lines[1]["alert_type"] == "TTL_ANOMALY"
        print("PASS: test_log_persistence")


if __name__ == "__main__":
    test_ingest_and_recent_order()
    test_stats_counts()
    test_subscriber_broadcast()
    test_broken_subscriber_does_not_crash_ingest()
    test_history_size_bound()
    test_log_persistence()
    print("\nAll alert_manager tests passed.")
