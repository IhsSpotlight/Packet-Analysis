"""
test_scan_detector.py
----------------------
Run: python3 test_scan_detector.py

Simulates packet flows through ScanDetector without needing scapy/root,
by constructing PacketRecords and session keys directly.
"""

import os
import sys
import time
import socket
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "capture"))
from session_table import SessionTable, PacketRecord   # noqa: E402
from scan_detector import ScanDetector, OpenPortMonitor, classify_tcp_scan_flags  # noqa: E402


def feed(table, detector, src_ip, dst_ip, dport, flags, sport=51000):
    key = table.make_key(src_ip, sport, dst_ip, dport, "TCP")
    session = table.get_or_create(key)
    rec = PacketRecord(timestamp=time.time(), seq=1, ack=0, ttl=64,
                        flags=flags, src_mac="aa:bb:cc:dd:ee:ff", length=60)
    session.add_packet(rec)
    table.record_port_touch(src_ip, dport, rec.timestamp)
    return detector.on_packet(session, key, rec)


def test_normal_traffic_no_alert():
    table = SessionTable()
    fired = []
    detector = ScanDetector(table, on_alert=lambda a: fired.append(a))

    # a handful of normal completed handshakes to different but few ports
    for dport in (80, 443, 22):
        feed(table, detector, "192.168.1.50", "10.0.0.1", dport, "S")
        feed(table, detector, "192.168.1.50", "10.0.0.1", dport, "A")  # completes handshake

    assert fired == [], f"expected no alerts, got {fired}"
    print("PASS: test_normal_traffic_no_alert")


def test_port_scan_detected():
    table = SessionTable()
    fired = []
    detector = ScanDetector(table, port_scan_threshold=15, port_scan_window=5.0,
                             on_alert=lambda a: fired.append(a))

    attacker = "10.0.0.99"
    alerts = []
    for port in range(20, 45):  # 25 distinct ports, well past threshold of 15
        alerts += feed(table, detector, attacker, "10.0.0.1", port, "S")

    port_scan_alerts = [a for a in fired if a.alert_type == "PORT_SCAN"]
    assert len(port_scan_alerts) >= 1, "expected a PORT_SCAN alert to fire"
    assert port_scan_alerts[0].src_ip == attacker
    assert port_scan_alerts[0].details["scan_type_breakdown"].get("SYN", 0) >= 15
    print("PASS: test_port_scan_detected")


def test_syn_flood_detected():
    table = SessionTable()
    fired = []
    detector = ScanDetector(table, synflood_threshold=50, synflood_window=10.0,
                             on_alert=lambda a: fired.append(a))

    attacker = "10.0.0.77"
    # 60 SYNs to 60 different ports on the same target, none ever ACKed —
    # classic half-open flood pattern
    for port in range(2000, 2060):
        feed(table, detector, attacker, "10.0.0.1", port, "S")

    flood_alerts = [a for a in fired if a.alert_type == "SYN_FLOOD"]
    assert len(flood_alerts) >= 1, "expected a SYN_FLOOD alert to fire"
    assert flood_alerts[0].details["half_open_count"] >= 50
    print("PASS: test_syn_flood_detected")


def test_completed_handshakes_dont_count_as_half_open():
    table = SessionTable()
    fired = []
    detector = ScanDetector(table, synflood_threshold=10, synflood_window=10.0,
                             on_alert=lambda a: fired.append(a))

    src = "192.168.1.20"
    # 20 SYNs, but EVERY one gets its completing ACK — should never flag
    for port in range(3000, 3020):
        feed(table, detector, src, "10.0.0.1", port, "S")
        feed(table, detector, src, "10.0.0.1", port, "A")

    flood_alerts = [a for a in fired if a.alert_type == "SYN_FLOOD"]
    assert flood_alerts == [], f"expected no flood alert, got {flood_alerts}"
    print("PASS: test_completed_handshakes_dont_count_as_half_open")


def test_scan_flag_classification():
    assert classify_tcp_scan_flags("S") == "SYN"
    assert classify_tcp_scan_flags("F") == "FIN"
    assert classify_tcp_scan_flags("") == "NULL"
    assert classify_tcp_scan_flags("FPU") == "XMAS"
    assert classify_tcp_scan_flags("SA") == "OTHER"
    print("PASS: test_scan_flag_classification")


def test_alert_cooldown_suppresses_repeats():
    table = SessionTable()
    fired = []
    detector = ScanDetector(table, port_scan_threshold=5, port_scan_window=5.0,
                             alert_cooldown=60.0, on_alert=lambda a: fired.append(a))

    attacker = "10.0.0.66"
    for port in range(100, 110):
        feed(table, detector, attacker, "10.0.0.1", port, "S")
    for port in range(200, 210):  # would trigger again immediately without cooldown
        feed(table, detector, attacker, "10.0.0.1", port, "S")

    port_scan_alerts = [a for a in fired if a.alert_type == "PORT_SCAN"]
    assert len(port_scan_alerts) == 1, f"expected exactly 1 alert due to cooldown, got {len(port_scan_alerts)}"
    print("PASS: test_alert_cooldown_suppresses_repeats")


def test_open_port_monitor_flags_unexpected_port():
    # bind a real socket on an ephemeral port that is NOT in the whitelist
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    try:
        monitor = OpenPortMonitor(allowed_ports={22, 80, 443}, port_range=(port, port))
        alert = monitor.check()
        assert alert is not None, "expected an UNEXPECTED_OPEN_PORT alert"
        assert port in alert.details["unexpected_ports"]
        print("PASS: test_open_port_monitor_flags_unexpected_port")
    finally:
        srv.close()


def test_open_port_monitor_no_alert_when_whitelisted():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    try:
        monitor = OpenPortMonitor(allowed_ports={port}, port_range=(port, port))
        alert = monitor.check()
        assert alert is None, "expected no alert since port is whitelisted"
        print("PASS: test_open_port_monitor_no_alert_when_whitelisted")
    finally:
        srv.close()


if __name__ == "__main__":
    test_normal_traffic_no_alert()
    test_port_scan_detected()
    test_syn_flood_detected()
    test_completed_handshakes_dont_count_as_half_open()
    test_scan_flag_classification()
    test_alert_cooldown_suppresses_repeats()
    test_open_port_monitor_flags_unexpected_port()
    test_open_port_monitor_no_alert_when_whitelisted()
    print("\nAll scan_detector tests passed.")
