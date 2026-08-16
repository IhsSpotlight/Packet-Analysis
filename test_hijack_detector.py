"""
test_hijack_detector.py
------------------------
Run: python3 test_hijack_detector.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "capture"))
from session_table import SessionTable, PacketRecord   # noqa: E402
from hijack_detector import HijackDetector              # noqa: E402


def feed(table, detector, src_ip, dst_ip, dport, flags,
         seq=1000, ack=0, ttl=64, mac="aa:bb:cc:dd:ee:ff", sport=51000):
    key = table.make_key(src_ip, sport, dst_ip, dport, "TCP")
    session = table.get_or_create(key)
    rec = PacketRecord(timestamp=time.time(), seq=seq, ack=ack, ttl=ttl,
                        flags=flags, src_mac=mac, length=60)
    session.add_packet(rec)
    return detector.on_packet(session, key, rec), key


def test_normal_session_no_alerts():
    table = SessionTable()
    fired = []
    detector = HijackDetector(table, on_alert=lambda a: fired.append(a))

    # a clean handshake + a few data packets with steadily increasing seq,
    # consistent TTL, consistent MAC — nothing here should ever fire
    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "S", seq=1000, ttl=64)
    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "A", seq=1001, ttl=64)
    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "PA", seq=1101, ttl=64)
    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "PA", seq=1201, ttl=63)  # 1 tick of TTL jitter

    assert fired == [], f"expected no alerts on normal traffic, got {fired}"
    print("PASS: test_normal_session_no_alerts")


def test_ttl_anomaly_detected():
    table = SessionTable()
    fired = []
    detector = HijackDetector(table, ttl_variance=5, on_alert=lambda a: fired.append(a))

    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "S", seq=1000, ttl=64)
    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "PA", seq=1101, ttl=64)
    # attacker's forged packet arrives with a very different TTL (different hop count)
    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "PA", seq=1201, ttl=40)

    ttl_alerts = [a for a in fired if a.alert_type == "TTL_ANOMALY"]
    assert len(ttl_alerts) == 1, f"expected 1 TTL_ANOMALY alert, got {len(ttl_alerts)}"
    assert ttl_alerts[0].details["baseline_ttl"] == 64
    assert ttl_alerts[0].details["observed_ttl"] == 40
    print("PASS: test_ttl_anomaly_detected")


def test_mac_swap_detected():
    table = SessionTable()
    fired = []
    detector = HijackDetector(table, on_alert=lambda a: fired.append(a))

    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "S", seq=1000, mac="aa:aa:aa:aa:aa:aa")
    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "PA", seq=1101, mac="aa:aa:aa:aa:aa:aa")
    # a different device on the LAN starts sending packets claiming this session's IP
    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "PA", seq=1201, mac="bb:bb:bb:bb:bb:bb")

    mac_alerts = [a for a in fired if a.alert_type == "MAC_SWAP"]
    assert len(mac_alerts) == 1, f"expected 1 MAC_SWAP alert, got {len(mac_alerts)}"
    assert mac_alerts[0].severity.value == "critical"
    print("PASS: test_mac_swap_detected")


def test_seq_anomaly_forward_jump_detected():
    table = SessionTable()
    fired = []
    detector = HijackDetector(table, seq_jump_threshold=500_000,
                               on_alert=lambda a: fired.append(a))

    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "S", seq=1000)
    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "PA", seq=1100)
    # huge unexplained jump — attacker injecting a packet with a guessed/wrong seq
    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "PA", seq=900_000)

    seq_alerts = [a for a in fired if a.alert_type == "SEQ_ANOMALY"]
    assert len(seq_alerts) == 1, f"expected 1 SEQ_ANOMALY alert, got {len(seq_alerts)}"
    assert seq_alerts[0].details["direction"] == "forward"
    print("PASS: test_seq_anomaly_forward_jump_detected")


def test_seq_small_backward_move_is_normal():
    """Small backward seq moves happen during normal retransmits — must NOT alert."""
    table = SessionTable()
    fired = []
    detector = HijackDetector(table, on_alert=lambda a: fired.append(a))

    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "S", seq=5000)
    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "PA", seq=5200)
    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "PA", seq=5150)  # retransmit, small backward move

    seq_alerts = [a for a in fired if a.alert_type == "SEQ_ANOMALY"]
    assert seq_alerts == [], f"expected no SEQ_ANOMALY on normal retransmit, got {seq_alerts}"
    print("PASS: test_seq_small_backward_move_is_normal")


def test_rst_storm_detected():
    table = SessionTable()
    fired = []
    detector = HijackDetector(table, rst_storm_threshold=5, rst_storm_window=5.0,
                               on_alert=lambda a: fired.append(a))

    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "S", seq=1000)
    for i in range(6):
        feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "R", seq=1000 + i)

    rst_alerts = [a for a in fired if a.alert_type == "RST_STORM"]
    assert len(rst_alerts) == 1, f"expected 1 RST_STORM alert, got {len(rst_alerts)}"
    print("PASS: test_rst_storm_detected")


def test_dup_ack_storm_detected():
    table = SessionTable()
    fired = []
    detector = HijackDetector(table, dup_ack_threshold=4, dup_ack_window=5.0,
                               on_alert=lambda a: fired.append(a))

    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "S", seq=1000)
    # same ACK value repeated many times — two peers racing for control
    for _ in range(5):
        feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "A", seq=1000, ack=2000)

    dup_alerts = [a for a in fired if a.alert_type == "DUP_ACK_STORM"]
    assert len(dup_alerts) == 1, f"expected 1 DUP_ACK_STORM alert, got {len(dup_alerts)}"
    print("PASS: test_dup_ack_storm_detected")


def test_alert_cooldown_suppresses_repeats():
    table = SessionTable()
    fired = []
    detector = HijackDetector(table, ttl_variance=5, alert_cooldown=60.0,
                               on_alert=lambda a: fired.append(a))

    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "S", seq=1000, ttl=64)
    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "PA", seq=1100, ttl=40)  # fires
    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "PA", seq=1200, ttl=40)  # suppressed by cooldown

    ttl_alerts = [a for a in fired if a.alert_type == "TTL_ANOMALY"]
    assert len(ttl_alerts) == 1, f"expected exactly 1 alert due to cooldown, got {len(ttl_alerts)}"
    print("PASS: test_alert_cooldown_suppresses_repeats")


def test_connection_reuse_does_not_false_positive():
    """Regression test: ephemeral port reuse (e.g. rapid-fire HTTPS
    connections to the same CDN edge) makes the same 5-tuple represent
    two genuinely different TCP connections back to back. A brand new
    connection's fresh, randomized ISN and possibly different TTL/MAC
    must NOT be flagged as SEQ_ANOMALY / TTL_ANOMALY / MAC_SWAP against
    the old, unrelated connection's state."""
    table = SessionTable()
    fired = []
    detector = HijackDetector(table, ttl_variance=5, seq_jump_threshold=500_000,
                               on_alert=lambda a: fired.append(a))

    # --- connection #1: completes a normal handshake and exchanges data ---
    feed(table, detector, "192.168.0.100", "57.144.87.32", 443, "S",
         seq=2_800_000_000, ttl=64, mac="aa:aa:aa:aa:aa:aa")
    feed(table, detector, "192.168.0.100", "57.144.87.32", 443, "A",
         seq=2_800_000_100, ttl=64, mac="aa:aa:aa:aa:aa:aa")
    feed(table, detector, "192.168.0.100", "57.144.87.32", 443, "PA",
         seq=2_800_050_000, ttl=64, mac="aa:aa:aa:aa:aa:aa")

    # --- connection #2: same 5-tuple (port reused), brand new ISN ---
    # this is the exact shape of the real false positive: a much SMALLER
    # seq number than the previous connection's last seq, plus TTL could
    # legitimately differ by a hop or two on a new route.
    feed(table, detector, "192.168.0.100", "57.144.87.32", 443, "S",
         seq=2_845_426_822, ttl=64, mac="aa:aa:aa:aa:aa:aa")
    feed(table, detector, "192.168.0.100", "57.144.87.32", 443, "A",
         seq=2_845_426_922, ttl=64, mac="aa:aa:aa:aa:aa:aa")

    seq_alerts = [a for a in fired if a.alert_type == "SEQ_ANOMALY"]
    ttl_alerts = [a for a in fired if a.alert_type == "TTL_ANOMALY"]
    mac_alerts = [a for a in fired if a.alert_type == "MAC_SWAP"]

    assert seq_alerts == [], f"expected no SEQ_ANOMALY across reused connection, got {seq_alerts}"
    assert ttl_alerts == [], f"expected no TTL_ANOMALY across reused connection, got {ttl_alerts}"
    assert mac_alerts == [], f"expected no MAC_SWAP across reused connection, got {mac_alerts}"
    print("PASS: test_connection_reuse_does_not_false_positive")


def test_real_hijack_within_same_connection_still_detected():
    """Make sure the fix doesn't accidentally blind the detector to a
    REAL hijack — an anomaly appearing WITHOUT a new SYN in between must
    still fire, since that's not a new connection, just a forged packet."""
    table = SessionTable()
    fired = []
    detector = HijackDetector(table, ttl_variance=5,
                               on_alert=lambda a: fired.append(a))

    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "S", seq=1000, ttl=64)
    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "A", seq=1100, ttl=64)
    # no new SYN here — this is a forged packet injected mid-stream
    feed(table, detector, "192.168.1.10", "10.0.0.1", 443, "PA", seq=1200, ttl=30)

    ttl_alerts = [a for a in fired if a.alert_type == "TTL_ANOMALY"]
    assert len(ttl_alerts) == 1, "a real TTL anomaly mid-connection should still be caught"
    print("PASS: test_real_hijack_within_same_connection_still_detected")


if __name__ == "__main__":
    test_normal_session_no_alerts()
    test_ttl_anomaly_detected()
    test_mac_swap_detected()
    test_seq_anomaly_forward_jump_detected()
    test_seq_small_backward_move_is_normal()
    test_rst_storm_detected()
    test_dup_ack_storm_detected()
    test_alert_cooldown_suppresses_repeats()
    test_connection_reuse_does_not_false_positive()
    test_real_hijack_within_same_connection_still_detected()
    print("\nAll hijack_detector tests passed.")
