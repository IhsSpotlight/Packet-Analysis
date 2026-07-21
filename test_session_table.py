"""
test_session_table.py
----------------------
Sanity tests for SessionTable that don't require root or a live NIC.
Run: python3 test_session_table.py
"""

import time
from session_table import SessionTable, PacketRecord


def make_rec(seq=1000, ack=0, ttl=64, flags="S", mac="aa:bb:cc:dd:ee:ff"):
    return PacketRecord(
        timestamp=time.time(),
        seq=seq, ack=ack, ttl=ttl, flags=flags, src_mac=mac, length=60,
    )


def test_basic_session_creation():
    tbl = SessionTable()
    key = tbl.make_key("192.168.1.10", 51000, "93.184.216.34", 443, "TCP")
    sess = tbl.get_or_create(key)
    sess.add_packet(make_rec(flags="S"))
    sess.add_packet(make_rec(flags="SA"))
    sess.add_packet(make_rec(flags="A"))

    assert tbl.count() == 1
    assert sess.syn_count == 1
    assert sess.synack_count == 1
    assert sess.baseline_ttl == 64
    assert sess.baseline_mac == "aa:bb:cc:dd:ee:ff"
    print("PASS: test_basic_session_creation")


def test_port_scan_window():
    tbl = SessionTable()
    src = "10.0.0.5"
    for port in range(20, 45):  # touch 25 distinct ports rapidly
        tbl.record_port_touch(src, port, time.time())

    touched = tbl.ports_touched_in_window(src, window_seconds=5)
    assert len(touched) == 25, f"expected 25 ports, got {len(touched)}"
    print("PASS: test_port_scan_window")


def test_stale_reaping():
    tbl = SessionTable()
    key = tbl.make_key("10.0.0.1", 1234, "10.0.0.2", 80, "TCP")
    sess = tbl.get_or_create(key)
    sess.last_seen = time.time() - 999  # force staleness

    reaped = tbl.reap_stale(timeout=120)
    assert reaped == 1
    assert tbl.count() == 0
    print("PASS: test_stale_reaping")


def test_ttl_and_mac_baseline_locks_on_first_packet():
    tbl = SessionTable()
    key = tbl.make_key("10.0.0.1", 1234, "10.0.0.2", 80, "TCP")
    sess = tbl.get_or_create(key)
    sess.add_packet(make_rec(ttl=64, mac="aa:aa:aa:aa:aa:aa"))
    sess.add_packet(make_rec(ttl=48, mac="bb:bb:bb:bb:bb:bb"))  # simulated hijack

    # baseline should NOT change after first packet — this is what
    # hijack_detector.py will compare later packets against
    assert sess.baseline_ttl == 64
    assert sess.baseline_mac == "aa:aa:aa:aa:aa:aa"
    print("PASS: test_ttl_and_mac_baseline_locks_on_first_packet")


if __name__ == "__main__":
    test_basic_session_creation()
    test_port_scan_window()
    test_stale_reaping()
    test_ttl_and_mac_baseline_locks_on_first_packet()
    print("\nAll session_table tests passed.")
