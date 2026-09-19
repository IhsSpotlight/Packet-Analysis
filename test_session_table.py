"""
test_session_table.py
----------------------
Sanity tests for SessionTable that don't require root or a live NIC.
Run: python3 test_session_table.py
"""

import time
from session_table import SessionTable, PacketRecord


def make_rec(seq=1000, ack=0, ttl=64, flags="S", mac="aa:bb:cc:dd:ee:ff", length=60):
    return PacketRecord(
        timestamp=time.time(),
        seq=seq, ack=ack, ttl=ttl, flags=flags, src_mac=mac, length=length,
    )


def test_basic_session_creation():
    tbl = SessionTable()
    key = tbl.make_key("192.168.1.10", 51000, "93.184.216.34", 443, "TCP")
    sess = tbl.get_or_create(key)
    sess.add_packet(make_rec(flags="S"), key)
    sess.add_packet(make_rec(flags="SA"), key)
    sess.add_packet(make_rec(flags="A"), key)

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
    sess.add_packet(make_rec(ttl=64, mac="aa:aa:aa:aa:aa:aa"), key)
    sess.add_packet(make_rec(ttl=48, mac="bb:bb:bb:bb:bb:bb"), key)  # simulated hijack

    # baseline should NOT change after first packet — this is what
    # hijack_detector.py will compare later packets against
    assert sess.baseline_ttl == 64
    assert sess.baseline_mac == "aa:aa:aa:aa:aa:aa"
    print("PASS: test_ttl_and_mac_baseline_locks_on_first_packet")


# ---------------- bidirectional flow stats (Phase 2/3 upgrade) ----------------

def test_both_directions_collapse_into_one_flow():
    """The core fix: a client->server packet and the server's reply
    packet (literally reversed src/dst) must land in the SAME Session,
    not two separate ones — that's what makes forward/reverse stats
    possible at all."""
    tbl = SessionTable()
    client_key = tbl.make_key("192.168.1.10", 51000, "10.0.0.1", 443, "TCP")
    server_key = tbl.make_key("10.0.0.1", 443, "192.168.1.10", 51000, "TCP")

    sess_a = tbl.get_or_create(client_key)
    sess_a.add_packet(make_rec(flags="S"), client_key)

    sess_b = tbl.get_or_create(server_key)
    sess_b.add_packet(make_rec(flags="SA"), server_key)

    assert sess_a is sess_b, "both directions must resolve to the same Session object"
    assert tbl.count() == 1, "should be exactly one flow, not two"
    print("PASS: test_both_directions_collapse_into_one_flow")


def test_forward_reverse_packet_and_byte_counts():
    tbl = SessionTable()
    client_key = tbl.make_key("192.168.1.10", 51000, "10.0.0.1", 443, "TCP")
    server_key = tbl.make_key("10.0.0.1", 443, "192.168.1.10", 51000, "TCP")

    sess = tbl.get_or_create(client_key)
    sess.add_packet(make_rec(flags="S", length=60), client_key)     # fwd
    sess.add_packet(make_rec(flags="SA", length=60), server_key)    # rev
    sess.add_packet(make_rec(flags="A", length=54), client_key)     # fwd
    sess.add_packet(make_rec(flags="PA", length=1200), client_key)  # fwd (data upload)
    sess.add_packet(make_rec(flags="PA", length=1500), server_key)  # rev (data download)

    assert sess.fwd_packets == 3
    assert sess.rev_packets == 2
    assert sess.fwd_bytes == 60 + 54 + 1200
    assert sess.rev_bytes == 60 + 1500
    assert sess.total_packets() == 5
    assert sess.total_bytes() == sess.fwd_bytes + sess.rev_bytes
    print("PASS: test_forward_reverse_packet_and_byte_counts")


def test_packet_size_min_max_avg():
    tbl = SessionTable()
    key = tbl.make_key("192.168.1.10", 51000, "10.0.0.1", 443, "TCP")
    sess = tbl.get_or_create(key)
    for length in (60, 1500, 200, 40):
        sess.add_packet(make_rec(flags="PA", length=length), key)

    assert sess.min_pkt_size == 40
    assert sess.max_pkt_size == 1500
    assert sess.avg_packet_size() == (60 + 1500 + 200 + 40) / 4
    print("PASS: test_packet_size_min_max_avg")


def test_duration_and_rate_stats():
    tbl = SessionTable()
    key = tbl.make_key("192.168.1.10", 51000, "10.0.0.1", 443, "TCP")
    sess = tbl.get_or_create(key)

    t0 = time.time()
    r1 = make_rec(flags="S", length=60)
    r1.timestamp = t0
    r2 = make_rec(flags="A", length=100)
    r2.timestamp = t0 + 2.0  # 2 seconds later

    sess.add_packet(r1, key)
    sess.created_at = t0  # pin for a deterministic duration in this test
    sess.add_packet(r2, key)

    assert abs(sess.duration_seconds() - 2.0) < 0.01
    assert sess.total_packets() == 2
    assert abs(sess.packets_per_second() - 1.0) < 0.01  # 2 packets / 2s
    assert abs(sess.bytes_per_second() - 80.0) < 0.01   # 160 bytes / 2s
    print("PASS: test_duration_and_rate_stats")


def test_retransmission_detected_per_direction():
    tbl = SessionTable()
    key = tbl.make_key("192.168.1.10", 51000, "10.0.0.1", 443, "TCP")
    sess = tbl.get_or_create(key)

    sess.add_packet(make_rec(flags="S", seq=1000), key)
    sess.add_packet(make_rec(flags="PA", seq=1100), key)
    sess.add_packet(make_rec(flags="PA", seq=1100), key)  # exact retransmit, same seq
    sess.add_packet(make_rec(flags="PA", seq=1050), key)  # out-of-order/retransmit, seq went backward

    assert sess.fwd_retransmit_count == 2
    print("PASS: test_retransmission_detected_per_direction")


def test_handshake_success_vs_failure():
    tbl = SessionTable()

    # successful handshake
    ok_key = tbl.make_key("192.168.1.10", 51000, "10.0.0.1", 443, "TCP")
    ok = tbl.get_or_create(ok_key)
    ok.add_packet(make_rec(flags="S"), ok_key)
    ok.add_packet(make_rec(flags="A"), ok_key)
    assert ok.connection_established is True
    assert ok.handshake_failed is False

    # refused connection: SYN met with RST, no ACK ever seen
    refused_key = tbl.make_key("192.168.1.10", 51001, "10.0.0.1", 9999, "TCP")
    refused = tbl.get_or_create(refused_key)
    refused.add_packet(make_rec(flags="S"), refused_key)
    refused.add_packet(make_rec(flags="R"), refused_key)
    assert refused.connection_established is False
    assert refused.handshake_failed is True
    print("PASS: test_handshake_success_vs_failure")


def test_flow_stats_snapshot_shape():
    tbl = SessionTable()
    key = tbl.make_key("192.168.1.10", 51000, "10.0.0.1", 443, "TCP")
    sess = tbl.get_or_create(key)
    sess.add_packet(make_rec(flags="S", length=60), key)
    sess.add_packet(make_rec(flags="A", length=54), key)

    stats = sess.flow_stats()
    expected_keys = {
        "flow_key", "initiator", "duration_seconds", "total_packets", "total_bytes",
        "fwd_packets", "rev_packets", "fwd_bytes", "rev_bytes", "avg_packet_size",
        "min_packet_size", "max_packet_size", "packets_per_second", "bytes_per_second",
        "syn_count", "synack_count", "ack_count", "rst_count", "fin_count",
        "fwd_retransmit_count", "rev_retransmit_count", "connection_established",
        "handshake_failed",
    }
    assert expected_keys.issubset(stats.keys()), f"missing keys: {expected_keys - stats.keys()}"
    assert stats["total_packets"] == 2
    print("PASS: test_flow_stats_snapshot_shape")


def test_reset_on_new_connection_clears_flow_stats_too():
    """The existing connection-reuse fix must also reset the NEW flow
    stats fields, not just baseline_ttl/baseline_mac — otherwise a reused
    port would blend two connections' byte counts together."""
    tbl = SessionTable()
    key = tbl.make_key("192.168.1.10", 51000, "10.0.0.1", 443, "TCP")
    sess = tbl.get_or_create(key)

    # connection #1
    sess.add_packet(make_rec(flags="S", length=60), key)
    sess.add_packet(make_rec(flags="A", length=1000), key)
    assert sess.total_bytes() == 1060

    # connection #2 reuses the same tuple
    sess.add_packet(make_rec(flags="S", length=60), key)

    assert sess.total_bytes() == 60, "flow byte counters should reset for the new connection"
    assert sess.fwd_packets == 1
    assert sess.generation == 1
    print("PASS: test_reset_on_new_connection_clears_flow_stats_too")


def test_network_id_flows_into_flow_stats():
    """SessionTable's network_id (sensor-level config) must be stamped
    onto every Session it creates and show up in flow_stats() — this is
    what lets a flow snapshot be attributed to the right department
    network once shipped to a central aggregator."""
    tbl = SessionTable(network_id="hr-net")
    key = tbl.make_key("192.168.1.10", 51000, "10.0.0.1", 443, "TCP")
    sess = tbl.get_or_create(key)
    sess.add_packet(make_rec(flags="S"), key)

    assert sess.network_id == "hr-net"
    assert sess.flow_stats()["network_id"] == "hr-net"
    print("PASS: test_network_id_flows_into_flow_stats")


def test_network_id_defaults_to_none_when_unset():
    tbl = SessionTable()  # no network_id given — single-sensor deployments unaffected
    key = tbl.make_key("192.168.1.10", 51000, "10.0.0.1", 443, "TCP")
    sess = tbl.get_or_create(key)
    sess.add_packet(make_rec(flags="S"), key)

    assert sess.network_id is None
    assert sess.flow_stats()["network_id"] is None
    print("PASS: test_network_id_defaults_to_none_when_unset")


if __name__ == "__main__":
    test_basic_session_creation()
    test_port_scan_window()
    test_stale_reaping()
    test_ttl_and_mac_baseline_locks_on_first_packet()
    test_both_directions_collapse_into_one_flow()
    test_forward_reverse_packet_and_byte_counts()
    test_packet_size_min_max_avg()
    test_duration_and_rate_stats()
    test_retransmission_detected_per_direction()
    test_handshake_success_vs_failure()
    test_flow_stats_snapshot_shape()
    test_reset_on_new_connection_clears_flow_stats_too()
    test_network_id_flows_into_flow_stats()
    test_network_id_defaults_to_none_when_unset()
    print("\nAll session_table tests passed.")
