"""
sniffer.py
----------
Live packet capture using scapy. Parses each packet into a PacketRecord
and feeds it into the shared SessionTable. Requires root / CAP_NET_RAW
to actually sniff on a real interface.

Run standalone for a smoke test:
    sudo python3 sniffer.py --iface eth0

Import and use `start_sniffing()` from main.py to wire it into the
full pipeline (detectors + dashboard).
"""

import argparse
import time

from scapy.all import sniff, IP, TCP, UDP, Ether

from session_table import SessionTable, PacketRecord


TCP_FLAG_MAP = {
    "F": "F", "S": "S", "R": "R", "P": "P",
    "A": "A", "U": "U", "E": "E", "C": "C",
}


def _flags_to_str(pkt) -> str:
    if TCP in pkt:
        # scapy exposes flags as a FlagValue; str() gives e.g. 'SA'
        return str(pkt[TCP].flags)
    return ""


def _extract(pkt) -> PacketRecord | None:
    """Turn a raw scapy packet into a normalized PacketRecord, or None
    if it's not a protocol we track (only IPv4 TCP/UDP for now)."""
    if IP not in pkt:
        return None

    ip = pkt[IP]
    proto = None
    sport = dport = None
    seq = ack = None

    if TCP in pkt:
        proto = "TCP"
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        seq, ack = pkt[TCP].seq, pkt[TCP].ack
    elif UDP in pkt:
        proto = "UDP"
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    else:
        return None

    src_mac = pkt[Ether].src if Ether in pkt else None

    rec = PacketRecord(
        timestamp=time.time(),
        seq=seq,
        ack=ack,
        ttl=ip.ttl,
        flags=_flags_to_str(pkt),
        src_mac=src_mac,
        length=len(pkt),
    )
    return rec, ip.src, sport, ip.dst, dport, proto


def make_packet_handler(table: SessionTable, on_packet=None):
    """Returns a callback suitable for scapy's sniff(prn=...).
    `on_packet(session, key, rec)` is called after each packet is recorded,
    so detectors can be wired in without this module knowing about them."""

    def handle(pkt):
        extracted = _extract(pkt)
        if extracted is None:
            return
        rec, src_ip, sport, dst_ip, dport, proto = extracted

        key = table.make_key(src_ip, sport, dst_ip, dport, proto)
        session = table.get_or_create(key)
        session.add_packet(rec, key)

        # scan detection needs a source-ip -> port history independent of
        # full session tuples (a scanner touches many different dports)
        table.record_port_touch(src_ip, dport, rec.timestamp)

        if on_packet:
            on_packet(session, key, rec)

    return handle


def start_sniffing(iface: str, table: SessionTable, on_packet=None, bpf_filter="ip"):
    """Blocking call — starts live capture. Run in its own thread from main.py."""
    handler = make_packet_handler(table, on_packet=on_packet)
    sniff(iface=iface, prn=handler, filter=bpf_filter, store=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sniffer smoke test")
    parser.add_argument("--iface", required=True, help="Network interface to sniff on")
    args = parser.parse_args()

    tbl = SessionTable()

    def _print_progress(session, key, rec):
        print(f"[{rec.timestamp:.2f}] {key} flags={rec.flags} ttl={rec.ttl} "
              f"sessions_tracked={tbl.count()}")

    print(f"Sniffing on {args.iface} — Ctrl+C to stop")
    start_sniffing(args.iface, tbl, on_packet=_print_progress)
