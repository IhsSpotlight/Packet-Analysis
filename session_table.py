"""
session_table.py
-----------------
In-memory flow tracker. Every packet the sniffer sees gets folded into a
Session object — which now represents a proper bidirectional FLOW, per
the flow-based IDS design: both directions of a TCP conversation
(client->server AND server->client) are the same flow, not two separate
objects.

Two distinct "key" concepts are used deliberately:

  - LITERAL key: (src_ip, sport, dst_ip, dport, proto) exactly as seen on
    THIS packet. This is what sniffer.py computes per-packet and what
    gets passed to scan_detector/hijack_detector — they need to know
    which literal direction a packet traveled (e.g. "who is scanning
    whom" is direction-sensitive).

  - CANONICAL key: the literal key normalized so both directions of the
    same conversation map to the same dict entry. Used only internally
    by SessionTable to decide which Session object a packet belongs to.

A Session tracks which literal (ip, port) pair initiated the flow
(`initiator`) so it can classify every packet as forward (initiator ->
peer) or reverse (peer -> initiator) and accumulate the statistics a
flow-based IDS needs: total/forward/reverse packets and bytes, duration,
packets-per-second, bytes-per-second, packet size min/max/avg, TCP flag
counts, a basic retransmission indicator, and handshake success/failure.

This is the shared state both detectors read from:
  - hijack_detector.py needs seq/ack history + TTL history + MAC history per session
  - scan_detector.py needs per-source-IP port-touch history and half-open SYN counts

Kept deliberately dependency-free (just stdlib) so it's easy to unit test
without scapy or root privileges.
"""

import time
import threading
from collections import deque
from dataclasses import dataclass, field


# How much raw-packet history to keep per session before trimming (memory bound).
# Flow-level totals below are tracked via explicit counters, NOT by len(packets),
# since this deque evicts old entries — counters must survive that eviction.
MAX_HISTORY = 50

# A session with no packets for this long is considered stale and can be reaped
SESSION_TIMEOUT_SECONDS = 120


@dataclass
class PacketRecord:
    timestamp: float
    seq: int | None
    ack: int | None
    ttl: int | None
    flags: str          # e.g. "S", "SA", "A", "F", "R", "PA"
    src_mac: str | None
    length: int


@dataclass
class Session:
    key: tuple                       # canonical flow key (see module docstring)
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packets: deque = field(default_factory=lambda: deque(maxlen=MAX_HISTORY))

    # rolling baselines used by hijack_detector
    baseline_ttl: int | None = None
    baseline_mac: str | None = None
    expected_next_seq: int | None = None

    # counters used by scan_detector
    syn_count: int = 0
    synack_count: int = 0
    rst_count: int = 0
    dup_ack_count: int = 0

    # ---- flow-level statistics (Phase 2/3: flow generation + features) ----
    initiator: tuple | None = None     # (ip, port) of whichever side sent the first packet
    fwd_packets: int = 0               # initiator -> peer
    rev_packets: int = 0               # peer -> initiator
    fwd_bytes: int = 0
    rev_bytes: int = 0
    min_pkt_size: int | None = None
    max_pkt_size: int | None = None
    fin_count: int = 0
    ack_count: int = 0                 # any packet with the ACK flag set (broader than synack_count)
    fwd_retransmit_count: int = 0
    rev_retransmit_count: int = 0
    connection_established: bool = False   # tracked separately from has_seen_ack for clarity in flow stats
    handshake_failed: bool = False         # RST seen before the handshake ever completed
    _last_fwd_seq: int | None = field(default=None, repr=False)
    _last_rev_seq: int | None = field(default=None, repr=False)

    # connection-reuse tracking: ephemeral ports get recycled quickly under
    # load (e.g. many short-lived HTTPS connections to the same CDN edge),
    # so the same 5-tuple key can legitimately represent a brand new TCP
    # connection later on. has_seen_ack flips True once the handshake has
    # visibly progressed; a bare SYN arriving after that can only mean a
    # new connection just reused this tuple — never a mid-stream SYN.
    has_seen_ack: bool = False
    generation: int = 0

    def add_packet(self, rec: PacketRecord, literal_key: tuple):
        """literal_key is the packet's own (src_ip, sport, dst_ip, dport, proto)
        exactly as captured — used to determine forward/reverse direction
        and, on reset, who the new connection's initiator is."""
        pkt_src = (literal_key[0], literal_key[1])

        if rec.flags == "S" and self.has_seen_ack:
            self._reset_for_new_connection()

        if self.initiator is None:
            self.initiator = pkt_src
        is_forward = (pkt_src == self.initiator)

        self.packets.append(rec)
        self.last_seen = rec.timestamp

        if self.baseline_ttl is None and rec.ttl is not None:
            self.baseline_ttl = rec.ttl
        if self.baseline_mac is None and rec.src_mac is not None:
            self.baseline_mac = rec.src_mac
        if "A" in rec.flags:
            self.has_seen_ack = True
            self.connection_established = True
            self.ack_count += 1

        if "S" in rec.flags and "A" not in rec.flags:
            self.syn_count += 1
        if "S" in rec.flags and "A" in rec.flags:
            self.synack_count += 1
        if "R" in rec.flags:
            self.rst_count += 1
            if not self.connection_established:
                self.handshake_failed = True
        if "F" in rec.flags:
            self.fin_count += 1

        # ---- direction-aware flow stats ----
        if is_forward:
            self.fwd_packets += 1
            self.fwd_bytes += rec.length
            if rec.seq is not None:
                if self._last_fwd_seq is not None and rec.seq <= self._last_fwd_seq:
                    self.fwd_retransmit_count += 1
                self._last_fwd_seq = rec.seq
        else:
            self.rev_packets += 1
            self.rev_bytes += rec.length
            if rec.seq is not None:
                if self._last_rev_seq is not None and rec.seq <= self._last_rev_seq:
                    self.rev_retransmit_count += 1
                self._last_rev_seq = rec.seq

        if self.min_pkt_size is None or rec.length < self.min_pkt_size:
            self.min_pkt_size = rec.length
        if self.max_pkt_size is None or rec.length > self.max_pkt_size:
            self.max_pkt_size = rec.length

    def _reset_for_new_connection(self):
        """Called when a bare SYN reuses a session key whose previous
        connection already completed a handshake — i.e. this key now
        belongs to a different, unrelated TCP connection. Wipes the
        baselines/history/flow-stats so detectors and flow features don't
        blend two unrelated connections together, and bumps `generation`
        so external per-session tracking (hijack_detector's seq/RST/ACK
        dicts) knows to start fresh too."""
        self.packets.clear()
        self.baseline_ttl = None
        self.baseline_mac = None
        self.expected_next_seq = None
        self.has_seen_ack = False
        self.syn_count = 0
        self.synack_count = 0
        self.rst_count = 0
        self.dup_ack_count = 0
        self.generation += 1
        self.created_at = time.time()

        self.initiator = None
        self.fwd_packets = 0
        self.rev_packets = 0
        self.fwd_bytes = 0
        self.rev_bytes = 0
        self.min_pkt_size = None
        self.max_pkt_size = None
        self.fin_count = 0
        self.ack_count = 0
        self.fwd_retransmit_count = 0
        self.rev_retransmit_count = 0
        self.connection_established = False
        self.handshake_failed = False
        self._last_fwd_seq = None
        self._last_rev_seq = None

    # ---- derived flow statistics (computed, never stored, so they can't go stale) ----

    def duration_seconds(self) -> float:
        return max(0.0, self.last_seen - self.created_at)

    def total_packets(self) -> int:
        return self.fwd_packets + self.rev_packets

    def total_bytes(self) -> int:
        return self.fwd_bytes + self.rev_bytes

    def avg_packet_size(self) -> float:
        total = self.total_packets()
        return (self.total_bytes() / total) if total else 0.0

    def packets_per_second(self) -> float:
        dur = self.duration_seconds()
        return (self.total_packets() / dur) if dur > 0 else 0.0

    def bytes_per_second(self) -> float:
        dur = self.duration_seconds()
        return (self.total_bytes() / dur) if dur > 0 else 0.0

    def flow_stats(self) -> dict:
        """Snapshot of all flow-level statistics, in the shape a feature
        extractor / dashboard / ML pipeline would want to consume."""
        return {
            "flow_key": self.key,
            "initiator": self.initiator,
            "duration_seconds": self.duration_seconds(),
            "total_packets": self.total_packets(),
            "total_bytes": self.total_bytes(),
            "fwd_packets": self.fwd_packets,
            "rev_packets": self.rev_packets,
            "fwd_bytes": self.fwd_bytes,
            "rev_bytes": self.rev_bytes,
            "avg_packet_size": self.avg_packet_size(),
            "min_packet_size": self.min_pkt_size,
            "max_packet_size": self.max_pkt_size,
            "packets_per_second": self.packets_per_second(),
            "bytes_per_second": self.bytes_per_second(),
            "syn_count": self.syn_count,
            "synack_count": self.synack_count,
            "ack_count": self.ack_count,
            "rst_count": self.rst_count,
            "fin_count": self.fin_count,
            "fwd_retransmit_count": self.fwd_retransmit_count,
            "rev_retransmit_count": self.rev_retransmit_count,
            "connection_established": self.connection_established,
            "handshake_failed": self.handshake_failed,
        }


class SessionTable:
    """Thread-safe store of active Session (flow) objects."""

    def __init__(self):
        self._sessions: dict[tuple, Session] = {}
        self._lock = threading.Lock()

        # secondary index for scan_detector: source_ip -> set of dst ports touched,
        # each entry timestamped so we can apply a sliding window.
        self._port_touches: dict[str, deque] = {}

    @staticmethod
    def make_key(src_ip, sport, dst_ip, dport, proto):
        # LITERAL key — exactly as seen on the packet. Detectors need this
        # exact form (they read key[0] as "the source of this packet").
        return (src_ip, sport, dst_ip, dport, proto)

    @staticmethod
    def _canonical(key) -> tuple:
        """Normalizes a literal key so both directions of one conversation
        collapse to the same dict entry: order the two (ip, port) endpoints
        deterministically rather than by "who happened to be src on this
        particular packet"."""
        src_ip, sport, dst_ip, dport, proto = key
        a = (src_ip, sport)
        b = (dst_ip, dport)
        if a <= b:
            return (src_ip, sport, dst_ip, dport, proto)
        return (dst_ip, dport, src_ip, sport, proto)

    def get_or_create(self, key) -> Session:
        canonical = self._canonical(key)
        with self._lock:
            sess = self._sessions.get(canonical)
            if sess is None:
                sess = Session(key=canonical)
                self._sessions[canonical] = sess
            return sess

    def record_port_touch(self, src_ip: str, dst_port: int, ts: float):
        with self._lock:
            dq = self._port_touches.setdefault(src_ip, deque())
            dq.append((ts, dst_port))

    def ports_touched_in_window(self, src_ip: str, window_seconds: float) -> set:
        """Returns the set of distinct dst ports src_ip has touched in the
        last `window_seconds`. Also prunes old entries."""
        now = time.time()
        with self._lock:
            dq = self._port_touches.get(src_ip)
            if not dq:
                return set()
            while dq and now - dq[0][0] > window_seconds:
                dq.popleft()
            return {port for _, port in dq}

    def reap_stale(self, timeout=SESSION_TIMEOUT_SECONDS):
        now = time.time()
        with self._lock:
            stale = [k for k, s in self._sessions.items() if now - s.last_seen > timeout]
            for k in stale:
                del self._sessions[k]
            return len(stale)

    def all_sessions(self):
        with self._lock:
            return list(self._sessions.values())

    def count(self):
        with self._lock:
            return len(self._sessions)
