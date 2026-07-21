"""
session_table.py
-----------------
In-memory session tracker. Every packet the sniffer sees gets folded into
a Session object keyed by the 5-tuple (src_ip, src_port, dst_ip, dst_port, proto).

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


# How much history to keep per session before trimming (memory bound)
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
    key: tuple                       # (src_ip, sport, dst_ip, dport, proto)
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

    def add_packet(self, rec: PacketRecord):
        self.packets.append(rec)
        self.last_seen = rec.timestamp

        if self.baseline_ttl is None and rec.ttl is not None:
            self.baseline_ttl = rec.ttl
        if self.baseline_mac is None and rec.src_mac is not None:
            self.baseline_mac = rec.src_mac

        if "S" in rec.flags and "A" not in rec.flags:
            self.syn_count += 1
        if "S" in rec.flags and "A" in rec.flags:
            self.synack_count += 1
        if "R" in rec.flags:
            self.rst_count += 1


class SessionTable:
    """Thread-safe store of active Session objects."""

    def __init__(self):
        self._sessions: dict[tuple, Session] = {}
        self._lock = threading.Lock()

        # secondary index for scan_detector: source_ip -> set of dst ports touched,
        # each entry timestamped so we can apply a sliding window.
        self._port_touches: dict[str, deque] = {}

    @staticmethod
    def make_key(src_ip, sport, dst_ip, dport, proto):
        # Session identity should be direction-agnostic for hijack purposes,
        # but scan detection cares about the *initiator*, so we keep the
        # literal tuple here and normalize where needed by the caller.
        return (src_ip, sport, dst_ip, dport, proto)

    def get_or_create(self, key) -> Session:
        with self._lock:
            sess = self._sessions.get(key)
            if sess is None:
                sess = Session(key=key)
                self._sessions[key] = sess
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
