"""
scan_detector.py
-----------------
Module 2: detects network scans and DoS/DDoS precursors.

Three checks, all threshold-based (rules first, per the project plan):

  1. Port scan     — one source IP touching too many distinct dst ports
                      within a sliding window. Also classifies scan type
                      (SYN / FIN / NULL / XMAS) from TCP flag combinations,
                      since stealth scans use non-standard flag sets.

  2. SYN flood      — one source IP with too many half-open connections
                      (SYN sent, handshake never completed) within a window.
                      Tracked per (src_ip, dst_ip, dst_port) so we don't
                      need to correlate both directions of a session —
                      a SYN and its completing ACK share the same
                      (src_ip, dst_ip, dst_port) tuple.

  3. Open port exposure — periodic self-scan of localhost against a
                      whitelist of ports that are supposed to be listening.
                      Anything open outside the whitelist is flagged.

Wire this into the sniffer via on_packet(session, key, rec), the same
callback shape sniffer.py already expects.
"""

import os
import sys
import time
import socket
import threading
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "capture"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "reporting"))

from session_table import SessionTable          # noqa: E402
from alert import Alert, Severity                # noqa: E402


# ---- Tunable thresholds (move to config.py once these are validated) ----
PORT_SCAN_THRESHOLD = 15         # distinct dst ports from one src within window = scan
PORT_SCAN_WINDOW_SEC = 5.0

SYNFLOOD_THRESHOLD = 50          # half-open conns from one src within window = flood
SYNFLOOD_WINDOW_SEC = 10.0
SYN_PENDING_TIMEOUT_SEC = 30.0   # stop counting a half-open SYN as "pending" after this

ALERT_COOLDOWN_SEC = 20.0        # don't re-fire the same alert type for the same src this often


def classify_tcp_scan_flags(flags: str) -> str:
    """Classify a TCP flag combination into a scan technique name.
    Stealth scanners rarely use plain SYN — FIN/NULL/XMAS scans are
    designed to slip past naive firewalls, so worth tagging separately."""
    f = set(flags)
    if f == {"S"}:
        return "SYN"
    if f == {"F"}:
        return "FIN"
    if f == set():
        return "NULL"
    if f == {"F", "P", "U"}:
        return "XMAS"
    return "OTHER"


class ScanDetector:
    def __init__(
        self,
        table: SessionTable,
        port_scan_threshold=PORT_SCAN_THRESHOLD,
        port_scan_window=PORT_SCAN_WINDOW_SEC,
        synflood_threshold=SYNFLOOD_THRESHOLD,
        synflood_window=SYNFLOOD_WINDOW_SEC,
        alert_cooldown=ALERT_COOLDOWN_SEC,
        on_alert=None,
    ):
        self.table = table
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        self.synflood_threshold = synflood_threshold
        self.synflood_window = synflood_window
        self.alert_cooldown = alert_cooldown
        self.on_alert = on_alert  # callback(Alert) — e.g. push to dashboard/log

        self._lock = threading.Lock()

        # (src_ip, dst_ip, dst_port) -> timestamp of the SYN that opened it
        self._pending_syn: dict[tuple, float] = {}

        # per-src scan-type tally within current window, for reporting detail
        self._scan_flag_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

        # cooldown tracking: (src_ip, alert_type) -> last fired timestamp
        self._last_fired: dict[tuple, float] = {}

    # ---------------- packet ingestion ----------------

    def on_packet(self, session, key, rec):
        """Call this from the sniffer's on_packet hook for every packet seen."""
        src_ip, sport, dst_ip, dport, proto = key

        if proto != "TCP":
            return []

        alerts = []
        scan_type = classify_tcp_scan_flags(rec.flags)
        if scan_type != "OTHER":
            with self._lock:
                self._scan_flag_counts[src_ip][scan_type] += 1

        pending_key = (src_ip, dst_ip, dport)

        if rec.flags == "S":
            with self._lock:
                self._pending_syn[pending_key] = rec.timestamp
        elif rec.flags == "A":
            # pure ACK with no SYN flag completes a prior handshake
            with self._lock:
                self._pending_syn.pop(pending_key, None)

        port_alert = self._check_port_scan(src_ip)
        if port_alert:
            alerts.append(port_alert)

        flood_alert = self._check_syn_flood(src_ip)
        if flood_alert:
            alerts.append(flood_alert)

        for a in alerts:
            if self.on_alert:
                self.on_alert(a)

        return alerts

    # ---------------- checks ----------------

    def _cooldown_ok(self, src_ip, alert_type):
        now = time.time()
        last = self._last_fired.get((src_ip, alert_type), 0)
        if now - last < self.alert_cooldown:
            return False
        self._last_fired[(src_ip, alert_type)] = now
        return True

    def _check_port_scan(self, src_ip):
        touched = self.table.ports_touched_in_window(src_ip, self.port_scan_window)
        if len(touched) < self.port_scan_threshold:
            return None
        if not self._cooldown_ok(src_ip, "PORT_SCAN"):
            return None

        with self._lock:
            scan_types = dict(self._scan_flag_counts.get(src_ip, {}))

        dominant_type = max(scan_types, key=scan_types.get) if scan_types else "SYN"

        return Alert(
            alert_type="PORT_SCAN",
            src_ip=src_ip,
            severity=Severity.HIGH,
            message=(f"{src_ip} touched {len(touched)} distinct ports in "
                      f"{self.port_scan_window:.0f}s (likely {dominant_type} scan)"),
            details={
                "ports_touched": sorted(touched),
                "scan_type_breakdown": scan_types,
                "window_seconds": self.port_scan_window,
            },
        )

    def _check_syn_flood(self, src_ip):
        now = time.time()
        with self._lock:
            # count still-pending (unacked) SYNs from this src, within window,
            # and drop entries that have aged out past the timeout
            half_open = 0
            stale = []
            for (s_ip, d_ip, d_port), ts in self._pending_syn.items():
                if s_ip != src_ip:
                    continue
                if now - ts > SYN_PENDING_TIMEOUT_SEC:
                    stale.append((s_ip, d_ip, d_port))
                    continue
                if now - ts <= self.synflood_window:
                    half_open += 1
            for k in stale:
                del self._pending_syn[k]

        if half_open < self.synflood_threshold:
            return None
        if not self._cooldown_ok(src_ip, "SYN_FLOOD"):
            return None

        return Alert(
            alert_type="SYN_FLOOD",
            src_ip=src_ip,
            severity=Severity.CRITICAL,
            message=(f"{src_ip} has {half_open} half-open TCP connections in "
                      f"{self.synflood_window:.0f}s (possible SYN flood / DoS)"),
            details={"half_open_count": half_open, "window_seconds": self.synflood_window},
        )


# ---------------- open port exposure (standalone, not per-packet) ----------------

class OpenPortMonitor:
    """Periodically checks localhost's open TCP ports against a whitelist.
    Runs independently of the packet stream — this is active probing,
    not passive capture."""

    def __init__(self, allowed_ports: set[int], port_range=(1, 1024), on_alert=None):
        self.allowed_ports = set(allowed_ports)
        self.port_range = port_range
        self.on_alert = on_alert

    def scan_localhost(self) -> set[int]:
        """Lightweight TCP connect scan of localhost. For a real device
        this range should be widened / made async — a full 1-65535 sweep
        with blocking connect() is too slow for periodic use as-is."""
        open_ports = set()
        for port in range(self.port_range[0], self.port_range[1] + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.05)
            try:
                result = sock.connect_ex(("127.0.0.1", port))
                if result == 0:
                    open_ports.add(port)
            finally:
                sock.close()
        return open_ports

    def check(self):
        open_ports = self.scan_localhost()
        unexpected = open_ports - self.allowed_ports
        if not unexpected:
            return None

        alert = Alert(
            alert_type="UNEXPECTED_OPEN_PORT",
            src_ip="127.0.0.1",
            severity=Severity.MEDIUM,
            message=f"Unexpected open ports detected: {sorted(unexpected)}",
            details={"unexpected_ports": sorted(unexpected), "all_open": sorted(open_ports)},
        )
        if self.on_alert:
            self.on_alert(alert)
        return alert
