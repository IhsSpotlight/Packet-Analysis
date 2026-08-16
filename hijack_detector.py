"""
hijack_detector.py
-------------------
Module 1: detects TCP session hijacking / spoofing within an already-
established session. Four rule-based signals, run per-packet:

  1. TTL anomaly        — baseline TTL is locked on the session's first
                           packet (session_table.py already does this).
                           A later packet claiming to be the same peer
                           but arriving with a very different TTL suggests
                           it actually came from a different host/hop
                           distance — classic spoofing tell.

  2. Sequence anomaly    — an unexplained large jump (or backward jump)
                           in TCP sequence numbers within a session, not
                           consistent with normal retransmission, suggests
                           an attacker injecting packets into the stream.

  3. Mid-session MAC swap — on a local segment, if the source MAC for an
                           "existing" session suddenly changes, someone
                           else is now sending packets claiming that
                           session's IP (ARP spoofing / takeover).

  4. RST / duplicate-ACK storm — a burst of RSTs or repeated identical
                           ACKs on a session is the classic signature of
                           two hosts racing to control the same TCP
                           connection (attacker vs. legitimate peer).

Same wiring pattern as scan_detector.py: on_packet(session, key, rec)
matches what sniffer.py's callback already provides.
"""

import os
import sys
import time
import threading
from collections import deque

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "capture"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "reporting"))

from session_table import SessionTable          # noqa: E402
from alert import Alert, Severity                # noqa: E402


# ---- Tunable thresholds (move to config.py once validated on real traffic) ----
TTL_VARIANCE_THRESHOLD = 5          # max allowed TTL drift from session baseline

SEQ_JUMP_THRESHOLD = 500_000        # unexplained seq delta this large = suspicious
SEQ_BACKWARD_GRACE = 5_000          # small backward moves are normal (retransmits)

RST_STORM_THRESHOLD = 5             # RSTs within window = storm
RST_STORM_WINDOW_SEC = 5.0

DUP_ACK_THRESHOLD = 4               # identical ACK repeated this many times = storm
DUP_ACK_WINDOW_SEC = 5.0

ALERT_COOLDOWN_SEC = 20.0


class HijackDetector:
    def __init__(
        self,
        table: SessionTable,
        ttl_variance=TTL_VARIANCE_THRESHOLD,
        seq_jump_threshold=SEQ_JUMP_THRESHOLD,
        rst_storm_threshold=RST_STORM_THRESHOLD,
        rst_storm_window=RST_STORM_WINDOW_SEC,
        dup_ack_threshold=DUP_ACK_THRESHOLD,
        dup_ack_window=DUP_ACK_WINDOW_SEC,
        alert_cooldown=ALERT_COOLDOWN_SEC,
        on_alert=None,
    ):
        self.table = table
        self.ttl_variance = ttl_variance
        self.seq_jump_threshold = seq_jump_threshold
        self.rst_storm_threshold = rst_storm_threshold
        self.rst_storm_window = rst_storm_window
        self.dup_ack_threshold = dup_ack_threshold
        self.dup_ack_window = dup_ack_window
        self.alert_cooldown = alert_cooldown
        self.on_alert = on_alert

        self._lock = threading.Lock()

        # per-session running state, keyed by (session_key, generation) —
        # see _gkey() below for why generation matters
        self._last_seq: dict[tuple, int] = {}
        self._rst_times: dict[tuple, deque] = {}
        self._last_ack: dict[tuple, tuple[int, deque]] = {}  # ack_val -> deque of timestamps it repeated at

        self._last_fired: dict[tuple, float] = {}  # (key, alert_type) -> timestamp

    # ---------------- packet ingestion ----------------

    def on_packet(self, session, key, rec):
        """Call this from the sniffer's on_packet hook for every packet seen."""
        src_ip, sport, dst_ip, dport, proto = key
        if proto != "TCP":
            return []

        alerts = []

        a = self._check_ttl(session, key, rec)
        if a:
            alerts.append(a)

        a = self._check_mac(session, key, rec)
        if a:
            alerts.append(a)

        a = self._check_seq(session, key, rec)
        if a:
            alerts.append(a)

        a = self._check_rst_storm(session, key, rec)
        if a:
            alerts.append(a)

        a = self._check_dup_ack(session, key, rec)
        if a:
            alerts.append(a)

        for alert in alerts:
            if self.on_alert:
                self.on_alert(alert)

        return alerts

    # ---------------- helpers ----------------

    def _cooldown_ok(self, key, alert_type):
        now = time.time()
        last = self._last_fired.get((key, alert_type), 0)
        if now - last < self.alert_cooldown:
            return False
        self._last_fired[(key, alert_type)] = now
        return True

    @staticmethod
    def _gkey(session, key):
        """Generation-scoped key: when session_table.py detects a session
        key got reused by a genuinely new connection (bare SYN after a
        completed handshake), it bumps session.generation. Folding that
        into the dict key here means our internal seq/RST/dup-ACK
        trackers automatically start fresh for the new connection instead
        of comparing it against the old, unrelated connection's state."""
        return (key, session.generation)

    # ---------------- checks ----------------

    def _check_ttl(self, session, key, rec):
        if session.baseline_ttl is None or rec.ttl is None:
            return None
        drift = abs(rec.ttl - session.baseline_ttl)
        if drift <= self.ttl_variance:
            return None
        if not self._cooldown_ok(key, "TTL_ANOMALY"):
            return None

        return Alert(
            alert_type="TTL_ANOMALY",
            src_ip=key[0],
            severity=Severity.HIGH,
            message=(f"TTL drift of {drift} on session {key} "
                     f"(baseline={session.baseline_ttl}, observed={rec.ttl}) — "
                     f"possible spoofed packet"),
            details={"baseline_ttl": session.baseline_ttl, "observed_ttl": rec.ttl,
                      "session_key": key},
        )

    def _check_mac(self, session, key, rec):
        if session.baseline_mac is None or rec.src_mac is None:
            return None
        if rec.src_mac == session.baseline_mac:
            return None
        if not self._cooldown_ok(key, "MAC_SWAP"):
            return None

        return Alert(
            alert_type="MAC_SWAP",
            src_ip=key[0],
            severity=Severity.CRITICAL,
            message=(f"Source MAC changed mid-session on {key} "
                     f"(baseline={session.baseline_mac}, observed={rec.src_mac}) — "
                     f"possible ARP spoofing / session takeover"),
            details={"baseline_mac": session.baseline_mac, "observed_mac": rec.src_mac,
                      "session_key": key},
        )

    def _check_seq(self, session, key, rec):
        if rec.seq is None:
            return None

        gkey = self._gkey(session, key)
        with self._lock:
            last_seq = self._last_seq.get(gkey)
            self._last_seq[gkey] = rec.seq

        if last_seq is None:
            return None  # first packet, nothing to compare against yet

        delta = rec.seq - last_seq

        # forward jump too large to be a normal next-segment seq number
        if delta > self.seq_jump_threshold:
            anomaly = "forward"
        # backward jump beyond typical retransmit slack — could be injected/replayed
        elif delta < -SEQ_BACKWARD_GRACE:
            anomaly = "backward"
        else:
            return None

        if not self._cooldown_ok(key, "SEQ_ANOMALY"):
            return None

        return Alert(
            alert_type="SEQ_ANOMALY",
            src_ip=key[0],
            severity=Severity.HIGH,
            message=(f"Unexplained {anomaly} sequence jump of {delta} on session {key} "
                     f"— possible packet injection"),
            details={"last_seq": last_seq, "observed_seq": rec.seq, "delta": delta,
                      "direction": anomaly, "session_key": key},
        )

    def _check_rst_storm(self, session, key, rec):
        if "R" not in rec.flags:
            return None

        gkey = self._gkey(session, key)
        now = rec.timestamp
        with self._lock:
            dq = self._rst_times.setdefault(gkey, deque())
            dq.append(now)
            while dq and now - dq[0] > self.rst_storm_window:
                dq.popleft()
            count = len(dq)

        if count < self.rst_storm_threshold:
            return None
        if not self._cooldown_ok(key, "RST_STORM"):
            return None

        return Alert(
            alert_type="RST_STORM",
            src_ip=key[0],
            severity=Severity.HIGH,
            message=(f"{count} RSTs on session {key} within {self.rst_storm_window:.0f}s "
                     f"— possible hijack race condition"),
            details={"rst_count": count, "window_seconds": self.rst_storm_window,
                      "session_key": key},
        )

    def _check_dup_ack(self, session, key, rec):
        if rec.flags != "A" or rec.ack is None:
            return None

        gkey = self._gkey(session, key)
        now = rec.timestamp
        with self._lock:
            prev = self._last_ack.get(gkey)
            if prev is None or prev[0] != rec.ack:
                # new ACK value — reset the repeat tracker
                self._last_ack[gkey] = (rec.ack, deque([now]))
                return None

            ack_val, dq = prev
            dq.append(now)
            while dq and now - dq[0] > self.dup_ack_window:
                dq.popleft()
            count = len(dq)

        if count < self.dup_ack_threshold:
            return None
        if not self._cooldown_ok(key, "DUP_ACK_STORM"):
            return None

        return Alert(
            alert_type="DUP_ACK_STORM",
            src_ip=key[0],
            severity=Severity.MEDIUM,
            message=(f"ACK {rec.ack} repeated {count}x on session {key} within "
                     f"{self.dup_ack_window:.0f}s — possible hijack race condition"),
            details={"ack_value": rec.ack, "repeat_count": count, "session_key": key},
        )
