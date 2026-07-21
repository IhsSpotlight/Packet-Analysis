"""
alert_manager.py
-----------------
Sits between the detectors and the outside world (dashboard, log file).
Both ScanDetector and HijackDetector should be constructed with
on_alert=alert_manager.ingest, so every alert — regardless of which
module produced it — flows through one place for storage, stats, and
broadcast.

Deliberately transport-agnostic: it doesn't know about Flask or
SocketIO. subscribe() takes any callback; main.py wires a SocketIO
emit function in as the subscriber.
"""

import json
import os
import threading
import time
from collections import deque, Counter

from alert import Alert, Severity


DEFAULT_HISTORY_SIZE = 500


class AlertManager:
    def __init__(self, history_size=DEFAULT_HISTORY_SIZE, log_path=None):
        self._lock = threading.Lock()
        self._history = deque(maxlen=history_size)
        self._counts_by_type = Counter()
        self._counts_by_severity = Counter()
        self._subscribers = []
        self.log_path = log_path

        if self.log_path:
            os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)

    def subscribe(self, callback):
        """callback(alert: Alert) is invoked on every ingested alert."""
        self._subscribers.append(callback)

    def ingest(self, alert: Alert):
        """Entry point detectors call (directly, or via on_alert=...)."""
        with self._lock:
            self._history.append(alert)
            self._counts_by_type[alert.alert_type] += 1
            self._counts_by_severity[alert.severity.value] += 1

        if self.log_path:
            self._append_log(alert)

        for cb in self._subscribers:
            try:
                cb(alert)
            except Exception as e:
                # a broken dashboard subscriber should never take down detection
                print(f"[alert_manager] subscriber error: {e}")

    def _append_log(self, alert: Alert):
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(alert.to_dict()) + "\n")
        except OSError as e:
            print(f"[alert_manager] failed to write log: {e}")

    def recent(self, n=50):
        with self._lock:
            items = list(self._history)[-n:]
        items.reverse()  # newest first, matches how a live feed should read
        return items

    def stats(self):
        with self._lock:
            return {
                "total": len(self._history),
                "by_type": dict(self._counts_by_type),
                "by_severity": dict(self._counts_by_severity),
            }
