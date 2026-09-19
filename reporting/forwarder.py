"""
forwarder.py
------------
Sensor-side component: ships alerts, periodic flow snapshots, and
discovered-host batches to the central SOC server's ingestion API. If
the SOC server is unreachable, each channel buffers locally to disk and
retries on the next flush — nothing should be silently dropped just
because the network to the SOC server blipped.

Three independent channels (alerts / flows / discovery), each with its
own queue and endpoint, but sharing one buffer file and one flush cycle
for simplicity. Deliberately decoupled from AlertManager/SessionTable/
DiscoveryScanner: callers just call enqueue_*() from wherever that data
already gets produced — this module doesn't know or care where it came
from.
"""

import json
import os
import threading
import time
import urllib.error
import urllib.request

from alert import Alert


DEFAULT_FLUSH_INTERVAL_SEC = 10
DEFAULT_BATCH_SIZE = 100
REQUEST_TIMEOUT_SEC = 5

CHANNELS = {
    "alerts": "/api/ingest/alerts",
    "flows": "/api/ingest/flow-snapshot",
    "discovery": "/api/ingest/discovery",
}
# the JSON body key each endpoint expects its batch under
BODY_KEY = {"alerts": "alerts", "flows": "flows", "discovery": "hosts"}


class Forwarder:
    def __init__(self, soc_url: str, api_key: str, buffer_path: str,
                 flush_interval=DEFAULT_FLUSH_INTERVAL_SEC, batch_size=DEFAULT_BATCH_SIZE,
                 post_fn=None):
        self.soc_url = soc_url.rstrip("/")
        self.api_key = api_key
        self.buffer_path = buffer_path
        self.flush_interval = flush_interval
        self.batch_size = batch_size
        # post_fn is injectable for testing — default does a real HTTP POST
        self.post_fn = post_fn or self._http_post

        self._lock = threading.Lock()
        self._queues: dict[str, list[dict]] = {"alerts": [], "flows": [], "discovery": []}
        self._load_buffer()

    # ---------------- enqueue (called from wherever the data is produced) ----------------

    def enqueue(self, alert: Alert):
        """Kept as the original method name/signature — AlertManager
        subscribes to this directly, same as before."""
        self._enqueue("alerts", alert.to_dict())

    def enqueue_flows(self, flow_stats_list: list[dict]):
        with self._lock:
            self._queues["flows"].extend(flow_stats_list)
            self._save_buffer_locked()

    def enqueue_discovery(self, hosts: list[dict]):
        with self._lock:
            self._queues["discovery"].extend(hosts)
            self._save_buffer_locked()

    def _enqueue(self, channel: str, item: dict):
        with self._lock:
            self._queues[channel].append(item)
            self._save_buffer_locked()

    # ---------------- persistence ----------------

    def _load_buffer(self):
        if os.path.exists(self.buffer_path):
            try:
                with open(self.buffer_path) as f:
                    loaded = json.load(f)
                for channel in self._queues:
                    self._queues[channel] = loaded.get(channel, [])
            except (json.JSONDecodeError, OSError):
                pass

    def _save_buffer_locked(self):
        os.makedirs(os.path.dirname(self.buffer_path) or ".", exist_ok=True)
        with open(self.buffer_path, "w") as f:
            json.dump(self._queues, f)

    # ---------------- sending ----------------

    def _http_post(self, path: str, payload: dict) -> bool:
        """Returns True on success (2xx), False on any failure. Never
        raises — a forwarder failure must not take down the sensor."""
        url = f"{self.soc_url}{path}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SEC) as resp:
                return 200 <= resp.status < 300
        except (urllib.error.URLError, TimeoutError, OSError):
            return False

    def _flush_channel(self, channel: str) -> int:
        with self._lock:
            queue = self._queues[channel]
            if not queue:
                return 0
            batch = queue[:self.batch_size]

        ok = self.post_fn(CHANNELS[channel], {BODY_KEY[channel]: batch})

        if ok:
            with self._lock:
                self._queues[channel] = self._queues[channel][len(batch):]
                self._save_buffer_locked()
            return len(batch)
        return 0

    def flush(self) -> int:
        """Attempts to send everything currently queued, across all three
        channels. Each channel succeeds/fails independently — a flow
        snapshot outage doesn't block alerts from going out, and vice
        versa. Returns the total item count successfully sent across all
        channels (kept as a single int for backward compatibility with
        existing alert-only callers/tests; use pending_counts() for a
        per-channel breakdown)."""
        return sum(self._flush_channel(ch) for ch in self._queues)

    def pending_count(self) -> int:
        with self._lock:
            return sum(len(q) for q in self._queues.values())

    def pending_counts(self) -> dict:
        with self._lock:
            return {ch: len(q) for ch, q in self._queues.items()}


def start_forwarder_thread(forwarder: Forwarder, interval=None):
    interval = interval or forwarder.flush_interval

    def loop():
        while True:
            time.sleep(interval)
            try:
                forwarder.flush()
            except Exception as e:
                print(f"[forwarder] flush error: {e}")

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t
