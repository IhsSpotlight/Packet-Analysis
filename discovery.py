"""
discovery.py
------------
Sub-network scanning and device registration, per the enterprise design:
each network's senior user should be able to see what's actually on their
subnet and maintain a registry of authorized devices — anything present
but not registered gets flagged.

Two pieces, deliberately separable:

  AssetRegistry   — persistent (JSON file) list of devices a senior user
                    has explicitly approved for this network. Matches
                    primarily by MAC (IP can shift under DHCP).

  DiscoveryScanner — does the actual subnet sweep (ARP request/reply via
                    scapy — needs root, same as sniffer.py) and diffs the
                    live host list against the registry, emitting
                    UNREGISTERED_DEVICE alerts through the same Alert
                    pipeline every other detector uses.

The diff logic is intentionally decoupled from the scan itself so it's
unit-testable without root/scapy — same pattern as sniffer.py.
"""

import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "reporting"))

from alert import Alert, Severity


UNREGISTERED_ALERT_COOLDOWN_SEC = 3600  # don't re-alert on the same unknown device every scan cycle


class AssetRegistry:
    """Persistent registry of devices approved for one network. Backed by
    a plain JSON file — no DB dependency needed for a single sensor."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._assets: list[dict] = []
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    self._assets = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._assets = []
        else:
            self._assets = []

    def _save(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(self._assets, f, indent=2)

    def add(self, ip: str, mac: str, label: str = "") -> dict:
        with self._lock:
            entry = {"ip": ip, "mac": mac.lower(), "label": label, "added_at": time.time()}
            # replace any existing entry for this MAC rather than duplicating
            self._assets = [a for a in self._assets if a["mac"] != entry["mac"]]
            self._assets.append(entry)
            self._save()
            return entry

    def remove(self, mac: str) -> bool:
        with self._lock:
            before = len(self._assets)
            self._assets = [a for a in self._assets if a["mac"] != mac.lower()]
            if len(self._assets) != before:
                self._save()
                return True
            return False

    def is_registered(self, ip: str, mac: str) -> bool:
        mac = (mac or "").lower()
        with self._lock:
            return any(a["mac"] == mac for a in self._assets)

    def list(self) -> list[dict]:
        with self._lock:
            return list(self._assets)


class DiscoveryScanner:
    """Diffs a discovered-host list against an AssetRegistry and raises
    UNREGISTERED_DEVICE alerts for anything unrecognized. The actual
    subnet sweep (scan_subnet) needs scapy + root; diff_and_alert() takes
    a plain list so it's testable without either."""

    def __init__(self, registry: AssetRegistry, network_id: str | None = None,
                 cooldown=UNREGISTERED_ALERT_COOLDOWN_SEC, on_alert=None):
        self.registry = registry
        self.network_id = network_id
        self.cooldown = cooldown
        self.on_alert = on_alert
        self._last_fired: dict[str, float] = {}  # mac -> last alert timestamp

    def _cooldown_ok(self, mac: str) -> bool:
        now = time.time()
        last = self._last_fired.get(mac, 0)
        if now - last < self.cooldown:
            return False
        self._last_fired[mac] = now
        return True

    def diff_and_alert(self, discovered_hosts: list[dict]) -> list[Alert]:
        """discovered_hosts: list of {"ip": ..., "mac": ..., "vendor": ...}
        as produced by scan_subnet(). Returns (and emits via on_alert) one
        UNREGISTERED_DEVICE alert per newly-seen unregistered device."""
        alerts = []
        for host in discovered_hosts:
            ip, mac = host.get("ip"), host.get("mac")
            if not ip or not mac:
                continue
            if self.registry.is_registered(ip, mac):
                continue
            if not self._cooldown_ok(mac.lower()):
                continue

            alert = Alert(
                alert_type="UNREGISTERED_DEVICE",
                src_ip=ip,
                severity=Severity.MEDIUM,
                message=(f"Unregistered device on network: {ip} ({mac}"
                         f"{', ' + host['vendor'] if host.get('vendor') else ''}) — "
                         f"not in the approved asset list"),
                details={"ip": ip, "mac": mac, "vendor": host.get("vendor")},
                network_id=self.network_id,
            )
            alerts.append(alert)
            if self.on_alert:
                self.on_alert(alert)
        return alerts

    def scan_subnet(self, cidr: str, timeout=3) -> list[dict]:
        """ARP sweep of `cidr` (e.g. '192.168.1.0/24'). Requires root and
        scapy — this is the live-network path, not exercised in tests."""
        from scapy.all import ARP, Ether, srp

        arp = ARP(pdst=cidr)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered, _ = srp(ether / arp, timeout=timeout, verbose=False)

        hosts = []
        for _, received in answered:
            hosts.append({"ip": received.psrc, "mac": received.hwsrc, "vendor": None})
        return hosts


def start_discovery_thread(scanner: DiscoveryScanner, cidr: str, interval_sec=300):
    """Runs scan_subnet + diff_and_alert on a timer, in a background thread."""
    def loop():
        while True:
            try:
                hosts = scanner.scan_subnet(cidr)
                scanner.diff_and_alert(hosts)
            except Exception as e:
                print(f"[discovery] scan failed: {e}")
            time.sleep(interval_sec)
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t
