"""
test_discovery.py
------------------
Run: python3 test_discovery.py

Tests the registry + diff logic only — scan_subnet() needs root/scapy on a
real NIC and isn't exercised here, same as sniffer.py's live capture path.
"""

import os
import tempfile

from discovery import AssetRegistry, DiscoveryScanner


def test_registry_add_and_is_registered():
    with tempfile.TemporaryDirectory() as tmp:
        reg = AssetRegistry(os.path.join(tmp, "assets.json"))
        reg.add("192.168.1.50", "AA:BB:CC:DD:EE:FF", label="Alice's laptop")

        assert reg.is_registered("192.168.1.50", "aa:bb:cc:dd:ee:ff") is True  # case-insensitive
        assert reg.is_registered("192.168.1.99", "11:22:33:44:55:66") is False
        print("PASS: test_registry_add_and_is_registered")


def test_registry_persists_across_instances():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "assets.json")
        reg1 = AssetRegistry(path)
        reg1.add("10.0.0.5", "11:11:11:11:11:11", label="Printer")

        reg2 = AssetRegistry(path)  # fresh instance, same file
        assert reg2.is_registered("10.0.0.5", "11:11:11:11:11:11") is True
        print("PASS: test_registry_persists_across_instances")


def test_registry_add_replaces_existing_mac():
    with tempfile.TemporaryDirectory() as tmp:
        reg = AssetRegistry(os.path.join(tmp, "assets.json"))
        reg.add("10.0.0.5", "11:11:11:11:11:11", label="old label")
        reg.add("10.0.0.6", "11:11:11:11:11:11", label="new label")  # IP changed (DHCP), same device

        entries = reg.list()
        assert len(entries) == 1, "re-adding the same MAC should replace, not duplicate"
        assert entries[0]["ip"] == "10.0.0.6"
        assert entries[0]["label"] == "new label"
        print("PASS: test_registry_add_replaces_existing_mac")


def test_registry_remove():
    with tempfile.TemporaryDirectory() as tmp:
        reg = AssetRegistry(os.path.join(tmp, "assets.json"))
        reg.add("10.0.0.5", "11:11:11:11:11:11")
        assert reg.remove("11:11:11:11:11:11") is True
        assert reg.is_registered("10.0.0.5", "11:11:11:11:11:11") is False
        assert reg.remove("22:22:22:22:22:22") is False  # wasn't there
        print("PASS: test_registry_remove")


def test_unregistered_device_flagged():
    with tempfile.TemporaryDirectory() as tmp:
        reg = AssetRegistry(os.path.join(tmp, "assets.json"))
        reg.add("192.168.1.10", "aa:aa:aa:aa:aa:aa", label="Known laptop")

        fired = []
        scanner = DiscoveryScanner(reg, network_id="hr-net", on_alert=lambda a: fired.append(a))

        discovered = [
            {"ip": "192.168.1.10", "mac": "aa:aa:aa:aa:aa:aa", "vendor": "Dell"},   # registered
            {"ip": "192.168.1.66", "mac": "bb:bb:bb:bb:bb:bb", "vendor": "Unknown"},  # NOT registered
        ]
        alerts = scanner.diff_and_alert(discovered)

        assert len(alerts) == 1
        assert alerts[0].alert_type == "UNREGISTERED_DEVICE"
        assert alerts[0].src_ip == "192.168.1.66"
        assert alerts[0].network_id == "hr-net"
        assert len(fired) == 1
        print("PASS: test_unregistered_device_flagged")


def test_no_alert_when_all_registered():
    with tempfile.TemporaryDirectory() as tmp:
        reg = AssetRegistry(os.path.join(tmp, "assets.json"))
        reg.add("192.168.1.10", "aa:aa:aa:aa:aa:aa")
        reg.add("192.168.1.11", "bb:bb:bb:bb:bb:bb")

        scanner = DiscoveryScanner(reg)
        discovered = [
            {"ip": "192.168.1.10", "mac": "aa:aa:aa:aa:aa:aa"},
            {"ip": "192.168.1.11", "mac": "bb:bb:bb:bb:bb:bb"},
        ]
        alerts = scanner.diff_and_alert(discovered)
        assert alerts == []
        print("PASS: test_no_alert_when_all_registered")


def test_unregistered_device_cooldown():
    with tempfile.TemporaryDirectory() as tmp:
        reg = AssetRegistry(os.path.join(tmp, "assets.json"))
        scanner = DiscoveryScanner(reg, cooldown=3600)

        host = [{"ip": "192.168.1.66", "mac": "bb:bb:bb:bb:bb:bb"}]
        first = scanner.diff_and_alert(host)
        second = scanner.diff_and_alert(host)  # same scan cycle repeated immediately

        assert len(first) == 1
        assert len(second) == 0, "cooldown should suppress re-alerting the same unknown device"
        print("PASS: test_unregistered_device_cooldown")


if __name__ == "__main__":
    test_registry_add_and_is_registered()
    test_registry_persists_across_instances()
    test_registry_add_replaces_existing_mac()
    test_registry_remove()
    test_unregistered_device_flagged()
    test_no_alert_when_all_registered()
    test_unregistered_device_cooldown()
    print("\nAll discovery tests passed.")
