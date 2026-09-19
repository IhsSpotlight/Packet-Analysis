"""
main.py
-------
Wires the whole pipeline together:

    sniffer.py  --packets-->  SessionTable
                                   |
                    +--------------+--------------+
                    |                             |
              ScanDetector                 HijackDetector
                    |                             |
                    +--------------+--------------+
                                   |
                             AlertManager  ----(log file)
                                   |
                             SocketIO  ----> dashboard/ (cyber-green UI)

Two run modes:

  --iface eth0     Live capture. Requires root/CAP_NET_RAW. Use this on
                    your actual machine, not in a sandboxed container.

  --demo           No NIC access needed. Runs a synthetic traffic
                    generator (normal traffic + a simulated port scan +
                    a simulated SYN flood + a simulated session hijack)
                    through the exact same SessionTable/detector/alert
                    pipeline, so you can verify the dashboard and rule
                    logic end-to-end before touching real hardware.

Usage:
    sudo python3 main.py --iface eth0
    python3 main.py --demo
"""

import argparse
import os
import random
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "capture"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "detectors"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "reporting"))

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO

from session_table import SessionTable, PacketRecord     # noqa: E402
from scan_detector import ScanDetector, OpenPortMonitor    # noqa: E402
from hijack_detector import HijackDetector                 # noqa: E402
from discovery import AssetRegistry, DiscoveryScanner, start_discovery_thread  # noqa: E402
from alert_manager import AlertManager                     # noqa: E402
from alert import Alert                                    # noqa: E402
from ip_lookup import get_ip_info                           # noqa: E402
from forwarder import Forwarder, start_forwarder_thread     # noqa: E402


OPEN_PORT_WHITELIST = {22, 80, 443, 5000}   # adjust to what SHOULD be listening on your device
OPEN_PORT_CHECK_INTERVAL_SEC = 60


def build_app(mode: str, iface_label: str, network_id: str = "default-net",
              soc_url: str | None = None, soc_api_key: str | None = None):
    app = Flask(__name__, template_folder="dashboard/templates", static_folder="dashboard/static")
    app.config["SECRET_KEY"] = "sentinel-dev"  # fine for a local research tool; rotate before any real deployment
    socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

    table = SessionTable(network_id=network_id)
    alert_mgr = AlertManager(log_path=os.path.join(os.path.dirname(__file__), "logs", "alerts.log"))
    registry = AssetRegistry(os.path.join(os.path.dirname(__file__), "logs", "assets.json"))

    def tag_and_ingest(alert: Alert):
        """Every alert, regardless of which detector raised it, gets
        stamped with this sensor's network_id before it enters the
        pipeline — this is the tenancy boundary the multi-network design
        relies on (see sentinel-enterprise-system-design.md)."""
        alert.network_id = network_id
        alert_mgr.ingest(alert)

    def broadcast_alert(alert: Alert):
        socketio.emit("new_alert", alert.to_dict())
        socketio.emit("stats_update", {"stats": alert_mgr.stats(), "session_count": table.count()})

    alert_mgr.subscribe(broadcast_alert)

    forwarder = None
    if soc_url and soc_api_key:
        # Forwarder subscribes the same way the dashboard broadcast does —
        # the sensor's local dashboard/log keep working identically whether
        # or not a SOC server is configured; this is purely additive.
        forwarder = Forwarder(
            soc_url, soc_api_key,
            buffer_path=os.path.join(os.path.dirname(__file__), "logs", "forwarder_buffer.json"),
        )
        alert_mgr.subscribe(forwarder.enqueue)

    scan_detector = ScanDetector(table, on_alert=tag_and_ingest)
    hijack_detector = HijackDetector(table, on_alert=tag_and_ingest)
    open_port_monitor = OpenPortMonitor(allowed_ports=OPEN_PORT_WHITELIST, on_alert=tag_and_ingest)
    discovery_scanner = DiscoveryScanner(registry, network_id=network_id, on_alert=tag_and_ingest)

    def on_packet(session, key, rec):
        scan_detector.on_packet(session, key, rec)
        hijack_detector.on_packet(session, key, rec)

    @app.route("/")
    def index():
        return render_template("index.html", mode=mode, iface=iface_label, network_id=network_id)

    @app.route("/api/ip-info/<ip>")
    def ip_info(ip):
        return jsonify(get_ip_info(ip))

    @app.route("/api/assets", methods=["GET"])
    def list_assets():
        return jsonify(registry.list())

    @app.route("/api/assets", methods=["POST"])
    def add_asset():
        data = request.get_json(force=True) or {}
        ip, mac = data.get("ip"), data.get("mac")
        if not ip or not mac:
            return jsonify({"error": "ip and mac are required"}), 400
        entry = registry.add(ip, mac, label=data.get("label", ""))
        return jsonify(entry), 201

    @app.route("/api/assets/<mac>", methods=["DELETE"])
    def remove_asset(mac):
        removed = registry.remove(mac)
        return jsonify({"removed": removed})

    @socketio.on("connect")
    def handle_connect():
        socketio.emit("init_state", {
            "recent_alerts": [a.to_dict() for a in alert_mgr.recent(50)],
            "stats": alert_mgr.stats(),
            "session_count": table.count(),
        })

    return app, socketio, table, on_packet, open_port_monitor, alert_mgr, discovery_scanner, registry, forwarder


def start_reaper_thread(table: SessionTable, interval=30):
    def loop():
        while True:
            time.sleep(interval)
            table.reap_stale()
    t = threading.Thread(target=loop, daemon=True)
    t.start()


def start_open_port_monitor_thread(monitor: OpenPortMonitor, interval=OPEN_PORT_CHECK_INTERVAL_SEC):
    def loop():
        while True:
            monitor.check()
            time.sleep(interval)
    t = threading.Thread(target=loop, daemon=True)
    t.start()


def start_flow_snapshot_thread(table: SessionTable, forwarder, interval=60):
    """Periodically samples every active flow's flow_stats() and enqueues
    them for forwarding — this is what actually feeds the SOC server's
    flow_snapshots table (and, downstream, the ML anomaly layer). Without
    this thread, Session.flow_stats() computes real data that nothing
    ever reads."""
    def loop():
        while True:
            time.sleep(interval)
            sessions = table.all_sessions()
            if sessions:
                forwarder.enqueue_flows([s.flow_stats() for s in sessions])
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t


# ---------------- demo traffic generator ----------------

def _make_rec(flags, seq=1000, ack=0, ttl=64, mac="aa:bb:cc:dd:ee:ff"):
    return PacketRecord(timestamp=time.time(), seq=seq, ack=ack, ttl=ttl,
                         flags=flags, src_mac=mac, length=random.randint(60, 1500))


def _feed(table, on_packet, src_ip, dst_ip, dport, flags, **kwargs):
    key = table.make_key(src_ip, random.randint(40000, 60000), dst_ip, dport, "TCP")
    session = table.get_or_create(key)
    rec = _make_rec(flags, **kwargs)
    session.add_packet(rec, key)
    table.record_port_touch(src_ip, dport, rec.timestamp)
    on_packet(session, key, rec)


def run_demo_traffic(table, on_packet, stop_event):
    """Continuously generates: background normal traffic, plus periodic
    bursts simulating a port scan, a SYN flood, and a session hijack —
    so every module in the dashboard lights up within the first minute."""
    normal_hosts = [f"192.168.1.{n}" for n in (10, 12, 15, 20)]
    server = "10.0.0.1"

    scenario_tick = 0

    while not stop_event.is_set():
        # background normal traffic
        for host in normal_hosts:
            port = random.choice([80, 443, 22])
            _feed(table, on_packet, host, server, port, "S")
            _feed(table, on_packet, host, server, port, "A")

        scenario_tick += 1

        if scenario_tick % 8 == 0:
            attacker = "10.0.0.66"
            for port in range(2000, 2030):
                _feed(table, on_packet, attacker, server, port, "S")

        if scenario_tick % 11 == 0:
            attacker = "10.0.0.77"
            for port in range(3000, 3060):
                _feed(table, on_packet, attacker, server, port, "S")

        if scenario_tick % 14 == 0:
            victim = "192.168.1.10"
            _feed(table, on_packet, victim, server, 443, "S", seq=1000, ttl=64,
                  mac="aa:aa:aa:aa:aa:aa")
            _feed(table, on_packet, victim, server, 443, "PA", seq=1100, ttl=64,
                  mac="aa:aa:aa:aa:aa:aa")
            # forged packet: different TTL AND different MAC — simulated takeover
            _feed(table, on_packet, victim, server, 443, "PA", seq=1200, ttl=38,
                  mac="66:66:66:66:66:66")

        time.sleep(1.5)


def main():
    parser = argparse.ArgumentParser(description="SENTINEL — session hijack & scan detector")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--iface", help="Network interface for live capture (requires root)")
    group.add_argument("--demo", action="store_true", help="Run with simulated traffic, no NIC/root needed")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--network-id", default="default-net",
                         help="Tag for this sensor's network in a multi-network deployment "
                              "(e.g. 'hr-net', 'dev-net'). See sentinel-enterprise-system-design.md.")
    parser.add_argument("--subnet",
                         help="CIDR to periodically ARP-scan for device discovery, e.g. 192.168.1.0/24. "
                              "Requires root, same as --iface. Omit to disable discovery scanning.")
    parser.add_argument("--soc-url",
                         help="Central SOC server URL to forward alerts to, e.g. http://soc-host:6000. "
                              "Omit to run standalone (local dashboard/log only). See soc_server/.")
    parser.add_argument("--soc-api-key",
                         help="API key issued by soc_server/provision_sensor.py. Required if --soc-url is set.")
    args = parser.parse_args()

    if args.soc_url and not args.soc_api_key:
        parser.error("--soc-url requires --soc-api-key (provision one with soc_server/provision_sensor.py)")

    mode = "demo" if args.demo else "live"
    iface_label = "SYNTHETIC" if args.demo else args.iface

    app, socketio, table, on_packet, open_port_monitor, alert_mgr, discovery_scanner, registry, forwarder = \
        build_app(mode, iface_label, network_id=args.network_id,
                  soc_url=args.soc_url, soc_api_key=args.soc_api_key)

    start_reaper_thread(table)
    start_open_port_monitor_thread(open_port_monitor)

    if forwarder:
        start_forwarder_thread(forwarder)
        start_flow_snapshot_thread(table, forwarder)
        print(f"[main] forwarding alerts + flow snapshots to SOC server: {args.soc_url}")

    if args.subnet:
        if args.demo:
            print("[main] --subnet ignored in --demo mode (needs a real NIC/root)")
        else:
            on_hosts = forwarder.enqueue_discovery if forwarder else None
            start_discovery_thread(discovery_scanner, args.subnet, on_hosts=on_hosts)
            print(f"[main] discovery scanning {args.subnet} every 5 minutes")

    if args.demo:
        stop_event = threading.Event()
        t = threading.Thread(target=run_demo_traffic, args=(table, on_packet, stop_event), daemon=True)
        t.start()
        print(f"[main] demo traffic generator started")
    else:
        from sniffer import start_sniffing
        t = threading.Thread(target=start_sniffing, args=(args.iface, table, on_packet), daemon=True)
        t.start()
        print(f"[main] live sniffing started on {args.iface} (requires root)")

    print(f"[main] network_id: {args.network_id}")
    print(f"[main] SENTINEL dashboard: http://{args.host}:{args.port}")
    # allow_unsafe_werkzeug: this is a local research tool, not a public-facing
    # service — swap to eventlet/gunicorn if you ever expose it beyond localhost.
    socketio.run(app, host=args.host, port=args.port, allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    main()
