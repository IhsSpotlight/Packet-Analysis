"""
provision_sensor.py
--------------------
Onboards a new sensor: creates the network if it doesn't exist yet,
generates an API key, stores only its hash, and prints the plaintext key
ONCE — this is the only time it's ever shown. Put it straight into the
sensor's --api-key config; there's no way to retrieve it again (by
design — if you lose it, provision a new sensor and revoke the old one).

Usage:
    python3 provision_sensor.py --db soc.db --network hr-net --hostname hr-sensor-01
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import db
from auth import generate_api_key, hash_api_key


def main():
    parser = argparse.ArgumentParser(description="Provision a new SENTINEL sensor")
    parser.add_argument("--db", default=os.path.join(os.path.dirname(__file__), "soc.db"))
    parser.add_argument("--network", required=True, help="Network name, e.g. hr-net")
    parser.add_argument("--hostname", default="", help="Optional label for this sensor")
    args = parser.parse_args()

    db.init_db(args.db)
    conn = db.connect(args.db)

    network_id = db.get_or_create_network(conn, args.network)
    api_key = generate_api_key()
    sensor_id = db.create_sensor(conn, network_id, hash_api_key(api_key), hostname=args.hostname)

    print(f"Sensor provisioned: id={sensor_id}, network='{args.network}' (network_id={network_id})")
    print()
    print("API KEY (shown once — save it now):")
    print(f"  {api_key}")
    print()
    print("Use it when starting the sensor, e.g.:")
    print(f'  python3 main.py --demo --network-id {args.network} '
          f'--soc-url http://<soc-server>:6000 --soc-api-key {api_key}')


if __name__ == "__main__":
    main()
