"""
provision_user.py
------------------
Creates a dashboard login. Two roles:

  senior_user   scoped to exactly one network — requires --network
  soc_admin     sees everything, aggregated + per-network drill-down —
                --network must be omitted

Usage:
    python3 provision_user.py --db soc.db --username alice --role senior_user --network hr-net
    python3 provision_user.py --db soc.db --username ceo --role soc_admin

Password is prompted interactively (not passed as a CLI arg, so it
doesn't end up in shell history).
"""

import argparse
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import db
from auth import hash_password


def main():
    parser = argparse.ArgumentParser(description="Provision a SENTINEL SOC dashboard user")
    parser.add_argument("--db", default=os.path.join(os.path.dirname(__file__), "soc.db"))
    parser.add_argument("--username", required=True)
    parser.add_argument("--role", required=True, choices=["senior_user", "soc_admin"])
    parser.add_argument("--network", help="Required for senior_user; must be omitted for soc_admin")
    args = parser.parse_args()

    if args.role == "senior_user" and not args.network:
        parser.error("--role senior_user requires --network")
    if args.role == "soc_admin" and args.network:
        parser.error("--role soc_admin must not have --network (it sees all networks)")

    db.init_db(args.db)
    conn = db.connect(args.db)

    if db.get_user_by_username(conn, args.username):
        print(f"Error: username '{args.username}' already exists.")
        return

    network_id = None
    if args.network:
        network_id = db.get_or_create_network(conn, args.network)

    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Error: passwords did not match.")
        return
    if len(password) < 8:
        print("Error: password must be at least 8 characters.")
        return

    user_id = db.create_user(conn, args.username, hash_password(password), args.role, network_id)
    scope = f"network '{args.network}'" if args.network else "ALL networks (soc_admin)"
    print(f"User provisioned: id={user_id}, username='{args.username}', role={args.role}, scope={scope}")


if __name__ == "__main__":
    main()
