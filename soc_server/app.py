"""
app.py
------
The central SOC server. Two separate auth systems, deliberately kept
apart (see auth.py for why):

  Ingestion API   — sensors POST here, authenticated by per-sensor API
                     key. network_id for every write comes from the
                     authenticated sensor, never the request body.

  Dashboard API    — human users log in here (session cookie), and every
                     read is scoped by their role:
                       senior_user -> forced to their own network_id,
                                       server-side, never from a query param
                       soc_admin   -> may pass ?network_id= to filter, or
                                       omit it to see everything

Run standalone:
    python3 app.py --db soc.db --host 0.0.0.0 --port 6000

Provision a sensor first with provision_sensor.py, and at least one user
with provision_user.py — there's no self-signup by design.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from functools import wraps

from flask import Flask, jsonify, request, session, render_template

import db
import behavioral
import ml_anomaly
import correlation
from auth import extract_bearer_token, hash_api_key, verify_password


def build_app(db_path: str, secret_key: str = "sentinel-soc-dev") -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    # SECRET_KEY signs the session cookie — rotate this for any real
    # deployment; the default here is fine only for local development.
    app.config["SECRET_KEY"] = secret_key
    db.init_db(db_path)
    conn = db.connect(db_path)

    # ---------------- sensor (ingestion) auth ----------------

    def authenticate_sensor():
        token = extract_bearer_token(request.headers.get("Authorization"))
        if not token:
            return None
        return db.get_sensor_by_key_hash(conn, hash_api_key(token))

    # ---------------- user (dashboard) auth ----------------

    def current_user():
        user_id = session.get("user_id")
        if not user_id:
            return None
        return db.get_user_by_id(conn, user_id)

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                return jsonify({"error": "login required"}), 401
            return view(user, *args, **kwargs)
        return wrapped

    def scoped_network_id(user, requested: str | None) -> tuple[int | None, str | None]:
        """The RBAC enforcement point: returns (network_id_filter, error).
        senior_user is ALWAYS forced to their own network_id — `requested`
        is ignored for them entirely, not merely validated, so there's no
        parameter-tampering path to another network's data. soc_admin may
        pass a network name to filter, or nothing to see all networks."""
        if user["role"] == "senior_user":
            return user["network_id"], None
        # soc_admin
        if requested:
            row = conn.execute("SELECT id FROM networks WHERE name = ?", (requested,)).fetchone()
            if not row:
                return None, f"unknown network '{requested}'"
            return row["id"], None
        return None, None  # no filter — sees all networks

    # ==================== INGESTION API (sensor auth) ====================

    @app.route("/api/heartbeat", methods=["POST"])
    def heartbeat():
        sensor = authenticate_sensor()
        if not sensor:
            return jsonify({"error": "invalid or missing API key"}), 401
        db.touch_sensor_heartbeat(conn, sensor["id"])
        return jsonify({"status": "ok"})

    @app.route("/api/ingest/alerts", methods=["POST"])
    def ingest_alerts():
        sensor = authenticate_sensor()
        if not sensor:
            return jsonify({"error": "invalid or missing API key"}), 401
        body = request.get_json(force=True) or {}
        alerts = body.get("alerts", [])
        if not alerts:
            return jsonify({"error": "no alerts in request body"}), 400
        db.insert_alerts(conn, sensor["network_id"], sensor["id"], alerts)
        db.touch_sensor_heartbeat(conn, sensor["id"])
        return jsonify({"ingested": len(alerts)})

    @app.route("/api/ingest/flow-snapshot", methods=["POST"])
    def ingest_flows():
        sensor = authenticate_sensor()
        if not sensor:
            return jsonify({"error": "invalid or missing API key"}), 401
        body = request.get_json(force=True) or {}
        flows = body.get("flows", [])
        if not flows:
            return jsonify({"error": "no flows in request body"}), 400
        db.insert_flow_snapshots(conn, sensor["network_id"], sensor["id"], flows)
        db.touch_sensor_heartbeat(conn, sensor["id"])
        return jsonify({"ingested": len(flows)})

    @app.route("/api/ingest/discovery", methods=["POST"])
    def ingest_discovery():
        sensor = authenticate_sensor()
        if not sensor:
            return jsonify({"error": "invalid or missing API key"}), 401
        body = request.get_json(force=True) or {}
        hosts = body.get("hosts", [])
        if not hosts:
            return jsonify({"error": "no hosts in request body"}), 400
        db.upsert_discovered_hosts(conn, sensor["network_id"], sensor["id"], hosts)
        db.touch_sensor_heartbeat(conn, sensor["id"])
        return jsonify({"upserted": len(hosts)})

    # ==================== DASHBOARD API (user auth, RBAC-scoped) ====================

    # ==================== DASHBOARD (static shell — login/data handled client-side) ====================

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/login", methods=["POST"])
    def login():
        body = request.get_json(force=True) or {}
        username, password = body.get("username"), body.get("password")
        if not username or not password:
            return jsonify({"error": "username and password required"}), 400

        user = db.get_user_by_username(conn, username)
        if not user or not verify_password(password, user["password_hash"]):
            return jsonify({"error": "invalid credentials"}), 401

        session["user_id"] = user["id"]
        return jsonify({"username": user["username"], "role": user["role"]})

    @app.route("/api/logout", methods=["POST"])
    def logout():
        session.pop("user_id", None)
        return jsonify({"status": "ok"})

    @app.route("/api/me", methods=["GET"])
    @login_required
    def me(user):
        network_name = None
        if user["network_id"] is not None:
            row = conn.execute("SELECT name FROM networks WHERE id = ?", (user["network_id"],)).fetchone()
            network_name = row["name"] if row else None
        return jsonify({"username": user["username"], "role": user["role"], "network": network_name})

    @app.route("/api/networks", methods=["GET"])
    @login_required
    def list_networks(user):
        if user["role"] != "soc_admin":
            # senior_user only ever sees their own single network — no
            # value in listing others they can't view anyway
            row = conn.execute("SELECT id, name, created_at FROM networks WHERE id = ?",
                                (user["network_id"],)).fetchone()
            return jsonify([dict(row)] if row else [])
        rows = conn.execute("SELECT id, name, created_at FROM networks").fetchall()
        return jsonify([dict(r) for r in rows])

    @app.route("/api/alerts", methods=["GET"])
    @login_required
    def list_alerts(user):
        network_id, error = scoped_network_id(user, request.args.get("network"))
        if error:
            return jsonify({"error": error}), 400
        limit = min(int(request.args.get("limit", 50)), 500)

        if network_id is not None:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE network_id = ? ORDER BY event_timestamp DESC LIMIT ?",
                (network_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY event_timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return jsonify([dict(r) for r in rows])

    @app.route("/api/stats", methods=["GET"])
    @login_required
    def stats(user):
        network_id, error = scoped_network_id(user, request.args.get("network"))
        if error:
            return jsonify({"error": error}), 400

        where = "WHERE network_id = ?" if network_id is not None else ""
        params = (network_id,) if network_id is not None else ()

        by_severity = conn.execute(
            f"SELECT severity, COUNT(*) as count FROM alerts {where} GROUP BY severity", params
        ).fetchall()
        by_type = conn.execute(
            f"SELECT alert_type, COUNT(*) as count FROM alerts {where} GROUP BY alert_type", params
        ).fetchall()
        total = conn.execute(f"SELECT COUNT(*) as c FROM alerts {where}", params).fetchone()["c"]

        return jsonify({
            "total": total,
            "by_severity": {r["severity"]: r["count"] for r in by_severity},
            "by_type": {r["alert_type"]: r["count"] for r in by_type},
        })

    @app.route("/api/behavioral", methods=["GET"])
    @login_required
    def behavioral_check(user):
        """senior_user always gets their own network's check. soc_admin
        with ?network= gets that one network; with no filter, gets a
        list across every network (this is the one endpoint where 'no
        filter' means 'all, individually' rather than 'unfiltered union',
        since a baseline is inherently per-network — there's no such
        thing as a combined baseline across networks with different
        traffic patterns)."""
        network_id, error = scoped_network_id(user, request.args.get("network"))
        if error:
            return jsonify({"error": error}), 400

        if network_id is not None:
            return jsonify(behavioral.check_current_rate(conn, network_id))

        # soc_admin, no filter — check every network
        networks = conn.execute("SELECT id, name FROM networks").fetchall()
        results = []
        for net in networks:
            result = behavioral.check_current_rate(conn, net["id"])
            result["network_name"] = net["name"]
            results.append(result)
        return jsonify(results)

    @app.route("/api/ml-anomalies", methods=["GET"])
    @login_required
    def ml_anomalies(user):
        """Same RBAC pattern as /api/behavioral — a model is inherently
        per-network (flow feature distributions differ wildly between,
        say, a dev network and an HR network), so 'no filter' for
        soc_admin means one model per network, not one pooled model."""
        network_id, error = scoped_network_id(user, request.args.get("network"))
        if error:
            return jsonify({"error": error}), 400

        if network_id is not None:
            return jsonify(ml_anomaly.detect_flow_anomalies(conn, network_id))

        networks = conn.execute("SELECT id, name FROM networks").fetchall()
        results = []
        for net in networks:
            result = ml_anomaly.detect_flow_anomalies(conn, net["id"])
            result["network_name"] = net["name"]
            results.append(result)
        return jsonify(results)

    @app.route("/api/incidents", methods=["GET"])
    @login_required
    def incidents(user):
        network_id, error = scoped_network_id(user, request.args.get("network"))
        if error:
            return jsonify({"error": error}), 400
        return jsonify(correlation.get_incidents(conn, network_id))

    @app.route("/api/assets", methods=["GET"])
    @login_required
    def get_assets(user):
        """Returns registered assets + discovered hosts, with a diff flag
        showing which discovered devices are NOT yet registered.
        senior_user: always their own network.
        soc_admin: may pass ?network= to scope to one network."""
        network_id, error = scoped_network_id(user, request.args.get("network"))
        if error:
            return jsonify({"error": error}), 400
        if network_id is None:
            return jsonify({"error": "soc_admin must supply ?network= for asset queries"}), 400
        return jsonify(db.get_assets_with_discovery_diff(conn, network_id))

    @app.route("/api/assets", methods=["POST"])
    @login_required
    def register_asset(user):
        """Register a discovered host into the approved asset list.
        senior_user: can only register to their own network.
        soc_admin: must supply ?network= to specify which network."""
        network_id, error = scoped_network_id(user, request.args.get("network"))
        if error:
            return jsonify({"error": error}), 400
        if network_id is None:
            return jsonify({"error": "soc_admin must supply ?network= when registering assets"}), 400

        body = request.get_json(force=True) or {}
        ip, mac = body.get("ip"), body.get("mac")
        if not ip or not mac:
            return jsonify({"error": "ip and mac are required"}), 400

        asset_id = db.register_asset(
            conn, network_id, ip, mac,
            label=body.get("label", ""),
            added_by=user["id"]
        )
        return jsonify({"id": asset_id, "network_id": network_id,
                         "ip": ip, "mac": mac.lower()}), 201

    @app.route("/api/assets/<mac>", methods=["DELETE"])
    @login_required
    def remove_asset(user, mac):
        network_id, error = scoped_network_id(user, request.args.get("network"))
        if error:
            return jsonify({"error": error}), 400
        if network_id is None:
            return jsonify({"error": "soc_admin must supply ?network= when removing assets"}), 400
        removed = db.remove_registered_asset(conn, network_id, mac)
        return jsonify({"removed": removed})

    @app.route("/api/sensors", methods=["GET"])
    @login_required
    def list_sensors(user):
        """soc_admin only — lists all provisioned sensors and their last
        heartbeat so the dashboard can show which sensors are alive."""
        if user["role"] != "soc_admin":
            return jsonify({"error": "soc_admin only"}), 403
        rows = db.get_all_sensors(conn)
        return jsonify([dict(r) for r in rows])

    return app


def main():
    parser = argparse.ArgumentParser(description="SENTINEL SOC server")
    parser.add_argument("--db", default=os.path.join(os.path.dirname(__file__), "soc.db"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=6000)
    parser.add_argument("--secret-key", default="sentinel-soc-dev",
                         help="Session cookie signing key. Set a real random value in production.")
    args = parser.parse_args()

    app = build_app(args.db, secret_key=args.secret_key)
    print(f"[soc_server] DB: {args.db}")
    print(f"[soc_server] listening on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
