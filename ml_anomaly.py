"""
ml_anomaly.py
-------------
Step 7, ML slice: unsupervised anomaly detection over flow-level
features using Isolation Forest — the interpretable, fast model the
original spec explicitly recommended starting with ("start with
interpretable models such as Random Forest or XGBoost... compare
multiple models experimentally rather than assuming deep learning is
automatically better"). Isolation Forest is the natural unsupervised
counterpart for flows with no labels.

Operates on flow_snapshots ingested from sensors (Session.flow_stats()
output, forwarded periodically by main.py's flow-snapshot thread — see
start_flow_snapshot_thread). Lives at the SOC server, like behavioral.py,
because it needs enough flow volume across time to fit a meaningful
model — a handful of flows from one sensor isn't enough.

Explainability: Isolation Forest doesn't expose SHAP-style attributions
cheaply, and adding the shap package for this one feature isn't worth
the dependency weight. Instead, each flagged flow's top deviating
features are reported via simple z-scores against the same training
sample — enough to answer "why was this flagged" without needing a
black-box verdict, matching the spec's explainability requirement at
much lower cost.
"""

import json
import statistics
import time

from sklearn.ensemble import IsolationForest


FEATURE_KEYS = [
    "duration_seconds", "total_packets", "total_bytes",
    "fwd_packets", "rev_packets", "fwd_bytes", "rev_bytes",
    "avg_packet_size", "packets_per_second", "bytes_per_second",
    "syn_count", "synack_count", "ack_count", "rst_count", "fin_count",
    "fwd_retransmit_count", "rev_retransmit_count",
]

MIN_FLOWS_FOR_MODEL = 20
DEFAULT_CONTAMINATION = 0.05
DEFAULT_LOOKBACK_HOURS = 24
DEVIATION_Z_THRESHOLD = 2.0


def _extract_features(stats: dict) -> list[float]:
    return [float(stats.get(k) or 0) for k in FEATURE_KEYS]


def load_recent_flows(conn, network_id: int, since_ts: float) -> list[dict]:
    rows = conn.execute(
        "SELECT flow_key, stats, event_timestamp FROM flow_snapshots "
        "WHERE network_id = ? AND event_timestamp >= ? ORDER BY event_timestamp DESC",
        (network_id, since_ts),
    ).fetchall()
    flows = []
    for r in rows:
        try:
            stats = json.loads(r["stats"])
        except (TypeError, ValueError):
            continue
        flows.append({"flow_key": r["flow_key"], "event_timestamp": r["event_timestamp"], "stats": stats})
    return flows


def _top_deviating_features(features: list[float], all_features: list[list[float]]) -> list[str]:
    """For one flow's feature vector, find which features are most
    unusual relative to the whole sample (plain z-score) — the
    lightweight, dependency-free stand-in for SHAP/feature-importance."""
    deviations = []
    for i, key in enumerate(FEATURE_KEYS):
        column = [f[i] for f in all_features]
        mean = statistics.mean(column)
        stdev = statistics.pstdev(column) if len(column) > 1 else 0.0
        if stdev < 1e-9:
            continue
        z = (features[i] - mean) / stdev
        if abs(z) >= DEVIATION_Z_THRESHOLD:
            deviations.append((abs(z), key, features[i], mean, z))
    deviations.sort(reverse=True)
    return [
        f"{key} = {val:.1f} ({'above' if z > 0 else 'below'} average of {mean:.1f}, z={z:.1f})"
        for _, key, val, mean, z in deviations[:3]
    ]


def detect_flow_anomalies(conn, network_id: int, now: float | None = None,
                           lookback_hours: int = DEFAULT_LOOKBACK_HOURS,
                           contamination: float = DEFAULT_CONTAMINATION,
                           min_flows: int = MIN_FLOWS_FOR_MODEL,
                           top_n: int = 10) -> dict:
    now = now if now is not None else time.time()
    since_ts = now - lookback_hours * 3600

    flows = load_recent_flows(conn, network_id, since_ts)

    if len(flows) < min_flows:
        return {
            "network_id": network_id,
            "flows_analyzed": len(flows),
            "model_trained": False,
            "reason": (f"Need at least {min_flows} flow snapshots to train a meaningful model "
                       f"(have {len(flows)}) — flow forwarding may not be enabled on this "
                       f"network's sensor yet (needs --soc-url; see main.py)."),
            "anomalies": [],
        }

    feature_matrix = [_extract_features(f["stats"]) for f in flows]

    model = IsolationForest(contamination=contamination, random_state=42)
    model.fit(feature_matrix)
    scores = model.decision_function(feature_matrix)   # higher = more normal
    predictions = model.predict(feature_matrix)          # -1 = anomaly, 1 = normal

    results = []
    for flow, features, score, pred in zip(flows, feature_matrix, scores, predictions):
        if pred == -1:
            results.append({
                "flow_key": flow["flow_key"],
                "event_timestamp": flow["event_timestamp"],
                "anomaly_score": round(float(-score), 4),  # flip sign: higher = more anomalous
                "reasons": _top_deviating_features(features, feature_matrix),
            })

    results.sort(key=lambda r: r["anomaly_score"], reverse=True)

    return {
        "network_id": network_id,
        "flows_analyzed": len(flows),
        "model_trained": True,
        "anomalies_found": len(results),
        "anomalies": results[:top_n],
    }
