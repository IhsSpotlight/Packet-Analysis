"""
correlation.py
---------------
Step 7 finale, and Section 13 of the original spec: group related alerts
into incidents instead of showing them as independent noise. The spec's
own example is the target shape:

    10:01:01  Port scan detected
    10:01:04  SYN anomaly detected
    10:01:07  Connection-rate anomaly detected
        becomes
    INCIDENT: potential reconnaissance followed by possible TCP flooding
    Source: X.X.X.X   Risk: 94/100

Grouping rule (simple, explainable, no ML needed for this part): alerts
from the same (network_id, src_ip) within a sliding time window belong
to the same incident. This is intentionally the simplest correlation
rule that produces the right shape — a real deployment might also
correlate by destination or by attack-chain pattern (recon -> exploit),
but source+time is the one that's unambiguous and hard to get wrong.

A basic composite risk score (0-100) is derived from the incident's
alerts: severity mix + alert count + whether multiple distinct alert
types fired (multi-signal corroboration matters more than repeat counts
of the same signal) — the spec explicitly says the exact formulation
should be experimentally justified in the paper, so this is a
defensible starting point, not a claimed-final answer.
"""

import time


CORRELATION_WINDOW_SEC = 300  # alerts from the same source within 5 minutes group together

SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 12, "low": 5}


def build_incidents(alert_rows: list[dict], window_sec: int = CORRELATION_WINDOW_SEC) -> list[dict]:
    """alert_rows: list of dicts with at least alert_type, severity,
    src_ip, message, event_timestamp — as returned by a DB query.
    Returns incidents sorted by risk_score descending, each incident's
    alerts sorted chronologically."""
    by_source: dict[str, list[dict]] = {}
    for row in alert_rows:
        by_source.setdefault(row["src_ip"], []).append(row)

    incidents = []
    for src_ip, rows in by_source.items():
        rows.sort(key=lambda r: r["event_timestamp"])
        current_group: list[dict] = []
        for row in rows:
            if current_group and row["event_timestamp"] - current_group[-1]["event_timestamp"] > window_sec:
                incidents.append(_make_incident(src_ip, current_group))
                current_group = []
            current_group.append(row)
        if current_group:
            incidents.append(_make_incident(src_ip, current_group))

    incidents.sort(key=lambda i: i["risk_score"], reverse=True)
    return incidents


def _make_incident(src_ip: str, alerts: list[dict]) -> dict:
    distinct_types = sorted({a["alert_type"] for a in alerts})
    risk_score = _compute_risk_score(alerts, distinct_types)

    return {
        "src_ip": src_ip,
        "start_time": alerts[0]["event_timestamp"],
        "end_time": alerts[-1]["event_timestamp"],
        "alert_count": len(alerts),
        "alert_types": distinct_types,
        "risk_score": risk_score,
        "summary": _summarize(distinct_types, len(alerts)),
        "alerts": alerts,
    }


def _compute_risk_score(alerts: list[dict], distinct_types: list[str]) -> int:
    """0-100. Severity mix dominates; a second corroborating signal
    (different alert type, not just a repeat) adds meaningfully more
    than another instance of the same type would — multiple independent
    detectors agreeing is stronger evidence than one detector firing
    repeatedly."""
    severity_component = min(70, sum(SEVERITY_WEIGHT.get(a["severity"], 0) for a in alerts[:3]))
    corroboration_component = min(30, (len(distinct_types) - 1) * 15)
    return min(100, severity_component + corroboration_component)


def _summarize(distinct_types: list[str], count: int) -> str:
    if len(distinct_types) == 1:
        return f"{count}x {distinct_types[0]}"
    return f"{count} alerts across {len(distinct_types)} signal types: {', '.join(distinct_types)}"


def get_incidents(conn, network_id: int | None, lookback_hours: int = 24,
                   now: float | None = None, window_sec: int = CORRELATION_WINDOW_SEC) -> list[dict]:
    now = now if now is not None else time.time()
    since_ts = now - lookback_hours * 3600

    if network_id is not None:
        rows = conn.execute(
            "SELECT alert_type, severity, src_ip, message, event_timestamp FROM alerts "
            "WHERE network_id = ? AND event_timestamp >= ? ORDER BY event_timestamp",
            (network_id, since_ts),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT alert_type, severity, src_ip, message, event_timestamp FROM alerts "
            "WHERE event_timestamp >= ? ORDER BY event_timestamp",
            (since_ts,),
        ).fetchall()

    return build_incidents([dict(r) for r in rows], window_sec=window_sec)
