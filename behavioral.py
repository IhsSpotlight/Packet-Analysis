"""
behavioral.py
-------------
Step 7 (behavioral engine), first slice: per-network alert-RATE
baselining. This deliberately operates on already-ingested alert data at
the SOC server — per the design doc, this is where enough history and
cross-sensor volume exist to make a baseline meaningful; a single
sensor's short-lived local view can't establish "normal" reliably.

Approach (matches the original spec's own example almost exactly:
"normal 10-50 connections/minute, observed 2000/minute = anomaly"):

  1. Bucket this network's alert counts into hourly buckets going back
     `lookback_hours` (default 7 days).
  2. Baseline = mean/stdev of all COMPLETE historical hours (the current,
     still-in-progress hour is excluded — it's not comparable to a full
     hour).
  3. Z-score the current hour's count against that baseline. A hard
     minimum stdev floor prevents a very quiet, consistent network from
     becoming hypersensitive (mean=2, stdev=0 would flag literally any
     3rd alert as "infinite" deviations).
  4. Require a minimum amount of history before ever flagging — a brand
     new network with 1-2 hours of data has no real baseline yet, and a
     false anomaly on day one erodes trust in every anomaly after it.

This is intentionally simple and explainable (every field in the result
maps directly to something in the reasons text) — a proper ML anomaly
layer (Isolation Forest / autoencoder on the full flow-feature set) is
the next slice of Step 7, not this one.
"""

import statistics
import time


DEFAULT_LOOKBACK_HOURS = 24 * 7      # one week of history for the baseline
DEFAULT_Z_THRESHOLD = 3.0            # ~99.7th percentile under a normal approximation
MIN_STDEV_FLOOR = 1.0                # prevents hypersensitivity on very quiet, stable networks
MIN_SAMPLE_HOURS = 3                 # don't flag anomalies without at least this much history


def _hour_bucket(ts: float) -> int:
    return int(ts // 3600)


def get_hourly_counts(conn, network_id: int, since_ts: float) -> dict[int, int]:
    rows = conn.execute(
        """SELECT CAST(event_timestamp / 3600 AS INTEGER) as hour_bucket, COUNT(*) as c
           FROM alerts WHERE network_id = ? AND event_timestamp >= ?
           GROUP BY hour_bucket""",
        (network_id, since_ts),
    ).fetchall()
    return {r["hour_bucket"]: r["c"] for r in rows}


def compute_baseline(conn, network_id: int, now: float | None = None,
                      lookback_hours: int = DEFAULT_LOOKBACK_HOURS) -> dict:
    now = now if now is not None else time.time()
    current_hour = _hour_bucket(now)
    since_ts = now - lookback_hours * 3600

    counts = get_hourly_counts(conn, network_id, since_ts)
    historical = [c for hour, c in counts.items() if hour != current_hour]

    if not historical:
        return {"mean": 0.0, "stdev": 0.0, "sample_hours": 0}

    mean = statistics.mean(historical)
    stdev = statistics.pstdev(historical) if len(historical) > 1 else 0.0
    return {"mean": mean, "stdev": stdev, "sample_hours": len(historical)}


def check_current_rate(conn, network_id: int, now: float | None = None,
                        z_threshold: float = DEFAULT_Z_THRESHOLD,
                        min_sample_hours: int = MIN_SAMPLE_HOURS) -> dict:
    """The main entry point. Returns a fully explainable result — every
    number needed to justify (or refute) the anomaly call is in the
    output, not hidden in the computation."""
    now = now if now is not None else time.time()
    current_hour = _hour_bucket(now)

    current_count = conn.execute(
        "SELECT COUNT(*) as c FROM alerts WHERE network_id = ? "
        "AND CAST(event_timestamp / 3600 AS INTEGER) = ?",
        (network_id, current_hour),
    ).fetchone()["c"]

    baseline = compute_baseline(conn, network_id, now=now)
    mean, stdev, sample_hours = baseline["mean"], baseline["stdev"], baseline["sample_hours"]
    effective_stdev = max(stdev, MIN_STDEV_FLOOR)

    z_score = (current_count - mean) / effective_stdev

    has_enough_history = sample_hours >= min_sample_hours
    is_anomaly = has_enough_history and z_score >= z_threshold

    reasons = []
    if is_anomaly:
        reasons.append(
            f"Current hour's alert count ({current_count}) is {z_score:.1f} standard "
            f"deviations above this network's {sample_hours}-hour baseline average "
            f"({mean:.1f} alerts/hour)"
        )
    elif not has_enough_history:
        reasons.append(
            f"Not enough history yet to establish a baseline ({sample_hours} hour(s) "
            f"observed, need {min_sample_hours}+) — no anomaly check performed"
        )

    return {
        "network_id": network_id,
        "current_hour_count": current_count,
        "baseline_mean": round(mean, 2),
        "baseline_stdev": round(stdev, 2),
        "sample_hours": sample_hours,
        "z_score": round(z_score, 2),
        "is_anomaly": is_anomaly,
        "reasons": reasons,
    }
