"""
test_correlation.py
--------------------
Run: python3 test_correlation.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from correlation import build_incidents, CORRELATION_WINDOW_SEC


def make_alert(alert_type, severity, src_ip, ts):
    return {"alert_type": alert_type, "severity": severity, "src_ip": src_ip,
            "message": "x", "event_timestamp": ts}


def test_close_alerts_from_same_source_grouped():
    alerts = [
        make_alert("PORT_SCAN", "high", "10.0.0.66", 1000),
        make_alert("SYN_FLOOD", "critical", "10.0.0.66", 1030),
        make_alert("PORT_SCAN", "high", "10.0.0.66", 1060),
    ]
    incidents = build_incidents(alerts)
    assert len(incidents) == 1
    assert incidents[0]["alert_count"] == 3
    print("PASS: test_close_alerts_from_same_source_grouped")


def test_alerts_beyond_window_split_into_separate_incidents():
    alerts = [
        make_alert("PORT_SCAN", "high", "10.0.0.66", 1000),
        make_alert("PORT_SCAN", "high", "10.0.0.66", 1000 + CORRELATION_WINDOW_SEC + 100),  # well past window
    ]
    incidents = build_incidents(alerts)
    assert len(incidents) == 2
    print("PASS: test_alerts_beyond_window_split_into_separate_incidents")


def test_different_sources_never_grouped_together():
    alerts = [
        make_alert("PORT_SCAN", "high", "10.0.0.66", 1000),
        make_alert("PORT_SCAN", "high", "10.0.0.77", 1005),  # same time, different source
    ]
    incidents = build_incidents(alerts)
    assert len(incidents) == 2
    assert {i["src_ip"] for i in incidents} == {"10.0.0.66", "10.0.0.77"}
    print("PASS: test_different_sources_never_grouped_together")


def test_multi_signal_incident_scores_higher_than_single_repeat():
    """The spec's own point: multiple DIFFERENT detectors agreeing is
    stronger evidence than one detector firing repeatedly."""
    repeated_single_type = [
        make_alert("PORT_SCAN", "high", "10.0.0.1", 1000),
        make_alert("PORT_SCAN", "high", "10.0.0.1", 1010),
        make_alert("PORT_SCAN", "high", "10.0.0.1", 1020),
    ]
    multi_signal = [
        make_alert("PORT_SCAN", "high", "10.0.0.2", 1000),
        make_alert("SEQ_ANOMALY", "high", "10.0.0.2", 1010),
        make_alert("RST_STORM", "high", "10.0.0.2", 1020),
    ]

    single_incident = build_incidents(repeated_single_type)[0]
    multi_incident = build_incidents(multi_signal)[0]

    assert multi_incident["risk_score"] > single_incident["risk_score"], \
        "corroborating signals from different detectors should score higher than repeats of one"
    print("PASS: test_multi_signal_incident_scores_higher_than_single_repeat")


def test_critical_severity_dominates_risk_score():
    low_severity = [make_alert("PORT_SCAN", "low", "10.0.0.1", 1000)]
    critical_severity = [make_alert("SYN_FLOOD", "critical", "10.0.0.2", 1000)]

    low_incident = build_incidents(low_severity)[0]
    crit_incident = build_incidents(critical_severity)[0]

    assert crit_incident["risk_score"] > low_incident["risk_score"]
    print("PASS: test_critical_severity_dominates_risk_score")


def test_risk_score_capped_at_100():
    alerts = [
        make_alert("PORT_SCAN", "critical", "10.0.0.1", 1000),
        make_alert("SYN_FLOOD", "critical", "10.0.0.1", 1010),
        make_alert("MAC_SWAP", "critical", "10.0.0.1", 1020),
        make_alert("RST_STORM", "critical", "10.0.0.1", 1030),
        make_alert("SEQ_ANOMALY", "critical", "10.0.0.1", 1040),
    ]
    incident = build_incidents(alerts)[0]
    assert incident["risk_score"] <= 100
    print("PASS: test_risk_score_capped_at_100")


def test_incidents_sorted_by_risk_descending():
    alerts = [
        make_alert("PORT_SCAN", "low", "10.0.0.1", 1000),           # low risk
        make_alert("SYN_FLOOD", "critical", "10.0.0.2", 2000),
        make_alert("MAC_SWAP", "critical", "10.0.0.2", 2010),       # multi-signal, critical: highest risk
    ]
    incidents = build_incidents(alerts)
    assert len(incidents) == 2
    assert incidents[0]["src_ip"] == "10.0.0.2", "the higher-risk incident should come first"
    scores = [i["risk_score"] for i in incidents]
    assert scores == sorted(scores, reverse=True)
    print("PASS: test_incidents_sorted_by_risk_descending")


def test_summary_text_reflects_signal_diversity():
    single_type = build_incidents([
        make_alert("PORT_SCAN", "high", "10.0.0.1", 1000),
        make_alert("PORT_SCAN", "high", "10.0.0.1", 1010),
    ])[0]
    assert "PORT_SCAN" in single_type["summary"]

    multi_type = build_incidents([
        make_alert("PORT_SCAN", "high", "10.0.0.2", 1000),
        make_alert("SYN_FLOOD", "critical", "10.0.0.2", 1010),
    ])[0]
    assert "signal types" in multi_type["summary"]
    print("PASS: test_summary_text_reflects_signal_diversity")


def test_empty_alerts_returns_no_incidents():
    assert build_incidents([]) == []
    print("PASS: test_empty_alerts_returns_no_incidents")


if __name__ == "__main__":
    test_close_alerts_from_same_source_grouped()
    test_alerts_beyond_window_split_into_separate_incidents()
    test_different_sources_never_grouped_together()
    test_multi_signal_incident_scores_higher_than_single_repeat()
    test_critical_severity_dominates_risk_score()
    test_risk_score_capped_at_100()
    test_incidents_sorted_by_risk_descending()
    test_summary_text_reflects_signal_diversity()
    test_empty_alerts_returns_no_incidents()
    print("\nAll correlation tests passed.")
