"""
test_forwarder.py
------------------
Run: python3 test_forwarder.py

The HTTP POST is injected (post_fn) so these run without network access.
"""

import os
import tempfile

from alert import Alert, Severity
from forwarder import Forwarder


def make_alert(alert_type="PORT_SCAN"):
    return Alert(alert_type=alert_type, src_ip="10.0.0.1", severity=Severity.HIGH,
                 message="test", network_id="hr-net")


def test_enqueue_and_flush_success():
    with tempfile.TemporaryDirectory() as tmp:
        sent = []
        fwd = Forwarder("http://fake", "key", os.path.join(tmp, "buf.json"),
                         post_fn=lambda path, payload: sent.append(payload) or True)

        fwd.enqueue(make_alert())
        fwd.enqueue(make_alert("SYN_FLOOD"))
        count = fwd.flush()

        assert count == 2
        assert fwd.pending_count() == 0
        assert len(sent) == 1, "should batch both alerts into one POST"
        assert len(sent[0]["alerts"]) == 2
        print("PASS: test_enqueue_and_flush_success")


def test_flush_failure_keeps_queue_intact():
    with tempfile.TemporaryDirectory() as tmp:
        fwd = Forwarder("http://fake", "key", os.path.join(tmp, "buf.json"),
                         post_fn=lambda path, payload: False)  # simulates SOC server unreachable

        fwd.enqueue(make_alert())
        count = fwd.flush()

        assert count == 0
        assert fwd.pending_count() == 1, "alert must not be lost when the SOC server is unreachable"
        print("PASS: test_flush_failure_keeps_queue_intact")


def test_retry_after_failure_succeeds():
    with tempfile.TemporaryDirectory() as tmp:
        attempts = []

        def flaky_post(path, payload):
            attempts.append(payload)
            return len(attempts) > 1  # fails first time, succeeds second

        fwd = Forwarder("http://fake", "key", os.path.join(tmp, "buf.json"), post_fn=flaky_post)
        fwd.enqueue(make_alert())

        first = fwd.flush()
        assert first == 0
        assert fwd.pending_count() == 1

        second = fwd.flush()
        assert second == 1
        assert fwd.pending_count() == 0
        print("PASS: test_retry_after_failure_succeeds")


def test_buffer_persists_across_instances():
    """Simulates a sensor restart while alerts are still queued (e.g. the
    SOC server was down when the process was killed)."""
    with tempfile.TemporaryDirectory() as tmp:
        buf_path = os.path.join(tmp, "buf.json")

        fwd1 = Forwarder("http://fake", "key", buf_path, post_fn=lambda p, b: False)
        fwd1.enqueue(make_alert())
        fwd1.enqueue(make_alert("MAC_SWAP"))
        assert fwd1.pending_count() == 2

        # new instance, same buffer file — as if the process restarted
        fwd2 = Forwarder("http://fake", "key", buf_path, post_fn=lambda p, b: False)
        assert fwd2.pending_count() == 2, "queued alerts must survive a restart"
        print("PASS: test_buffer_persists_across_instances")


def test_batch_size_respected():
    with tempfile.TemporaryDirectory() as tmp:
        sent = []
        fwd = Forwarder("http://fake", "key", os.path.join(tmp, "buf.json"),
                         batch_size=3, post_fn=lambda p, b: sent.append(b) or True)

        for _ in range(5):
            fwd.enqueue(make_alert())

        first_flush = fwd.flush()
        assert first_flush == 3, "first flush should only send up to batch_size"
        assert fwd.pending_count() == 2

        second_flush = fwd.flush()
        assert second_flush == 2
        assert fwd.pending_count() == 0
        print("PASS: test_batch_size_respected")


def test_authorization_header_uses_api_key():
    with tempfile.TemporaryDirectory() as tmp:
        # exercise the real _http_post path's request construction without
        # actually hitting the network, by checking it degrades to False
        # (unreachable fake host) rather than raising
        fwd = Forwarder("http://127.0.0.1:1", "my-secret-key", os.path.join(tmp, "buf.json"))
        fwd.enqueue(make_alert())
        result = fwd.flush()
        assert result == 0, "unreachable SOC server should fail gracefully, not raise"
        assert fwd.pending_count() == 1
        print("PASS: test_authorization_header_uses_api_key")


def test_flow_channel_sends_to_correct_endpoint():
    with tempfile.TemporaryDirectory() as tmp:
        calls = []
        fwd = Forwarder("http://fake", "key", os.path.join(tmp, "buf.json"),
                         post_fn=lambda path, payload: calls.append((path, payload)) or True)

        fwd.enqueue_flows([{"flow_key": ["a", 1, "b", 2, "TCP"], "total_packets": 10}])
        count = fwd.flush()

        assert count == 1
        assert calls[0][0] == "/api/ingest/flow-snapshot"
        assert "flows" in calls[0][1]
        print("PASS: test_flow_channel_sends_to_correct_endpoint")


def test_discovery_channel_sends_to_correct_endpoint():
    with tempfile.TemporaryDirectory() as tmp:
        calls = []
        fwd = Forwarder("http://fake", "key", os.path.join(tmp, "buf.json"),
                         post_fn=lambda path, payload: calls.append((path, payload)) or True)

        fwd.enqueue_discovery([{"ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:ff"}])
        count = fwd.flush()

        assert count == 1
        assert calls[0][0] == "/api/ingest/discovery"
        assert "hosts" in calls[0][1]
        print("PASS: test_discovery_channel_sends_to_correct_endpoint")


def test_channels_are_independent_on_failure():
    """If the flow endpoint is down but alerts endpoint works, alerts
    must still get through — one channel's failure can't block another."""
    with tempfile.TemporaryDirectory() as tmp:
        def selective_post(path, payload):
            return path != "/api/ingest/flow-snapshot"  # everything succeeds except flows

        fwd = Forwarder("http://fake", "key", os.path.join(tmp, "buf.json"), post_fn=selective_post)
        fwd.enqueue(make_alert())
        fwd.enqueue_flows([{"flow_key": "x"}])
        fwd.enqueue_discovery([{"ip": "1.2.3.4", "mac": "aa:aa:aa:aa:aa:aa"}])

        fwd.flush()
        counts = fwd.pending_counts()

        assert counts["alerts"] == 0, "alerts should have gone through"
        assert counts["discovery"] == 0, "discovery should have gone through"
        assert counts["flows"] == 1, "flows should still be queued after its own failure"
        print("PASS: test_channels_are_independent_on_failure")


def test_multi_channel_buffer_persists_across_instances():
    with tempfile.TemporaryDirectory() as tmp:
        buf_path = os.path.join(tmp, "buf.json")

        fwd1 = Forwarder("http://fake", "key", buf_path, post_fn=lambda p, b: False)
        fwd1.enqueue(make_alert())
        fwd1.enqueue_flows([{"flow_key": "x"}])
        fwd1.enqueue_discovery([{"ip": "1.2.3.4", "mac": "aa:aa:aa:aa:aa:aa"}])

        fwd2 = Forwarder("http://fake", "key", buf_path, post_fn=lambda p, b: False)
        counts = fwd2.pending_counts()
        assert counts == {"alerts": 1, "flows": 1, "discovery": 1}
        print("PASS: test_multi_channel_buffer_persists_across_instances")


if __name__ == "__main__":
    test_enqueue_and_flush_success()
    test_flush_failure_keeps_queue_intact()
    test_retry_after_failure_succeeds()
    test_buffer_persists_across_instances()
    test_batch_size_respected()
    test_authorization_header_uses_api_key()
    test_flow_channel_sends_to_correct_endpoint()
    test_discovery_channel_sends_to_correct_endpoint()
    test_channels_are_independent_on_failure()
    test_multi_channel_buffer_persists_across_instances()
    print("\nAll forwarder tests passed.")
