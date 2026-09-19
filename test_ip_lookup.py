"""
test_ip_lookup.py
------------------
Run: python3 test_ip_lookup.py

The external ip-api.com call is mocked via dependency injection so these
tests run without network access.
"""

import ip_lookup


def test_private_ip_skips_external_lookup():
    ip_lookup.clear_cache()
    calls = []

    def fake_fetch(ip):
        calls.append(ip)
        return {"org": "should not be called"}

    info = ip_lookup.get_ip_info("192.168.1.10", fetch_fn=fake_fetch)
    assert info["is_private"] is True
    assert info["org"] is None
    assert calls == [], "external fetch should never be called for a private IP"
    print("PASS: test_private_ip_skips_external_lookup")


def test_public_ip_uses_external_lookup():
    ip_lookup.clear_cache()

    def fake_fetch(ip):
        return {"org": "Microsoft Azure", "asn": "AS8075 Microsoft",
                 "country": "United States", "region": "Washington",
                 "city": "Redmond", "isp": "Microsoft"}

    info = ip_lookup.get_ip_info("40.79.167.9", fetch_fn=fake_fetch)
    assert info["is_private"] is False
    assert info["org"] == "Microsoft Azure"
    assert info["asn"] == "AS8075 Microsoft"
    assert info["cached"] is False
    assert info["service"] == "Microsoft"
    print("PASS: test_public_ip_uses_external_lookup")


def test_derive_service_name_matches_known_orgs():
    assert ip_lookup.derive_service_name({"org": "Google LLC"}) == "Google"
    assert ip_lookup.derive_service_name({"org": "Meta Platforms, Inc."}) == "Meta (Facebook)"
    assert ip_lookup.derive_service_name({"isp": "Akamai Technologies, Inc."}) == "Akamai (CDN)"
    assert ip_lookup.derive_service_name({"org": "Amazon.com, Inc."}) == "Amazon / AWS"
    assert ip_lookup.derive_service_name({"hostname": "a23-1-1-1.deploy.static.akamaitechnologies.com"}) == "Akamai (CDN)"
    print("PASS: test_derive_service_name_matches_known_orgs")


def test_derive_service_name_returns_none_for_unknown_org():
    assert ip_lookup.derive_service_name({"org": "Some Random Regional ISP Ltd"}) is None
    assert ip_lookup.derive_service_name({}) is None
    print("PASS: test_derive_service_name_returns_none_for_unknown_org")


def test_cache_hit_skips_second_external_call():
    ip_lookup.clear_cache()
    calls = []

    def fake_fetch(ip):
        calls.append(ip)
        return {"org": "Test Org"}

    first = ip_lookup.get_ip_info("8.8.8.8", fetch_fn=fake_fetch)
    second = ip_lookup.get_ip_info("8.8.8.8", fetch_fn=fake_fetch)

    assert first["cached"] is False
    assert second["cached"] is True
    assert len(calls) == 1, f"expected exactly 1 external call, got {len(calls)}"
    assert second["org"] == "Test Org"
    print("PASS: test_cache_hit_skips_second_external_call")


def test_failed_external_lookup_degrades_gracefully():
    ip_lookup.clear_cache()

    def failing_fetch(ip):
        return None  # simulates offline / rate-limited / blocked

    info = ip_lookup.get_ip_info("1.2.3.4", fetch_fn=failing_fetch)
    assert info["org"] is None
    assert info["asn"] is None
    assert info["country"] is None
    # should not raise, and ip/is_private should still be populated
    assert info["ip"] == "1.2.3.4"
    assert info["is_private"] is False
    print("PASS: test_failed_external_lookup_degrades_gracefully")


def test_loopback_treated_as_private():
    ip_lookup.clear_cache()
    calls = []
    info = ip_lookup.get_ip_info("127.0.0.1", fetch_fn=lambda ip: calls.append(ip))
    assert info["is_private"] is True
    assert calls == []
    print("PASS: test_loopback_treated_as_private")


if __name__ == "__main__":
    test_private_ip_skips_external_lookup()
    test_public_ip_uses_external_lookup()
    test_cache_hit_skips_second_external_call()
    test_failed_external_lookup_degrades_gracefully()
    test_loopback_treated_as_private()
    test_derive_service_name_matches_known_orgs()
    test_derive_service_name_returns_none_for_unknown_org()
    print("\nAll ip_lookup tests passed.")
