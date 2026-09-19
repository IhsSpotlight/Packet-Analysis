"""
test_auth.py
------------
Run: python3 test_auth.py
"""

from auth import generate_api_key, hash_api_key, extract_bearer_token, hash_password, verify_password


def test_generate_api_key_is_random_and_long_enough():
    a = generate_api_key()
    b = generate_api_key()
    assert a != b
    assert len(a) >= 32  # high-entropy, not a short guessable token
    print("PASS: test_generate_api_key_is_random_and_long_enough")


def test_hash_is_deterministic_and_one_way():
    key = "some-api-key-value"
    h1 = hash_api_key(key)
    h2 = hash_api_key(key)
    assert h1 == h2, "same input must hash the same way, or lookups would never match"
    assert h1 != key, "hash must not just be the plaintext"
    print("PASS: test_hash_is_deterministic_and_one_way")


def test_different_keys_hash_differently():
    assert hash_api_key("key-a") != hash_api_key("key-b")
    print("PASS: test_different_keys_hash_differently")


def test_extract_bearer_token_valid():
    assert extract_bearer_token("Bearer abc123") == "abc123"
    print("PASS: test_extract_bearer_token_valid")


def test_extract_bearer_token_missing_or_malformed():
    assert extract_bearer_token(None) is None
    assert extract_bearer_token("") is None
    assert extract_bearer_token("abc123") is None            # no scheme
    assert extract_bearer_token("Basic abc123") is None       # wrong scheme
    assert extract_bearer_token("Bearer ") is None             # empty token
    print("PASS: test_extract_bearer_token_missing_or_malformed")


def test_password_hash_verifies_correctly():
    h = hash_password("correct-horse-battery-staple")
    assert verify_password("correct-horse-battery-staple", h) is True
    assert verify_password("wrong-password", h) is False
    print("PASS: test_password_hash_verifies_correctly")


def test_password_hash_is_not_plaintext():
    password = "my-secret-password"
    h = hash_password(password)
    assert h != password
    print("PASS: test_password_hash_is_not_plaintext")


def test_password_hash_uses_distinct_scheme_from_api_key_hash():
    # sanity check that these are genuinely different code paths — a
    # password run through the API-key hasher should NOT verify as a
    # password (different algorithms, different output shapes)
    api_key_style_hash = hash_api_key("some-password")
    assert not api_key_style_hash.startswith("scrypt:") and not api_key_style_hash.startswith("pbkdf2:")
    password_style_hash = hash_password("some-password")
    assert password_style_hash != api_key_style_hash
    print("PASS: test_password_hash_uses_distinct_scheme_from_api_key_hash")


if __name__ == "__main__":
    test_generate_api_key_is_random_and_long_enough()
    test_hash_is_deterministic_and_one_way()
    test_different_keys_hash_differently()
    test_extract_bearer_token_valid()
    test_extract_bearer_token_missing_or_malformed()
    test_password_hash_verifies_correctly()
    test_password_hash_is_not_plaintext()
    test_password_hash_uses_distinct_scheme_from_api_key_hash()
    print("\nAll auth tests passed.")
