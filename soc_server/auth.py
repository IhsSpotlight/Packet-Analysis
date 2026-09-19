"""
auth.py
-------
Sensor authentication for the ingestion API only. This is deliberately
NOT the user/RBAC login system (that's Step 6 — a separate concern with
separate stakes: a leaked sensor API key lets someone submit fake alerts
for one network; a leaked user session could expose every network's
data).

API keys are high-entropy random tokens (not passwords), so a fast hash
(SHA-256) is the right tool here — bcrypt/argon2's deliberate slowness is
for defending low-entropy human passwords against offline guessing, which
doesn't apply to a 256-bit random token.
"""

import hashlib
import secrets

from werkzeug.security import generate_password_hash, check_password_hash


def generate_api_key() -> str:
    """Returns a new plaintext API key. Shown to the operator ONCE at
    provisioning time — only its hash is ever stored."""
    return secrets.token_urlsafe(32)


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def extract_bearer_token(auth_header: str | None) -> str | None:
    """Parses 'Authorization: Bearer <token>' — returns None if missing
    or malformed rather than raising, so callers can just check for None."""
    if not auth_header:
        return None
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token or None


# ---------------- user passwords (Step 6: RBAC) ----------------
# Deliberately a DIFFERENT hashing scheme from sensor API keys above:
# passwords are low-entropy, human-chosen secrets, vulnerable to offline
# guessing — they need a deliberately slow, salted algorithm.
# werkzeug's default (scrypt/pbkdf2) is appropriate here; a fast hash
# like the sensor keys use above would be a real weakness for passwords.

def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return check_password_hash(password_hash, password)
