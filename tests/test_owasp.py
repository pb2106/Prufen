"""
tests/test_owasp.py
OWASP security hardening tests for Prüfen.
"""
import sys
import os
import json
import time
import pytest

# ── Clear any modules cached from earlier test files to avoid name collision
# between issuer/models.py and backend/models.py
for _mod in list(sys.modules.keys()):
    if _mod in ('models', 'database', 'auth', 'crypto_utils', 'zk_verifier',
                'signing', 'main', 'routers') or _mod.startswith('routers.'):
        del sys.modules[_mod]

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "../backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import models
from database import Base, get_db
from main import app

# ─── In-memory DB ────────────────────────────────────────────────────────────

_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
_Session = sessionmaker(autocommit=False, autoflush=False, bind=_engine)

def override_get_db():
    db = _Session()
    try:
        yield db
    finally:
        db.close()

Base.metadata.create_all(bind=_engine)
app.dependency_overrides[get_db] = override_get_db

VERIFIER_API_KEY = "pk_owasp_test_verifier_key_xxxxxx"

@pytest.fixture(autouse=True)
def seed():
    db = _Session()
    db.add(models.Verifier(
        verifier_id="ver_owasp_01",
        company_name="OWASP Corp",
        domain="owasp-test.example",
        api_key=VERIFIER_API_KEY,
        active=True,
    ))
    db.commit()
    yield
    db.query(models.NullifierRegistry).delete()
    db.query(models.AuditLog).delete()
    db.query(models.Proof).delete()
    db.query(models.ProofRequest).delete()
    db.query(models.UsedNonce).delete()
    db.query(models.Verifier).delete()
    db.commit()
    db.close()

client = TestClient(app)


def _auth():
    return {"Authorization": f"Bearer {VERIFIER_API_KEY}"}


# ─── A1: Injection ────────────────────────────────────────────────────────────

SQL_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE verifiers; --",
    "1; SELECT * FROM verifiers --",
    "\" OR 1=1 --",
    "' UNION SELECT null,null,null --",
]


class TestInjection:
    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sql_injection_in_request_id_returns_404_not_500(self, payload):
        """SQL injection in path param should return 4xx, never 500."""
        r = client.get(f"/api/proof-requests/{payload}")
        assert r.status_code in (404, 422, 400), \
            f"Expected 4xx for injection payload, got {r.status_code}"

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sql_injection_in_condition_does_not_leak(self, payload):
        """SQL injection in condition field should not produce a 500."""
        r = client.post("/api/proof-requests/",
            json={"condition": payload, "expires_in": 300},
            headers=_auth()
        )
        # Should succeed (condition is stored as-is, or fail 422) — never 500
        assert r.status_code != 500

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sql_injection_in_nullifier_does_not_produce_500(self, payload):
        """SQL injection in nullifier_hash field must not cause 500."""
        # We need a valid proof request first
        pr = client.post("/api/proof-requests/",
            json={"condition": "age_over_18"},
            headers=_auth()
        )
        if pr.status_code != 200:
            return
        rid = pr.json()["proof_request_id"]

        r = client.post(f"/api/proof-requests/{rid}/approve", json={
            "proof": {"pi_a": [], "pi_b": [], "pi_c": [], "protocol": "groth16", "curve": "bn128"},
            "public_signals": [],
            "nullifier_hash": payload
        })
        assert r.status_code != 500


# ─── A2: Broken Authentication ────────────────────────────────────────────────

class TestBrokenAuth:
    def test_no_token_returns_401(self):
        r = client.post("/api/proof-requests/", json={"condition": "age_over_18"})
        assert r.status_code == 401

    def test_empty_bearer_returns_401(self):
        r = client.post("/api/proof-requests/",
            json={"condition": "age_over_18"},
            headers={"Authorization": "Bearer "}
        )
        assert r.status_code == 401

    def test_malformed_header_returns_401(self):
        r = client.post("/api/proof-requests/",
            json={"condition": "age_over_18"},
            headers={"Authorization": "Token abc123"}
        )
        assert r.status_code == 401

    def test_expired_key_returns_401(self):
        r = client.post("/api/proof-requests/",
            json={"condition": "age_over_18"},
            headers={"Authorization": "Bearer pk_this_key_does_not_exist_at_all"}
        )
        assert r.status_code == 401

    def test_inactive_verifier_returns_401(self):
        db = _Session()
        db.add(models.Verifier(
            verifier_id="ver_inactive",
            company_name="Inactive Corp",
            domain="inactive.example",
            api_key="pk_inactive_key_xyz",
            active=False,
        ))
        db.commit()
        db.close()

        r = client.post("/api/proof-requests/",
            json={"condition": "age_over_18"},
            headers={"Authorization": "Bearer pk_inactive_key_xyz"}
        )
        assert r.status_code == 401


# ─── A4: Insecure Design / PII Exposure ───────────────────────────────────────

class TestPIIExposure:
    def test_create_request_response_has_no_dob(self):
        r = client.post("/api/proof-requests/",
            json={"condition": "age_over_18"},
            headers=_auth()
        )
        body_str = json.dumps(r.json())
        for field in ["birthYear", "birthMonth", "birthDay", "date_of_birth", "dob"]:
            assert field not in body_str, f"PII field {field!r} found in response"

    def test_get_request_response_has_no_dob(self):
        pr = client.post("/api/proof-requests/",
            json={"condition": "age_over_18"},
            headers=_auth()
        )
        rid = pr.json()["proof_request_id"]
        r = client.get(f"/api/proof-requests/{rid}")
        body_str = json.dumps(r.json())
        for field in ["birthYear", "birthMonth", "birthDay", "date_of_birth"]:
            assert field not in body_str

    def test_admin_proofs_has_no_dob(self):
        r = client.get("/api/admin/proofs")
        body_str = json.dumps(r.json())
        for field in ["birthYear", "birthMonth", "birthDay", "date_of_birth"]:
            assert field not in body_str

    def test_approve_cannot_accept_raw_dob(self):
        """Sending raw DOB in the approve payload must not be accepted as meaningful."""
        pr = client.post("/api/proof-requests/",
            json={"condition": "age_over_18"},
            headers=_auth()
        )
        rid = pr.json()["proof_request_id"]
        r = client.post(f"/api/proof-requests/{rid}/approve", json={
            "proof": {},
            "public_signals": [],
            "nullifier_hash": "hash_abc",
            "birthYear": 1990,   # Must be ignored
            "birthMonth": 1,
            "birthDay": 1,
        })
        # Should fail on proof verification (not because of DOB)
        # and definitely not succeed silently with PII
        assert r.status_code != 200 or "birthYear" not in json.dumps(r.json())


# ─── A5: Security Misconfiguration ───────────────────────────────────────────

class TestSecurityMisconfiguration:
    def test_error_responses_dont_expose_stack_traces(self):
        """Errors should return clean JSON, not Python tracebacks."""
        r = client.get("/api/proof-requests/nonexistent-id")
        assert r.status_code == 404
        body_str = r.text
        assert "Traceback" not in body_str
        assert "File \"" not in body_str

    def test_404_returns_json_not_html(self):
        r = client.get("/api/this-does-not-exist-9999")
        # Should return JSON or simple error, not an HTML page
        assert "text/html" not in r.headers.get("content-type", "")

    def test_root_has_privacy_guarantee(self):
        """Root endpoint should advertise privacy model."""
        r = client.get("/")
        body = r.json()
        combined = json.dumps(body).lower()
        assert "privacy" in combined or "never" in combined


# ─── A7: Identification & Authentication Failures (Replay) ────────────────────

class TestReplayAttacks:
    import unittest.mock as mock

    def test_nullifier_replay_is_blocked(self):
        """Same nullifier used twice must be rejected on second use."""
        import unittest.mock as mock

        pr1 = client.post("/api/proof-requests/",
            json={"condition": "age_over_18"},
            headers=_auth()
        )
        pr2 = client.post("/api/proof-requests/",
            json={"condition": "age_over_18"},
            headers=_auth()
        )
        rid1 = pr1.json()["proof_request_id"]
        rid2 = pr2.json()["proof_request_id"]

        shared_nullifier = "shared_nullifier_owasp_test_111"

        with mock.patch("zk_verifier.verify_groth16_proof", return_value=True):
            r1 = client.post(f"/api/proof-requests/{rid1}/approve", json={
                "proof": {"pi_a": [], "pi_b": [], "pi_c": [], "protocol": "groth16", "curve": "bn128"},
                "public_signals": ["1"],
                "nullifier_hash": shared_nullifier
            })
            assert r1.status_code == 200

            r2 = client.post(f"/api/proof-requests/{rid2}/approve", json={
                "proof": {"pi_a": [], "pi_b": [], "pi_c": [], "protocol": "groth16", "curve": "bn128"},
                "public_signals": ["1"],
                "nullifier_hash": shared_nullifier
            })
            assert r2.status_code == 400
            assert "nullifier" in r2.json()["detail"].lower()


# ─── A8: Software & Data Integrity — Webhook Signature ───────────────────────

class TestWebhookIntegrity:
    def test_webhook_without_signature_rejected(self):
        r = client.post("/api/webhooks/proof-received",
            content='{"status":"approved"}',
            headers={"Content-Type": "application/json"}
        )
        assert r.status_code == 400

    def test_webhook_with_future_timestamp_rejected(self):
        """A timestamp 60 seconds in the future is also suspicious — reject it."""
        import base64
        future_ts = str(int(time.time()) + 60)
        r = client.post("/api/webhooks/proof-received",
            content='{"status":"approved"}',
            headers={
                "Content-Type": "application/json",
                "X-Prufen-Signature": base64.b64encode(b"fake").decode(),
                "X-Prufen-Timestamp": future_ts,
            }
        )
        assert r.status_code == 400

    def test_webhook_replayed_after_30s_rejected(self):
        """Timestamp 31 seconds old must be rejected."""
        import base64
        old_ts = str(int(time.time()) - 31)
        r = client.post("/api/webhooks/proof-received",
            content='{"status":"approved"}',
            headers={
                "Content-Type": "application/json",
                "X-Prufen-Signature": base64.b64encode(b"fake").decode(),
                "X-Prufen-Timestamp": old_ts,
            }
        )
        assert r.status_code == 400

    def test_webhook_tampered_body_rejected(self):
        """A valid signature over one payload must not validate a different payload."""
        import base64
        import crypto_utils
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        original = '{"status":"approved"}'
        timestamp = str(int(time.time()))
        message = f"{timestamp}.{original}".encode()
        private_key = crypto_utils.load_private_key()
        sig = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        sig_b64 = base64.b64encode(sig).decode()

        # Send with tampered body
        r = client.post("/api/webhooks/proof-received",
            content='{"status":"rejected"}',  # Different body!
            headers={
                "Content-Type": "application/json",
                "X-Prufen-Signature": sig_b64,
                "X-Prufen-Timestamp": timestamp,
            }
        )
        assert r.status_code == 400
