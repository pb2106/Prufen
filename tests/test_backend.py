"""
tests/test_backend.py
Tests for the Prüfen main backend (port 8000).
Uses FastAPI TestClient with an in-memory SQLite DB.

Run from the Prufen root:
    cd /home/naegleria/Desktop/Prufen
    pytest tests/test_backend.py -v
"""
import sys
import os
import json
import time
import base64
import pytest

# ── CRITICAL: clear any modules cached from test_issuer.py (which adds issuer/
# to sys.path and caches issuer/models.py under the name 'models').
# We must remove them BEFORE inserting the backend dir so Python re-imports
# the correct backend versions.
for _mod in list(sys.modules.keys()):
    if _mod in ('models', 'database', 'auth', 'crypto_utils', 'zk_verifier',
                'signing', 'main', 'routers') or _mod.startswith('routers.'):
        del sys.modules[_mod]

# Make backend importable
BACKEND_DIR = os.path.join(os.path.dirname(__file__), "../backend")
# Insert at position 0 so backend takes priority over anything added by test_issuer.py
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# Force an in-memory SQLite DB for tests before any import
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import models
from database import Base, get_db
from main import app

# ─── In-memory DB fixture ────────────────────────────────────────────────────

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

VERIFIER_API_KEY = "pk_test_verifier_key_1234567890abcdef"


@pytest.fixture(autouse=True)
def seed_db():
    """Seed a test verifier before each test, clean up after."""
    db = _Session()
    verifier = models.Verifier(
        verifier_id="ver_test123",
        company_name="Test Corp",
        domain="testcorp.example",
        api_key=VERIFIER_API_KEY,
        active=True,
    )
    db.add(verifier)
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


def _auth_headers():
    return {
        "Authorization": f"Bearer {VERIFIER_API_KEY}",
        "Content-Type": "application/json",
    }


def _create_request(condition="age_over_18", callback_url=None):
    body = {"condition": condition, "expires_in": 300}
    if callback_url:
        body["callback_url"] = callback_url
    return client.post("/api/proof-requests/", json=body, headers=_auth_headers())


# ─── Root / Health ───────────────────────────────────────────────────────────

class TestInfra:
    def test_root_returns_200(self):
        r = client.get("/")
        assert r.status_code == 200

    def test_health_returns_200(self):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "healthy"

    def test_jwks_returns_rsa_key(self):
        r = client.get("/.well-known/jwks.json")
        assert r.status_code == 200
        body = r.json()
        assert "keys" in body
        assert body["keys"][0]["kty"] == "RSA"
        assert body["keys"][0]["alg"] == "RS256"


# ─── Proof Request Creation ───────────────────────────────────────────────────

class TestCreateProofRequest:
    def test_valid_request_returns_201_shape(self):
        r = _create_request()
        assert r.status_code == 200
        body = r.json()
        assert "proof_request_id" in body
        assert "verifier" in body
        assert "claim" in body

    def test_missing_auth_returns_401(self):
        r = client.post("/api/proof-requests/", json={"condition": "age_over_18"})
        assert r.status_code == 401

    def test_wrong_api_key_returns_401(self):
        r = client.post(
            "/api/proof-requests/",
            json={"condition": "age_over_18"},
            headers={"Authorization": "Bearer bad_key"}
        )
        assert r.status_code == 401

    def test_response_has_expires_at(self):
        r = _create_request()
        body = r.json()
        assert "expires_at" in body

    def test_response_has_verifier_info(self):
        r = _create_request()
        body = r.json()
        assert body["verifier"]["name"] == "Test Corp"

    def test_callback_url_stored(self):
        r = _create_request(callback_url="http://example.com/webhook")
        body = r.json()
        # callback_url is echoed back
        assert body.get("callback_url") == "http://example.com/webhook"


# ─── Get Proof Request ────────────────────────────────────────────────────────

class TestGetProofRequest:
    def test_get_existing_request(self):
        create = _create_request()
        rid = create.json()["proof_request_id"]
        r = client.get(f"/api/proof-requests/{rid}")
        assert r.status_code == 200
        assert r.json()["proof_request_id"] == rid

    def test_get_nonexistent_request_returns_404(self):
        r = client.get("/api/proof-requests/does-not-exist-9999")
        assert r.status_code == 404

    def test_get_request_has_claim_type(self):
        create = _create_request("age_over_21")
        rid = create.json()["proof_request_id"]
        r = client.get(f"/api/proof-requests/{rid}")
        assert r.json()["claim_type"] == "age_over_21"

    def test_get_request_status_is_pending(self):
        create = _create_request()
        rid = create.json()["proof_request_id"]
        r = client.get(f"/api/proof-requests/{rid}")
        assert r.json()["status"] == "pending"


# ─── Reject Proof Request ─────────────────────────────────────────────────────

class TestRejectProofRequest:
    def test_reject_sets_status_rejected(self):
        create = _create_request()
        rid = create.json()["proof_request_id"]
        r = client.post(f"/api/proof-requests/{rid}/reject")
        assert r.status_code == 200
        assert r.json()["status"] == "rejected"

    def test_reject_nonexistent_returns_404(self):
        r = client.post("/api/proof-requests/no-such-id/reject")
        assert r.status_code == 404


# ─── Approve Proof Request (ZK path) ─────────────────────────────────────────

# We'll mock zk_verifier to avoid needing a real proof in unit tests
import unittest.mock as mock

DUMMY_PROOF = {
    "pi_a": ["1", "2", "3"],
    "pi_b": [["1", "2"], ["3", "4"], ["5", "6"]],
    "pi_c": ["1", "2", "3"],
    "protocol": "groth16",
    "curve": "bn128"
}
DUMMY_SIGNALS = ["1", "1", "2024", "1", "1", "18"]


class TestApproveProofRequest:
    def _approve(self, rid, nullifier="nullifier_abc123"):
        return client.post(f"/api/proof-requests/{rid}/approve", json={
            "proof": DUMMY_PROOF,
            "public_signals": DUMMY_SIGNALS,
            "nullifier_hash": nullifier
        })

    @mock.patch("zk_verifier.verify_groth16_proof", return_value=True)
    def test_valid_proof_returns_success(self, mock_verify):
        create = _create_request()
        rid = create.json()["proof_request_id"]
        r = self._approve(rid)
        assert r.status_code == 200
        assert r.json()["status"] == "success"
        assert "proof_id" in r.json()

    @mock.patch("zk_verifier.verify_groth16_proof", return_value=False)
    def test_invalid_proof_returns_400(self, mock_verify):
        create = _create_request()
        rid = create.json()["proof_request_id"]
        r = self._approve(rid)
        assert r.status_code == 400

    @mock.patch("zk_verifier.verify_groth16_proof", return_value=True)
    def test_nullifier_replay_returns_400(self, mock_verify):
        """The same nullifier_hash must be rejected on second use."""
        create1 = _create_request()
        rid1 = create1.json()["proof_request_id"]
        r1 = self._approve(rid1, nullifier="replay_nullifier_xyz")
        assert r1.status_code == 200

        # Second proof request, same nullifier
        create2 = _create_request()
        rid2 = create2.json()["proof_request_id"]
        r2 = self._approve(rid2, nullifier="replay_nullifier_xyz")
        assert r2.status_code == 400
        assert "nullifier" in r2.json()["detail"].lower()

    @mock.patch("zk_verifier.verify_groth16_proof", return_value=True)
    def test_approved_request_status_updates_to_approved(self, mock_verify):
        create = _create_request()
        rid = create.json()["proof_request_id"]
        self._approve(rid)
        r = client.get(f"/api/proof-requests/{rid}")
        assert r.json()["status"] == "approved"

    @mock.patch("zk_verifier.verify_groth16_proof", return_value=True)
    def test_approve_missing_proof_field_returns_422(self, mock_verify):
        create = _create_request()
        rid = create.json()["proof_request_id"]
        r = client.post(f"/api/proof-requests/{rid}/approve", json={
            "public_signals": DUMMY_SIGNALS,
            "nullifier_hash": "some_hash"
            # proof is missing
        })
        assert r.status_code == 422

    @mock.patch("zk_verifier.verify_groth16_proof", return_value=True)
    def test_response_never_contains_raw_dob(self, mock_verify):
        """Privacy: backend must never return birthYear/Month/Day."""
        create = _create_request()
        rid = create.json()["proof_request_id"]
        r = self._approve(rid)
        body_str = json.dumps(r.json())
        assert "birthYear" not in body_str
        assert "birthMonth" not in body_str
        assert "birthDay" not in body_str

    @mock.patch("zk_verifier.verify_groth16_proof", return_value=True)
    def test_approve_nonexistent_request_returns_404(self, mock_verify):
        r = client.post("/api/proof-requests/nonexistent/approve", json={
            "proof": DUMMY_PROOF,
            "public_signals": DUMMY_SIGNALS,
            "nullifier_hash": "some_hash"
        })
        assert r.status_code == 404


# ─── Webhook Signature ────────────────────────────────────────────────────────

class TestWebhookVerifier:
    def _signed_post(self, payload_dict, timestamp_offset=0):
        import crypto_utils
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        payload_str = json.dumps(payload_dict, separators=(',', ':'))
        timestamp = str(int(time.time()) + timestamp_offset)
        message = f"{timestamp}.{payload_str}".encode()

        private_key = crypto_utils.load_private_key()
        sig = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        sig_b64 = base64.b64encode(sig).decode()

        return client.post(
            "/api/webhooks/proof-received",
            content=payload_str,
            headers={
                "Content-Type": "application/json",
                "X-Prufen-Signature": sig_b64,
                "X-Prufen-Timestamp": timestamp,
            }
        )

    def test_valid_signed_webhook_returns_200(self):
        r = self._signed_post({"proof_request_id": "req_123", "status": "approved"})
        assert r.status_code == 200
        assert r.json()["status"] == "received_and_verified"

    def test_missing_signature_header_returns_400(self):
        r = client.post(
            "/api/webhooks/proof-received",
            content='{"proof_request_id":"req_123","status":"approved"}',
            headers={"Content-Type": "application/json"}
        )
        assert r.status_code == 400

    def test_missing_timestamp_header_returns_400(self):
        r = client.post(
            "/api/webhooks/proof-received",
            content='{"proof_request_id":"req_123","status":"approved"}',
            headers={
                "Content-Type": "application/json",
                "X-Prufen-Signature": "fakesig"
            }
        )
        assert r.status_code == 400

    def test_expired_timestamp_returns_400(self):
        """Timestamp more than 30 seconds old must be rejected."""
        r = self._signed_post(
            {"proof_request_id": "req_123", "status": "approved"},
            timestamp_offset=-60  # 60 seconds in the past
        )
        assert r.status_code == 400
        assert "expired" in r.json()["detail"].lower()

    def test_bad_signature_returns_400(self):
        payload = '{"proof_request_id":"req_123","status":"approved"}'
        timestamp = str(int(time.time()))
        r = client.post(
            "/api/webhooks/proof-received",
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-Prufen-Signature": base64.b64encode(b"totally-wrong-sig").decode(),
                "X-Prufen-Timestamp": timestamp,
            }
        )
        assert r.status_code == 400


# ─── Admin endpoints ──────────────────────────────────────────────────────────

class TestAdmin:
    def test_admin_proofs_returns_list(self):
        r = client.get("/api/admin/proofs")
        assert r.status_code == 200
        assert "proofs" in r.json()

    def test_admin_stats_returns_counts(self):
        r = client.get("/api/admin/stats")
        assert r.status_code == 200
        body = r.json()
        assert "total_proofs" in body
        assert "total_requests" in body
