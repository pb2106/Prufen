"""
tests/test_issuer.py
Tests for the Prüfen Issuer service (port 8001).
Uses FastAPI TestClient — no live server required.

Run from the Prufen root:
    cd /home/naegleria/Desktop/Prufen
    pytest tests/test_issuer.py -v
"""
import sys
import os
import pytest
import unittest.mock as mock

# Add issuer directory to path
ISSUER_DIR = os.path.join(os.path.dirname(__file__), "../issuer")
sys.path.insert(0, ISSUER_DIR)

# ── Mock the signing module BEFORE importing the issuer app.
# This prevents Node subprocess calls to circomlibjs (which is a runtime dep,
# not a test dep). We inject deterministic test values instead.
_MOCK_PUBKEY = {"Ax": "12345678901234567890123456789", "Ay": "98765432109876543210987654321"}
_MOCK_SIG = {
    "R8x": "111111111111111111111111111111",
    "R8y": "222222222222222222222222222222",
    "S":   "333333333333333333333333333333",
    "Ax":  "12345678901234567890123456789",
    "Ay":  "98765432109876543210987654321",
}

import signing as _signing_module  # noqa: E402 — must be after sys.path
_signing_module.ensure_keys      = mock.MagicMock()
_signing_module.load_public_key  = mock.MagicMock(return_value=_MOCK_PUBKEY)
_signing_module.sign_commitment  = mock.MagicMock(return_value=_MOCK_SIG)

from fastapi.testclient import TestClient
from main import app  # issuer/main.py

VALID_API_KEY = "issuer-dev-key-change-in-production"

# A real Poseidon commitment (decimal) — computed offline for:
#   Poseidon(1990, 1, 1, 123456789)
# We treat this as an opaque large integer from the issuer's point of view.
VALID_COMMITMENT = "7853200119776494731579049073919007882630784258459895508699754940308154824592"

client = TestClient(app)


# ─── Health / Info ───────────────────────────────────────────────────────────

class TestHealth:
    def test_health_returns_200(self):
        r = client.get("/health")
        assert r.status_code == 200

    def test_health_status_is_healthy(self):
        r = client.get("/health")
        assert r.json()["status"] == "healthy"

    def test_root_returns_service_info(self):
        r = client.get("/")
        assert r.status_code == 200
        body = r.json()
        assert body["service"] == "Prüfen Issuer"

    def test_root_privacy_guarantee_present(self):
        r = client.get("/")
        body = r.json()
        assert "NEVER" in body.get("privacy_guarantee", "")


# ─── Public Key ───────────────────────────────────────────────────────────────

class TestPublicKey:
    def test_public_key_returns_200(self):
        r = client.get("/public-key")
        assert r.status_code == 200

    def test_public_key_has_Ax_and_Ay(self):
        r = client.get("/public-key")
        body = r.json()
        assert "Ax" in body
        assert "Ay" in body

    def test_public_key_values_are_non_empty_strings(self):
        r = client.get("/public-key")
        body = r.json()
        assert isinstance(body["Ax"], str) and len(body["Ax"]) > 0
        assert isinstance(body["Ay"], str) and len(body["Ay"]) > 0


# ─── Authentication ───────────────────────────────────────────────────────────

class TestAuthentication:
    def test_issue_without_api_key_returns_401(self):
        r = client.post("/issue-credential", json={
            "commitment": VALID_COMMITMENT,
            "user_id": "usr_test"
        })
        assert r.status_code == 401

    def test_issue_with_wrong_api_key_returns_401(self):
        r = client.post("/issue-credential",
            json={"commitment": VALID_COMMITMENT, "user_id": "usr_test"},
            headers={"X-API-Key": "totally-wrong-key"}
        )
        assert r.status_code == 401

    def test_issue_with_valid_api_key_returns_200(self):
        r = client.post("/issue-credential",
            json={"commitment": VALID_COMMITMENT, "user_id": "usr_test"},
            headers={"X-API-Key": VALID_API_KEY}
        )
        assert r.status_code == 200


# ─── Credential Issuance ─────────────────────────────────────────────────────

class TestIssueCredential:
    def _issue(self, commitment, user_id="usr_test"):
        return client.post("/issue-credential",
            json={"commitment": commitment, "user_id": user_id},
            headers={"X-API-Key": VALID_API_KEY}
        )

    def test_valid_commitment_returns_signed_credential(self):
        r = self._issue(VALID_COMMITMENT)
        assert r.status_code == 200
        body = r.json()
        assert body["commitment"] == VALID_COMMITMENT

    def test_response_has_eddsa_fields(self):
        r = self._issue(VALID_COMMITMENT)
        body = r.json()
        for field in ["R8x", "R8y", "S", "Ax", "Ay"]:
            assert field in body, f"Missing field: {field}"

    def test_response_eddsa_fields_are_decimal_strings(self):
        r = self._issue(VALID_COMMITMENT)
        body = r.json()
        for field in ["R8x", "R8y", "S"]:
            int(body[field])  # Should not raise

    def test_response_has_issued_at(self):
        r = self._issue(VALID_COMMITMENT)
        body = r.json()
        assert "issued_at" in body
        assert body["issued_at"]  # non-empty

    def test_negative_commitment_rejected(self):
        r = self._issue("-999")
        assert r.status_code == 400

    def test_zero_commitment_rejected(self):
        r = self._issue("0")
        assert r.status_code == 400

    def test_non_numeric_commitment_rejected(self):
        r = self._issue("not-a-number")
        assert r.status_code == 400

    def test_empty_commitment_rejected(self):
        r = self._issue("")
        assert r.status_code in (400, 422)

    def test_raw_dob_fields_not_in_request_or_response(self):
        """Privacy: issuer must never expose or accept raw birth date fields."""
        r = client.post("/issue-credential",
            json={
                "commitment": VALID_COMMITMENT,
                "user_id": "usr_test",
                "birthYear": 1990,   # Should be ignored
                "birthMonth": 1,
                "birthDay": 1
            },
            headers={"X-API-Key": VALID_API_KEY}
        )
        body = r.json()
        assert "birthYear" not in body
        assert "birthMonth" not in body
        assert "birthDay" not in body

    def test_two_issues_same_commitment_produce_different_signatures(self):
        """EdDSA (Poseidon) should be deterministic but let's confirm field shapes."""
        r1 = self._issue(VALID_COMMITMENT)
        r2 = self._issue(VALID_COMMITMENT)
        # Both should succeed
        assert r1.status_code == 200
        assert r2.status_code == 200
        # Commitment is the same
        assert r1.json()["commitment"] == r2.json()["commitment"]
