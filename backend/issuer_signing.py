"""
issuer_signing.py — BabyJubJub signing via the signer service over HTTP.

Keys are sourced exclusively from environment variables. Generate them once
locally with keygen.js, then set them in Vercel's dashboard.

Required env vars:
  SIGNER_SERVICE_URL       — Internal URL of the signer Vercel service
  SIGNER_PRIVATE_KEY_HEX   — 64-char hex BabyJubJub private key (Secret)
  ISSUER_PUBKEY_AX         — Issuer public key x-coordinate (decimal string)
  ISSUER_PUBKEY_AY         — Issuer public key y-coordinate (decimal string)
"""
import os
import httpx


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"{name} is not set. Generate a keypair locally with keygen.js "
            f"and configure all required env vars in Vercel before deploying."
        )
    return value


def load_public_key() -> dict:
    """Return the issuer's BabyJubJub public key { Ax, Ay } from env vars."""
    return {
        "Ax": _require_env("ISSUER_PUBKEY_AX"),
        "Ay": _require_env("ISSUER_PUBKEY_AY"),
    }


def sign_commitment(commitment: str) -> dict:
    """
    Sign a Poseidon commitment by calling the signer service.
    Returns { R8x, R8y, S, Ax, Ay } — all decimal strings.
    """
    signer_url = _require_env("SIGNER_SERVICE_URL")
    priv_key = _require_env("SIGNER_PRIVATE_KEY_HEX")

    resp = httpx.post(
        f"{signer_url}/api/sign",
        json={"privKeyHex": priv_key, "commitment": commitment},
        timeout=30,
    )
    resp.raise_for_status()

    result = resp.json()
    if "error" in result:
        raise RuntimeError(f"Signer service error: {result['error']}")

    return result