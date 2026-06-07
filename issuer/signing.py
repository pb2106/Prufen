"""
signing.py — BabyJubJub signing via circomlibjs Node.js subprocess.

Design principle: the issuer NEVER receives or stores raw birth dates.
Only the Poseidon commitment H(birthYear, birthMonth, birthDay, salt)
is passed to this module and forwarded to the Node.js signer.
"""
import subprocess
import json
import os
from pathlib import Path

SCRIPT_DIR       = Path(__file__).parent
SIGN_SCRIPT      = SCRIPT_DIR / "sign_credential.js"
KEYGEN_SCRIPT    = SCRIPT_DIR / "keygen.js"
PRIVATE_KEY_PATH = SCRIPT_DIR / "keys" / "bjj_private_key.hex"
PUBLIC_KEY_PATH  = SCRIPT_DIR / "keys" / "bjj_public_key.json"


def _run_node(script: Path, *args) -> dict:
    """
    Run a Node.js script and return parsed JSON output from stdout.
    Raises RuntimeError if the script exits non-zero or output is not valid JSON.
    """
    result = subprocess.run(
        ["node", str(script), *[str(a) for a in args]],
        capture_output=True,
        text=True,
        cwd=str(SCRIPT_DIR),
        timeout=30,
    )

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    if result.returncode != 0:
        raise RuntimeError(f"Node.js script failed (exit {result.returncode}): {stderr or stdout}")

    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Node.js returned non-JSON output: {stdout!r}") from exc

    if "error" in parsed:
        raise RuntimeError(f"Node.js script error: {parsed['error']}")

    return parsed


def ensure_keys() -> dict:
    """
    Generate BabyJubJub key pair if it does not already exist.
    Returns the public key dict { Ax, Ay }.
    """
    result = _run_node(KEYGEN_SCRIPT)
    return result.get("pubKey", {})


def load_public_key() -> dict:
    """
    Load the issuer's BabyJubJub public key from disk.
    Returns { Ax: str, Ay: str } — decimal strings.
    """
    if not PUBLIC_KEY_PATH.exists():
        ensure_keys()
    with open(PUBLIC_KEY_PATH, "r") as f:
        return json.load(f)


def sign_commitment(commitment: str) -> dict:
    """
    Sign a Poseidon commitment using BabyJubJub EdDSA (Poseidon variant).

    Args:
        commitment: Poseidon(birthYear, birthMonth, birthDay, salt) as a
                    decimal string.  This is the ONLY value from the user
                    that the issuer ever touches — no raw birth date.

    Returns:
        {
          "R8x": str,   # Signature component — decimal
          "R8y": str,   # Signature component — decimal
          "S":   str,   # Signature scalar   — decimal
          "Ax":  str,   # Issuer public key X — decimal
          "Ay":  str,   # Issuer public key Y — decimal
        }

    All values are decimal strings compatible with circom public/private inputs.
    """
    if not PRIVATE_KEY_PATH.exists():
        ensure_keys()

    with open(PRIVATE_KEY_PATH, "r") as f:
        priv_key_hex = f.read().strip()

    return _run_node(SIGN_SCRIPT, priv_key_hex, commitment)
