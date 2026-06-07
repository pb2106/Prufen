"""
ZK Proof verification using Node.js child process (snarkjs)
"""
import subprocess
import json
import os
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
VERIFY_SCRIPT = SCRIPT_DIR / "verify_proof.js"
VERIFICATION_KEY_PATH = SCRIPT_DIR.parent / "circuits" / "build" / "verification_key.json"

def verify_groth16_proof(public_signals: list, proof: dict) -> bool:
    """
    Calls snarkjs via Node.js to verify the Groth16 proof.
    """
    if not VERIFICATION_KEY_PATH.exists():
        raise FileNotFoundError(f"Verification key not found at {VERIFICATION_KEY_PATH}")

    result = subprocess.run(
        [
            "node",
            str(VERIFY_SCRIPT),
            str(VERIFICATION_KEY_PATH),
            json.dumps(public_signals),
            json.dumps(proof)
        ],
        capture_output=True,
        text=True,
        cwd=str(SCRIPT_DIR),
        timeout=10,
    )

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    if result.returncode != 0:
        raise RuntimeError(f"Node.js proof verification failed: {stderr or stdout}")

    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Node.js returned non-JSON output: {stdout!r}") from exc

    if "error" in parsed:
        raise RuntimeError(f"Proof verification error: {parsed['error']}")

    return parsed.get("valid", False)
