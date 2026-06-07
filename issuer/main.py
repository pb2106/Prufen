"""
Prüfen Issuer Service
FastAPI on port 8001

Issues BabyJubJub-signed credentials over Poseidon commitments.
The issuer NEVER receives or stores raw birth dates or user secrets.

Flow:
  1. Client computes commitment = Poseidon(birthYear, birthMonth, birthDay, salt) locally
  2. Client sends { commitment, user_id } + X-API-Key header
  3. Issuer signs the commitment with its BabyJubJub private key (via Node.js / circomlibjs)
  4. Issuer returns { R8x, R8y, S, Ax, Ay, commitment, issued_at }
  5. Client uses these values as circom inputs alongside the private birth date
"""
from fastapi import FastAPI, HTTPException, Header, status
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone
import os

import signing
from models import (
    IssueCredentialRequest,
    SignedCredential,
    PublicKeyResponse,
    HealthResponse,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ISSUER_API_KEY = os.getenv("ISSUER_API_KEY", "issuer-dev-key-change-in-production")

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Prüfen Issuer",
    description=(
        "Trusted credential issuer for the Prüfen ZK verification platform.\n\n"
        "Signs Poseidon commitments with BabyJubJub EdDSA (circomlibjs).\n\n"
        "**Privacy guarantee:** Raw birth dates are *never* received or stored. "
        "Only `Poseidon(birthYear, birthMonth, birthDay, salt)` is handled here."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------
def _require_api_key(x_api_key: str | None) -> None:
    """Validate the X-API-Key header."""
    if x_api_key != ISSUER_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header.",
        )


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def on_startup() -> None:
    """Ensure BabyJubJub keys exist before accepting requests."""
    try:
        signing.ensure_keys()
        pub = signing.load_public_key()
        print("🔑 Prüfen Issuer — BabyJubJub public key ready")
        print(f"   Ax = {pub.get('Ax', '')[:24]}...")
        print(f"   Ay = {pub.get('Ay', '')[:24]}...")
    except Exception as exc:
        print(f"⚠️  Key init failed: {exc}")
        print("   Run `npm install` inside /issuer/ then restart.")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/", tags=["Info"])
async def root():
    """Service information."""
    return {
        "service": "Prüfen Issuer",
        "version": "1.0.0",
        "port": 8001,
        "privacy_guarantee": "Raw birth dates are NEVER received or stored.",
        "curve": "BabyJubJub",
        "hash_function": "Poseidon",
        "signing_backend": "circomlibjs (Node.js via subprocess)",
        "documentation": "/docs",
    }


@app.get("/health", response_model=HealthResponse, tags=["Info"])
async def health():
    """Health check."""
    return HealthResponse(status="healthy", service="prufen-issuer", port=8001)


@app.get("/public-key", response_model=PublicKeyResponse, tags=["Keys"])
async def get_public_key():
    """
    Return the issuer's BabyJubJub public key (Ax, Ay).

    The frontend and verifiers use this to confirm the issuer signed a credential.
    Both values are decimal strings compatible with circom public inputs.
    """
    try:
        pub = signing.load_public_key()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not load public key: {exc}")

    return PublicKeyResponse(Ax=pub["Ax"], Ay=pub["Ay"])


@app.post("/issue-credential", response_model=SignedCredential, tags=["Issuer"])
async def issue_credential(
    req: IssueCredentialRequest,
    x_api_key: str | None = Header(default=None),
):
    """
    Issue a BabyJubJub-signed credential.

    **Request body:**
    - `commitment` — `Poseidon(birthYear, birthMonth, birthDay, salt)` as a decimal string.
      Computed entirely client-side. The raw birth date is **never** sent here.
    - `user_id` — opaque user identifier.

    **Response:**
    All numeric fields are decimal strings ready for direct use as circom inputs:
    `{ commitment, R8x, R8y, S, Ax, Ay, issued_at, issuer }`

    **Auth:** supply the `X-API-Key` header matching `ISSUER_API_KEY` in `.env`.
    """
    _require_api_key(x_api_key)

    # Validate that commitment looks like a Poseidon field element (large positive int)
    try:
        commitment_int = int(req.commitment)
        if commitment_int <= 0:
            raise ValueError("must be positive")
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=400,
            detail=(
                "commitment must be a positive decimal integer string — "
                "the output of Poseidon(birthYear, birthMonth, birthDay, salt)."
            ),
        )

    # Sign — the only data handed to Node.js is the commitment decimal string
    try:
        sig = signing.sign_commitment(req.commitment)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"BabyJubJub signing failed: {exc}",
        )

    return SignedCredential(
        commitment=req.commitment,
        R8x=sig["R8x"],
        R8y=sig["R8y"],
        S=sig["S"],
        Ax=sig["Ax"],
        Ay=sig["Ay"],
        issued_at=datetime.now(timezone.utc).isoformat(),
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()

    port = int(os.getenv("PORT", 8001))
    print(f"🚀 Starting Prüfen Issuer on port {port}...")
    print(f"📚 Docs:    http://localhost:{port}/docs")
    print(f"📱 Network: http://{local_ip}:{port}/docs")
    print("🔐 Privacy: Raw birth dates are NEVER received or stored.")

    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
