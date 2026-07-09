from fastapi import APIRouter, HTTPException, Header, status
from pydantic import BaseModel
from datetime import datetime, timezone
import os

import issuer_signing
from models import IssueCredentialRequest, SignedCredential

router = APIRouter(prefix="/api", tags=["Issuer"])

ISSUER_API_KEY = os.getenv("ISSUER_API_KEY", "issuer-dev-key-change-in-production")

def _require_api_key(x_api_key: str | None) -> None:
    if x_api_key != ISSUER_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header.",
        )

@router.get("/public-key")
async def get_public_key():
    try:
        pub = issuer_signing.load_public_key()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not load public key: {exc}")
    return {"Ax": pub["Ax"], "Ay": pub["Ay"]}

@router.post("/issue-credential", response_model=SignedCredential)
async def issue_credential(
    req: IssueCredentialRequest,
    x_api_key: str | None = Header(default=None),
):
    _require_api_key(x_api_key)

    try:
        commitment_int = int(req.commitment)
        if commitment_int <= 0:
            raise ValueError("must be positive")
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=400,
            detail="commitment must be a positive decimal integer string",
        )

    try:
        sig = issuer_signing.sign_commitment(req.commitment)
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
