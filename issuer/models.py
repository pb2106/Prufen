"""
Pydantic models for the Prüfen Issuer service.
"""
from pydantic import BaseModel, Field
from typing import Optional


class IssueCredentialRequest(BaseModel):
    """
    Request body for POST /issue-credential.

    The issuer NEVER receives the raw birth date.
    Only the Poseidon commitment is accepted.
    """

    commitment: str = Field(
        ...,
        description=(
            "Poseidon(birthYear, birthMonth, birthDay, salt) expressed as a "
            "decimal string. Computed entirely client-side."
        ),
        examples=["7853200119776494731579049073919007882630784258459895508699754940308154824592"],
    )
    user_id: str = Field(
        ...,
        description="Opaque user identifier (e.g. sub claim from backend JWT).",
        examples=["usr_abc123def456"],
    )


class SignedCredential(BaseModel):
    """
    Credential issued by the Prüfen Issuer after signing the commitment.

    All numeric values are decimal strings for direct use as circom inputs.
    """

    commitment: str = Field(..., description="The commitment that was signed.")
    R8x: str        = Field(..., description="EdDSA signature R8 x-coordinate.")
    R8y: str        = Field(..., description="EdDSA signature R8 y-coordinate.")
    S: str          = Field(..., description="EdDSA signature scalar S.")
    Ax: str         = Field(..., description="Issuer BabyJubJub public key x.")
    Ay: str         = Field(..., description="Issuer BabyJubJub public key y.")
    issued_at: str  = Field(..., description="ISO 8601 UTC timestamp.")
    issuer: str     = Field("prufen-issuer-v1", description="Issuer identifier.")


class PublicKeyResponse(BaseModel):
    """Issuer's BabyJubJub public key."""

    Ax: str     = Field(..., description="Public key x-coordinate (decimal string).")
    Ay: str     = Field(..., description="Public key y-coordinate (decimal string).")
    issuer: str = "prufen-issuer-v1"
    curve: str  = "BabyJubJub"
    hash_function: str = "Poseidon"


class HealthResponse(BaseModel):
    status: str
    service: str
    port: int
