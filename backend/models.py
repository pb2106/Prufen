"""
Database models for Prüfen privacy-preserving verification platform.
"""
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, Date
from sqlalchemy.sql import func
from database import Base
import uuid


class Verifier(Base):
    """Registered verifiers who can request proofs."""
    __tablename__ = "verifiers"

    verifier_id = Column(String(50), primary_key=True, default=lambda: f"ver_{uuid.uuid4().hex[:12]}")
    company_name = Column(String(255), nullable=False)
    domain = Column(String(255), nullable=False)
    api_key = Column(String(64), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    active = Column(Boolean, default=True)


class ProofRequest(Base):
    """Verification requests created by verifiers."""
    __tablename__ = "proof_requests"

    proof_request_id = Column(String(50), primary_key=True)
    verifier_id = Column(String(50), nullable=False)
    claim_type = Column(String(100), nullable=False)  # e.g., "age_over_18"
    expires_at = Column(DateTime(timezone=True), nullable=False)
    callback_url = Column(String(500), nullable=True)
    status = Column(String(20), default="pending")  # pending, approved, expired
    presentation_result = Column(Boolean, nullable=True)  # True (Pass) / False (Fail)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class MockUser(Base):
    """Mock user accounts for demonstration (NOT for production)."""
    __tablename__ = "mock_users"

    user_id = Column(String(50), primary_key=True, default=lambda: f"usr_{uuid.uuid4().hex[:12]}")
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    name = Column(String(255), nullable=False)
    dob = Column(Date, nullable=False)  # Only for demo purposes
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Proof(Base):
    """Generated cryptographic proofs."""
    __tablename__ = "proofs"

    proof_id = Column(String(50), primary_key=True)
    user_id = Column(String(50), nullable=False)
    claim_type = Column(String(100), nullable=False)
    result = Column(Boolean, nullable=False)  # YES/NO result (no raw data!)
    verifier_hash = Column(String(64), nullable=False)  # SHA-256 of verifier API key + salt
    jwt_token = Column(Text, nullable=False)  # Signed JWT containing proof
    expires_at = Column(DateTime(timezone=True), nullable=False)
    max_access = Column(Integer, default=1)  # Single-use by default
    access_count = Column(Integer, default=0)
    accessed_at = Column(DateTime(timezone=True), nullable=True)
    deleted = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    """Immutable audit trail of all proof operations."""
    __tablename__ = "audit_log"

    log_id = Column(Integer, primary_key=True, autoincrement=True)
    proof_id = Column(String(50), nullable=False)
    action = Column(String(50), nullable=False)  # created, accessed, expired, deleted
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    extra_data = Column(Text, nullable=True)  # JSON string with additional details


class UsedNonce(Base):
    """Track used nonces to prevent replay attacks."""
    __tablename__ = "used_nonces"

    nonce = Column(String(64), primary_key=True)
    used_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)


class NullifierRegistry(Base):
    """Tracks spent nullifiers to prevent replay attacks."""
    __tablename__ = "nullifier_registry"

    id = Column(Integer, primary_key=True, autoincrement=True)
    nullifier_hash = Column(String(100), unique=True, index=True, nullable=False)
    proof_id = Column(String(50), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
