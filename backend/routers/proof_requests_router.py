"""
Proof request management endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional
import uuid
import json
import httpx
import models
from database import get_db

router = APIRouter(prefix="/api/proof-requests", tags=["Proof Requests"])


class CreateProofRequestRequest(BaseModel):
    condition: str  # e.g., "age_over_18"
    expires_in: int = 300  # seconds
    callback_url: Optional[str] = None


class VerifierInfo(BaseModel):
    id: str
    name: str
    domain: str


class ClaimInfo(BaseModel):
    type: str
    display: str


class ProofRequestResponse(BaseModel):
    proof_request_id: str
    request_token: str
    verifier: VerifierInfo
    claim: ClaimInfo
    callback_url: Optional[str] = None
    expires_at: str
    issued_at: str


class ApproveProofRequestRequest(BaseModel):
    proof: dict
    public_signals: list
    nullifier_hash: str


@router.post("/", response_model=ProofRequestResponse)
async def create_proof_request(
    request: CreateProofRequestRequest,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """
    Verifier creates a proof request.
    Returns QR-encodable consent URL.
    """
    # Extract and validate API key
    print(f"DEBUG: Received authorization header: {authorization}")
    print(f"DEBUG: Request body: {request}")
    
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key"
        )
    
    api_key = authorization.replace("Bearer ", "").replace("bearer ", "")
    print(f"DEBUG: Extracted API key: {api_key[:20]}...")
    
    verifier = db.query(models.Verifier).filter_by(api_key=api_key).first()
    
    if not verifier or not verifier.active:
        print(f"DEBUG: Verifier not found or inactive for API key: {api_key[:20]}...")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    # Create proof request
    request_id = str(uuid.uuid4())
    request_token = f"req_{uuid.uuid4().hex}"
    
    proof_request = models.ProofRequest(
        proof_request_id=request_id,
        verifier_id=verifier.verifier_id,
        claim_type=request.condition,
        expires_at=datetime.utcnow() + timedelta(seconds=request.expires_in),
        callback_url=request.callback_url,
        status="pending"
    )
    
    db.add(proof_request)
    db.commit()
    
    # Return complete request details as JSON (for QR code)
    # This allows Prüfen to work offline after scanning
    return {
        "proof_request_id": request_id,
        "request_token": request_token,
        "verifier": {
            "id": verifier.verifier_id,
            "name": verifier.company_name,
            "domain": verifier.domain
        },
        "claim": {
            "type": request.condition,
            "display": "Are you 18 or older?" if request.condition == "age_over_18" else request.condition
        },
        "callback_url": request.callback_url,
        "expires_at": proof_request.expires_at.isoformat(),
        "issued_at": datetime.utcnow().isoformat()
    }


@router.get("/{request_id}")
async def get_proof_request(
    request_id: str,
    db: Session = Depends(get_db)
):
    """
    Get proof request details for consent screen.
    """
    proof_request = db.query(models.ProofRequest).filter_by(
        proof_request_id=request_id
    ).first()
    
    if not proof_request:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Proof request not found"
        )
    
    # Check expiration
    if datetime.utcnow() > proof_request.expires_at:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Proof request expired"
        )
    
    # Get verifier details
    verifier = db.query(models.Verifier).filter_by(
        verifier_id=proof_request.verifier_id
    ).first()
    
    # Map claim type to human-readable display
    claim_displays = {
        "age_over_18": "Are you 18 or older?",
        "age_over_21": "Are you 21 or older?",
        "resident_of_eu": "Are you a resident of the EU?"
    }
    
    # Get the associated proof if the request has been approved
    proof_id = None
    if proof_request.status == "approved":
        proof = db.query(models.Proof).filter_by(
            claim_type=proof_request.claim_type,
            result=proof_request.presentation_result
        ).order_by(models.Proof.created_at.desc()).first()
        if proof:
            proof_id = proof.proof_id
    
    return {
        "proof_request_id": proof_request.proof_request_id,
        "claim_type": proof_request.claim_type,
        "claim_display": claim_displays.get(
            proof_request.claim_type,
            proof_request.claim_type
        ),
        "verifier_name": verifier.company_name,
        "verifier_domain": verifier.domain,
        "expires_at": proof_request.expires_at.isoformat(),
        "status": proof_request.status,
        "presentation_result": proof_request.presentation_result,
        "proof_id": proof_id
    }



@router.post("/{request_id}/approve")
async def approve_proof_request(
    request_id: str,
    request: ApproveProofRequestRequest,
    db: Session = Depends(get_db)
):
    """
    User approves proof request.
    Generates cryptographic proof with privacy guarantees.
    """
    from jose import jwt
    from datetime import date
    import crypto_utils
    import secrets
    
    # Fetch proof request
    proof_request = db.query(models.ProofRequest).filter_by(
        proof_request_id=request_id
    ).first()
    
    if not proof_request:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Proof request not found"
        )
    
    # Check expiration
    if datetime.utcnow() > proof_request.expires_at:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Proof request expired"
        )
    
    # Get verifier
    verifier = db.query(models.Verifier).filter_by(
        verifier_id=proof_request.verifier_id
    ).first()
    
    if not verifier:
        print(f"ERROR: Verifier not found for ID {proof_request.verifier_id}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Verifier configuration missing. Please run seed_data.py."
        )

    try:
        # ============================================
        # CRITICAL: Verify ZK Proof via Node.js
        # Raw DOB is NEVER received by the backend
        # ============================================
        import zk_verifier
        
        # 1. Check Nullifier to prevent replay attacks
        if db.query(models.NullifierRegistry).filter_by(nullifier_hash=request.nullifier_hash).first():
            raise HTTPException(status_code=400, detail="Proof has already been used (nullifier spent).")
            
        # 2. Verify Groth16 Proof
        is_valid = zk_verifier.verify_groth16_proof(request.public_signals, request.proof)
        if not is_valid:
            raise HTTPException(status_code=400, detail="Invalid Zero-Knowledge Proof.")
            
        result = True  # If the proof is valid, the condition (e.g. age) is met
        
        # Generate verifier binding
        salt = crypto_utils.generate_salt()
        verifier_hash = crypto_utils.compute_verifier_hash(verifier.api_key, salt)
        
        # Generate nonce for replay protection
        nonce = crypto_utils.generate_nonce()
        
        # Generate proof ID
        proof_id = f"pf_{uuid.uuid4().hex[:12]}"
        
        # Create JWT payload (contains NO raw PII)
        payload = {
            "sub": proof_id,
            "claim": proof_request.claim_type,
            "result": result,  # YES/NO only!
            "verifier_hash": verifier_hash,
            "salt": salt,
            "nonce": nonce,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(seconds=300)
        }
        
        # Sign with private key
        private_key = crypto_utils.load_private_key_bytes()
        jwt_token = jwt.encode(
            payload,
            private_key,
            algorithm="RS256",
            headers={"kid": "prufen-2024-01"}
        )
        
        # Store proof
        proof = models.Proof(
            proof_id=proof_id,
            user_id="zk-anonymous-user",  # User ID is now hidden from the backend
            claim_type=proof_request.claim_type,
            result=result,
            verifier_hash=verifier_hash,
            jwt_token=jwt_token,
            expires_at=datetime.utcnow() + timedelta(seconds=300),
            max_access=1,
            access_count=0
        )
        
        db.add(proof)
        
        # Update proof request status and result
        proof_request.status = "approved"
        proof_request.presentation_result = result
        
        # Audit log
        audit = models.AuditLog(
            proof_id=proof_id,
            action="created",
            extra_data=json.dumps({
                "claim_type": proof_request.claim_type,
                "data_deleted": True,
                "privacy_preserved": True
            })
        )
        
        db.add(audit)
        
        # Store nullifier to prevent replay
        nullifier_entry = models.NullifierRegistry(
            nullifier_hash=request.nullifier_hash,
            proof_id=proof_id
        )
        db.add(nullifier_entry)
        
        # Store nonce to prevent replay (legacy if needed, or remove)
        used_nonce = models.UsedNonce(
            nonce=nonce,
            expires_at=datetime.utcnow() + timedelta(seconds=300)
        )
        db.add(used_nonce)
        db.commit()
        
        # Send webhook notification if provided
        if proof_request.callback_url:
            try:
                import base64
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import padding
                
                payload = {
                    "proof_request_id": request_id,
                    "status": "approved",
                    "proof_url": f"http://localhost:8000/api/proofs/{proof_id}"
                }
                payload_str = json.dumps(payload, separators=(',', ':'))
                timestamp = str(int(datetime.utcnow().timestamp()))
                
                message = f"{timestamp}.{payload_str}".encode()
                
                private_key = crypto_utils.load_private_key()
                signature = private_key.sign(
                    message,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                signature_b64 = base64.b64encode(signature).decode()
                
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(
                        proof_request.callback_url,
                        content=payload_str,
                        headers={
                            "Content-Type": "application/json",
                            "X-Prufen-Signature": signature_b64,
                            "X-Prufen-Timestamp": timestamp
                        }
                    )
            except Exception as e:
                print(f"Webhook delivery failed: {e}")
                # Continue even if webhook fails
                
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"CRITICAL ERROR in approve_proof_request: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal error generating proof: {str(e)}"
        )
    
    return {
        "status": "success",
        "proof_id": proof_id,
        "message": "Proof generated. Your data has been deleted from memory."
    }


@router.post("/{request_id}/reject")
async def reject_proof_request(
    request_id: str,
    db: Session = Depends(get_db)
):
    """
    User rejects proof request.
    """
    # Fetch proof request
    proof_request = db.query(models.ProofRequest).filter_by(
        proof_request_id=request_id
    ).first()
    
    if not proof_request:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Proof request not found"
        )
    
    # Update status
    proof_request.status = "rejected"
    db.commit()
    
    # Send webhook notification if provided
    if proof_request.callback_url:
        try:
            import json
            import base64
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            import crypto_utils
            from datetime import datetime
            
            payload = {
                "proof_request_id": request_id,
                "status": "rejected"
            }
            payload_str = json.dumps(payload, separators=(',', ':'))
            timestamp = str(int(datetime.utcnow().timestamp()))
            
            message = f"{timestamp}.{payload_str}".encode()
            
            private_key = crypto_utils.load_private_key()
            signature = private_key.sign(
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            signature_b64 = base64.b64encode(signature).decode()
            
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(
                    proof_request.callback_url,
                    content=payload_str,
                    headers={
                        "Content-Type": "application/json",
                        "X-Prufen-Signature": signature_b64,
                        "X-Prufen-Timestamp": timestamp
                    }
                )
        except Exception as e:
            print(f"Webhook delivery failed: {e}")
            
    return {"status": "rejected"}
