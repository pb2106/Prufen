# Prüfen — Privacy-Preserving Attribute Verification Protocol
![Logo](https://i.ibb.co/MTmW2vQ/logo.jpg)
**Prove facts, not data.**
*A zero-knowledge attribute verification protocol with verifier binding, cross-verifier
unlinkability, and practical mobile performance.*
![Language](https://img.shields.io/badge/LanguagePython%20%2F%20JavaScript%20%2F%20Kotlin-blue)
![ZK Backend](https://img.shields.io/badge/ZK_Backend-Circom_2.x_%2B_Groth16green)
![Curve](https://img.shields.io/badge/Curve-BN254_(128--bit_security)-orange)
![License](https://img.shields.io/badge/License-MIT-lightgrey)
![Status](https://img.shields.io/badge/Status-Research_Prototype-red)
---
# What is Prüfen?
Prüfen is a zero-knowledge attribute verification protocol designed to allow users to
prove predicates over issuer-signed credentials without revealing the underlying
personal data. Instead of exposing sensitive information such as a full date of birth,
address, or identity number, a user can prove claims like “I am over 18” using a zero
knowledge proof generated entirely on their own device.
Unlike traditional verification systems where backend servers directly inspect and
process personal data, Prüfen removes the verifier and backend from the trust chain
for attribute correctness. The user’s credential remains local to the device, and the
proof generation process happens entirely client-side using a Circom circuit and
Groth16 proving system. The backend never sees the user’s date of birth at any point
during verification.
Prüfen is designed as a research prototype accompanying an academic paper
submission and is architected with privacy-by-design principles aligned with GDPR
Article 25 and India’s DPDP Act 2023. The project focuses on practical deployment
constraints such as verifier binding, unlinkability across services, replay resistance,
and mobile-browser proof generation performance.
---
# How It Actually Works
## Old Approach (Removed)
```text
User DOB → Backend checks age → Signs JWT → Verifier
```
Problem:
- Backend saw the raw date of birth
- Verification depended on backend trust
- Not truly zero-knowledge
- Replay prevention relied mostly on policy
- Cross-verifier linkability existed
---
## Current Protocol Flow
```text
User Device holds signed credential
↓
Device runs ZK circuit locally
↓
Generates proof π + nullifier
↓
Verifier checks proof validity
```
The backend never sees the user’s date of birth. It only processes:
- proof validity
- nonce status
- nullifier uniqueness
- session integrity
---
## Protocol Actors
### Issuer (Port 8001)
The Issuer signs user credentials and maintains the issuer signing keypair.Responsibilities:
- Receives:
- DOB
- H(user_secret) commitment
- Signs credentials using BabyJubJub EdDSA
- Never sees the raw `user_secret`
- Returns signed credential to the client
In production, this role could be fulfilled by:
- Aadhaar
- DigiLocker
- Government CA
- Bank KYC authority
- University credential authority
---
### Prover (User Device)
The user device is the actual proving environment.
Responsibilities:
- Stores credential locally
- Runs `age_verify.wasm` using snarkjs
- Generates proof π locally
- Generates verifier-bound nullifier
- Submits proof to backend
The raw DOB never leaves the device after credential issuance.
---
### Verifier (Mock App)
The verifier is a registered business or relying party.
Responsibilities:
- Registers with Prüfen Registry
- Receives signed verifier certificate
- Generates signed proof requests
- Displays QR code- Receives signed webhook results
- Verifies webhook signatures before trusting results
The verifier never learns:
- DOB
- identity
- credential contents
- user_secret
---
### Backend (Port 8000)
The backend is intentionally minimized in the trust model.
Responsibilities:
- Session management
- Nonce issuance
- Nullifier registry
- Proof verification orchestration
- Signed webhook delivery
The backend is NOT trusted for:
- proof correctness
- user privacy
- age determination
---
# Security Properties
## 1. Completeness
A valid user always obtains an accepted proof.
---
## 2. Soundness
An invalid user cannot forge an accepted proof.
Security reduces to the hardness of the BN254 discrete logarithm problem.---
## 3. Zero-Knowledge
The verifier learns nothing beyond:
```text
predicate satisfied = true
```
The proof transcript is computationally indistinguishable from a simulator output.
---
## 4. Verifier Binding
A proof generated for verifier A cannot be accepted by verifier B.
This is enforced mathematically because:
```text
verifier_id
```
is a public input to the circuit.
---
## 5. Unlinkability
Two proofs from the same user at different verifiers are computationally unlinkable
even if verifiers collude.
This is achieved using:
```text
nullifier = Poseidon(user_secret, verifier_id)
```
Different verifier IDs produce different nullifiers.
---
## 6. Credential Binding
A proof requires:
- valid issuer signature
- knowledge of user_secret
Stealing the credential file alone is insufficient.
---
## Verification Policy Parameters
| Parameter | Description |
|---|---|
| nonce_ttl | Seconds before unused nonce expires |
| nonce_max_attempts | Failed submissions before nonce invalidation |
| proof_epoch_size | Seconds per nullifier epoch |
| result_ttl | Seconds backend retains proof result |
| result_max_fetch | Maximum verifier fetches |
---
# Architecture Diagram
```text
┌────────────────────────────────────────────────────────────
─┐
│ Issuer Service (8001) │
├────────────────────────────────────────────────────────────
─┤
│ POST /issue-credential │
│ Receives: dob + H(user_secret) │
│ Never receives raw user_secret │
│ Returns signed credential (BabyJubJub EdDSA) │
└────────────────────────────────────────────────────────────
─┘
│
▼
┌────────────────────────────────────────────────────────────
─┐
│ User Device (Browser / Android) │
├────────────────────────────────────────────────────────────
─┤│ - Holds credential locally (encrypted) │
│ - Runs age_verify.wasm via snarkjs │
│ - Generates proof π and nullifier locally │
│ - Verifies verifier_cert + nonce_token signatures │
│ - Submits proof + public signals to backend │
└────────────────────────────────────────────────────────────
─┘
│
▼
┌────────────────────────────────────────────────────────────
─┐
│ Backend API (8000) │
├────────────────────────────────────────────────────────────
─┤
│ - Issues signed nonce tokens │
│ - Maintains append-only nullifier registry │
│ - Verifies proof via snarkjs subprocess │
│ - Fires signed webhook to verifier │
│ - Never receives DOB │
│ - Never stores ZK proof │
└────────────────────────────────────────────────────────────
─┘
│
▼
┌────────────────────────────────────────────────────────────
─┐
│ Mock Verifier App │
├────────────────────────────────────────────────────────────
─┤
│ - Registered with Prüfen Registry │
│ - Generates signed proof requests │
│ - Receives signed webhook results │
│ - Verifies webhook signatures before trust │
└────────────────────────────────────────────────────────────
─┘
```
---
# ZK Circuit## Circuit Details
| Property | Value |
|---|---|
| File | `circuits/age_verify.circom` |
| Curve | BN254 |
| Proving System | Groth16 |
| Hash Function | Poseidon |
Poseidon is used because it is ZK-friendly and significantly more constraint-efficient
than SHA256 inside arithmetic circuits.
---
## Private Inputs (Never Leave Device)
- `dob`
- `user_secret`
- `issuer_sig_R8[2]`
- `issuer_sig_S`
- `issuer_pk[2]`
---
## Public Inputs
- `threshold_date`
- `verifier_id`
- `nonce`
- `timestamp`
---
## Public Output
```text
nullifier = Poseidon(user_secret, verifier_id)
```
---
## What the Circuit Proves
1. The issuer signed the credential
2. The credential belongs to this user
3. The DOB satisfies the threshold predicate
4. The proof is verifier-bound
5. The proof is fresh
---
## Trusted Setup
- Powers of Tau ceremony
- `pot12`
- Maximum constraints: `2^12`
---
## Constraint Count
```text
TODO: Fill from `snarkjs r1cs info`
```
---
# Performance Benchmarks
| Metric | Result |
|---|---|
| Proof generation (desktop) | TODO |
| Proof generation (Android) | TODO |
| Proof generation (p95 mobile) | TODO |
| Proof size | TODO |
| Server verification time | TODO |
| Server verification (p99) | TODO |
| Nullifier lookup (indexed) | TODO |
| Circuit constraint count | TODO |
---
## Comparison Table| System | Proof Gen Mobile | Proof Size | Verif Time | Unlinkable | Device Bound |
|---|---|---|---|---|---|
| Prüfen (ours) | TODO | TODO | TODO | Yes | Yes |
| Polygon ID | ~2000-4000ms | ~800B | ~5ms | No | No |
| JWT baseline | <1ms | ~500B | <1ms | No | No |
---
# Project Structure
```text
prufen/
├── circuits/
│ ├── age_verify.circom
│ ├── build/
│ │ ├── age_verify.r1cs
│ │ ├── age_verify_js/
│ │ ├── age_verify_final.zkey
│ │ └── verification_key.json
│ └── pot12_final.ptau
├── issuer/
│ ├── issuer_service.py
│ ├── crypto_utils_issuer.py
│ └── seed_issuer.py
├── backend/
│ ├── main.py
│ ├── models.py
│ ├── crypto_utils.py
│ ├── nullifier_registry.py
│ ├── webhook.py
│ └── verify_proof.js
├── frontend/
│ ├── src/
│ │ ├── lib/
│ │ │ ├── zkProver.js
│ │ │ ├── verifierAuth.js
│ │ │ └── credentialStore.js
│ │ ├── pages/
│ │ │ └── Setup.jsx│ │ └── components/
│ │ └── ConsentScreen.jsx
│ └── public/
│ └── zk/
│ ├── age_verify.wasm
│ ├── age_verify_final.zkey
│ └── verification_key.json
├── benchmarks/
├── tests/
└── android/
```
---
# Quick Start
## Prerequisites
- Python 3.9+
- Node.js 18+
- Rust + Circom 2.x
- snarkjs
- Android Studio
- Cloudflare Tunnel
---
## Step 1 — Circuit Compilation
```bash
cd circuits
circom age_verify.circom --r1cs --wasm --sym -o build/
```
Precompiled WASM already exists in:
```text
frontend/public/zk/
```
---## Step 2 — Issuer Service
```bash
cd issuer
pip install -r requirements.txt
python issuer_service.py
```
Runs on:
```text
http://localhost:8001
```
---
## Step 3 — Backend
```bash
cd backend
pip install -r requirements.txt
python main.py
```
Runs on:
```text
http://localhost:8000
```
API docs:
```text
http://localhost:8000/docs
```
---
## Step 4 — Frontend
```bash
cd frontend
npm install
npm run dev -- --host
```
Runs on:
```text
http://localhost:5173
```
---
## Step 5 — Mobile Testing
```bash
cloudflared tunnel --url http://localhost:5173
```
---
# Demo Flow
## First-Time Setup
1. Open:
```text
http://localhost:5173/setup
```
2. Enter DOB
3. App generates `user_secret` locally
4. App sends:
```text
{dob, H(user_secret)}
```
to issuer
5. Issuer returns signed credential
6. Credential stored locally
DOB is never transmitted again after issuance.
---
## Verification Flow
1. Visit:
```text
http://localhost:5173/mock-verifier/login
```
2. Click:
```text
Verify with Prüfen
```
3. QR code appears
4. Open Prüfen app
5. Scan QR
6. Verify verifier certificate
7. Approve verification
8. Proof generated locally
9. Backend registers nullifier
10. Verifier receives webhook result
---
# API Reference
## Issuer Service (8001)
### POST /issue-credential
```json
{
"user_id": "usr_123",
"dob_unix_timestamp": 123456789,
"user_secret_commitment": "..."
}
```
---### GET /issuer-public-key
Returns issuer public key.
---
### POST /revoke-credential
Revokes credential.
---
### GET /revocation-root
Returns revocation Merkle root.
---
## Backend API (8000)
### POST /api/proof-requests
Creates proof request.
---
### POST /api/proof-requests/{request_id}/submit-proof
Submits ZK proof.
---
### GET /api/nonce-status/{request_id}
Returns nonce state.
---
### POST /api/verifiers/register
Registers verifier.---
### GET /api/proofs/{proof_id}
Fetches proof result.
---
# Database Schema
## NullifierRegistry
| Column | Type |
|---|---|
| nullifier_hash | STRING UNIQUE INDEXED |
| verifier_id | STRING |
| timestamp | DATETIME |
| accepted | BOOLEAN |
---
## VerifierRegistry
| Column | Type |
|---|---|
| verifier_id | STRING PRIMARY KEY |
| vk_pub | STRING |
| domain | STRING |
| cert | TEXT |
| issued_at | DATETIME |
| expiry | DATETIME |
---
## ProofRequest
| Column | Type |
|---|---|
| request_id | STRING PRIMARY KEY |
| verifier_id | STRING |
| nonce | STRING || session_key_hash | STRING |
| verifier_cert | TEXT |
| timestamp | DATETIME |
| expires_at | DATETIME |
| nonce_consumed | BOOLEAN |
| max_attempts | INTEGER |
| attempt_count | INTEGER |
---
## ProofResult
| Column | Type |
|---|---|
| proof_id | STRING PRIMARY KEY |
| verifier_id | STRING |
| result | BOOLEAN |
| fetch_count | INTEGER |
| max_fetch_count | INTEGER |
| expires_at | DATETIME |
---
No table stores:
- raw DOB
- ZK proofs
---
# OWASP Top 10 Coverage
| OWASP | Attack | Defense | Enforced By |
|---|---|---|---|
| A01 Broken Access Control | Wrong verifier usage | verifier_id public input | ZK
circuit |
| A02 Cryptographic Failures | Weak crypto | EdDSA + Poseidon + BN254 | Protocol |
| A03 Injection | SQL injection | Parameterized queries | Implementation |
| A04 Insecure Design | Backend sees PII | Backend removed from trust chain |
Architecture |
| A05 Security Misconfiguration | Open endpoints | Public vk/pk constants | Protocol |
| A06 Vulnerable Components | Outdated deps | Pinned versions | Implementation |
| A07 Auth Failures | Replay attacks | Nonce + nullifier + timestamp | Protocol || A08 Integrity Failures | Tampered vk | vk hash publication | Protocol |
| A09 Logging Failures | Undetected replay | Append-only nullifier log |
Implementation |
| A10 SSRF | Malicious callbacks | Allowlist | Implementation |
---
# Security Assumptions and Limitations
## Trust Assumptions
- Honest issuer
- BN254 discrete log hardness
- Poseidon collision resistance
- Non-compromised user device
---
## Known Limitations
- Groth16 trusted setup
- Quantum vulnerability
- Physical QR substitution
- Revocation non-membership not implemented
- Issuer key compromise risk
---
# Running Tests
## Circuit Tests
```bash
cd circuits
node tests/test_circuit.js
```
---
## Issuer Tests
```bash
cd issuer
pytest tests/test_issuer.py -v
```
---
## Backend Tests
```bash
cd backend
pytest tests/test_backend.py -v
pytest tests/test_owasp.py -v
```
---
## Benchmarks
```bash
cd benchmarks
node bench_proof_generation.js
python bench_verification.py
node bench_proof_size.js
python bench_nullifier_lookup.py
bash bench_constraints.sh
```
---
# Credits and Paper
Protocol design and implementation:
- Prabhav M Naik- Nathan Marc Anthony
Research paper:
```text
TODO: Fill when submitted
```
Circuit:
- Circom 2.x with circomlib
Proving system:
- Groth16 via snarkjs
Curve:
- BN254
---
## Citation
```bibtex
TODO: Fill when paper is published
```
---
# Complete Run and Usage Guide
## Full Local Development Workflow
Open four separate terminals.
---
## Terminal 1 — Start Issuer Service
```bash
cd issuer
pip install -r requirements.txt
python issuer_service.py
```
Expected output:
```text
Running on http://localhost:8001
```
What this service does:
- Generates issuer keypair on first launch
- Issues signed credentials
- Signs DOB commitments
- Simulates trusted identity authority
Optional:
```bash
python seed_issuer.py
```
Creates demo credentials for testing.
---
## Terminal 2 — Start Backend API
```bash
cd backend
pip install -r requirements.txt
python main.py
```
Expected output:
```text
Running on http://localhost:8000
```
Open:```text
http://localhost:8000/docs
```
This opens Swagger API documentation.
What the backend does:
- Creates verification sessions
- Issues signed nonce tokens
- Tracks nullifiers
- Verifies proofs
- Sends signed webhook results
---
## Terminal 3 — Start Frontend
```bash
cd frontend
npm install
npm run dev -- --host
```
Expected output:
```text
Local: http://localhost:5173
Network: http://192.x.x.x:5173
```
Frontend includes:
- Prüfen mobile/web client
- Mock verifier app
- QR scanner
- Browser ZK prover
---
## Terminal 4 — Cloudflare Tunnel (Mobile Testing)
```bash
cloudflared tunnel --url http://localhost:5173
```
Example output:
```text
https://random-name.trycloudflare.com
```
Open this URL on your mobile device.
Why this is needed:
- Mobile browser must access local frontend
- QR verification works best across devices
- Enables realistic verifier/prover flow
---
# How To Use Prüfen
## Step 1 — Create Credential
Open:
```text
http://localhost:5173/setup
```
You will see:
- DOB input form
- Setup button
When you continue:
### Client-Side Actions
The browser:
1. Generates random `user_secret`
2. Computes:
```text
Poseidon(user_secret)```
3. Stores secret locally
### Issuer Actions
Issuer receives:
```json
{
"dob": "...",
"commitment": "Poseidon(user_secret)"
}
```
Issuer:
- signs credential
- returns credential package
### Local Storage
Credential is stored locally in:
- browser storage
- Android app storage
The backend never stores the credential.
---
## Step 2 — Open Mock Verifier
Open:
```text
http://localhost:5173/mock-verifier/login
```
Login to mock verifier.
Click:
```text
Verify with Prüfen
```This creates:
- verifier-bound session
- nonce token
- QR payload
A QR code appears.
---
## Step 3 — Scan QR
Using mobile device:
1. Open Prüfen app/homepage
2. Click:
```text
Scan QR Code
```
3. Scan verifier QR
The app validates:
- verifier certificate
- nonce signature
- request expiry
If verification fails:
- QR rejected
- proof generation blocked
---
## Step 4 — Consent Screen
The user sees:
```text
Swiggy Instamart (verified)
is requesting:
Age Verification (18+)
```
The UI also displays:
- verifier domain
- certificate validity
- expiry time
User chooses:
- Approve
- Decline
---
## Step 5 — Proof Generation
When clicking Approve:
```text
age_verify.wasm
```
runs locally in the browser.
The circuit proves:
```text
dob < threshold_date
AND
issuer signature valid
AND
commitment matches user_secret
```
without revealing:
- DOB
- credential
- identity
Outputs:
- zk proof π
- public signals
- nullifier
Expected proof generation time:- desktop: ~sub-second to few seconds
- mobile: ~1–3 seconds
---
## Step 6 — Backend Verification
Backend receives:
```json
{
"zk_proof": "...",
"public_signals": "...",
"session_commitment": "..."
}
```
Backend:
1. validates nonce
2. checks nullifier uniqueness
3. verifies proof using snarkjs
4. marks session complete
5. fires webhook to verifier
Backend never receives:
- raw DOB
- user_secret
- credential contents
---
## Step 7 — Verifier Receives Result
Verifier webhook receives:
```json
{
"proof_id": "...",
"result": true,
"verifier_id": "...",
"timestamp": "..."
}```
Verifier validates:
- webhook signature
- timestamp freshness
If valid:
```text
Verification Successful
```
appears on verifier dashboard.
---
# Desktop-Only Testing
If mobile testing is unavailable:
1. Open verifier page on desktop
2. Generate QR
3. Save QR image
4. Open Prüfen homepage in another tab
5. Upload QR image manually
6. Continue flow normally
---
# Recompiling the Circuit
Only needed after circuit modifications.
```bash
cd circuits
```
Compile circuit:
```bash
circom age_verify.circom --r1cs --wasm --sym -o build/
```
Generate proving key:
```bash
snarkjs groth16 setup \
build/age_verify.r1cs \
pot12_final.ptau \
build/age_verify_0000.zkey
```
Export verification key:
```bash
snarkjs zkey export verificationkey \
build/age_verify_final.zkey \
build/verification_key.json
```
Copy artifacts:
```bash
cp build/age_verify_js/age_verify.wasm ../frontend/public/zk/
cp build/age_verify_final.zkey ../frontend/public/zk/
cp build/verification_key.json ../frontend/public/zk/
```
---
# Common Issues
## `snarkjs: command not found`
Install globally:
```bash
npm install -g snarkjs
```
---
## `circom: command not found`Install Circom 2.x:
```bash
cargo install --git https://github.com/iden3/circom.git
```
---
## QR Scanner Not Working
Possible causes:
- browser camera permissions denied
- Cloudflare tunnel inactive
- HTTPS not enabled
- invalid verifier certificate
---
## Proof Verification Fails
Check:
- matching verification key
- matching `.zkey`
- nonce not expired
- verifier_id consistency
---
## Mobile Proof Generation Too Slow
Recommendations:
- close background apps
- use Chrome latest version
- avoid battery saver mode
- use precompiled WASM artifacts
---
# Development Notes
## Security-Critical FilesNever expose:
- issuer private key
- proving toxic waste
- backend signing secrets
Ensure these are `.gitignore`d.
---
## Publicly Shareable Files
Safe to publish:
- `.wasm`
- `verification_key.json`
- `.r1cs`
- verifier certificates
These are public protocol artifacts.
---
## Production Considerations
Current repository is a research prototype.
Production deployment would additionally require:
- HSM-backed issuer keys
- secure credential backup
- device attestation
- MPC trusted setup
- revocation proofs
- rate limiting
- certificate transparency logs