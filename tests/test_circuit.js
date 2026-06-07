/**
 * tests/test_circuit.js
 * ZK circuit tests — uses snarkjs directly against the compiled WASM + zkey.
 * Run from the Prufen root: node tests/test_circuit.js
 */
const snarkjs = require("snarkjs");
const assert = require("assert");
const path = require("path");

const WASM  = path.join(__dirname, "../circuits/build/age_verify_js/age_verify.wasm");
const ZKEY  = path.join(__dirname, "../circuits/build/age_verify_final.zkey");
const VKEY  = path.join(__dirname, "../circuits/build/verification_key.json");

const { buildPoseidon } = require("circomlibjs");

let poseidon, F, vKey;
let passed = 0, failed = 0;

function ok(label, cond) {
    if (cond) { console.log(`  ✅ PASS: ${label}`); passed++; }
    else       { console.error(`  ❌ FAIL: ${label}`); failed++; }
}

async function commitment(year, month, day, salt) {
    const h = poseidon([year, month, day, salt]);
    return F.toString(h);
}

// ────────────────────────────────────────────────
async function test_valid_adult_proof() {
    console.log("\ntest_valid_adult_proof");
    const c = await commitment(1990, 1, 1, 123456789);
    const input = {
        birthYear: 1990, birthMonth: 1, birthDay: 1, salt: 123456789,
        currentYear: 2024, currentMonth: 6, currentDay: 1,
        minAge: 18, commitment: c
    };
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const valid = await snarkjs.groth16.verify(vKey, publicSignals, proof);
    ok("valid adult proof verifies", valid === true);
    ok("publicSignals is array", Array.isArray(publicSignals));
    ok("proof has pi_a pi_b pi_c", proof.pi_a && proof.pi_b && proof.pi_c);
}

async function test_valid_exactly_18() {
    console.log("\ntest_valid_exactly_18");
    // born in 2006, checking in 2024 → exactly 18
    const c = await commitment(2006, 1, 1, 555);
    const input = {
        birthYear: 2006, birthMonth: 1, birthDay: 1, salt: 555,
        currentYear: 2024, currentMonth: 6, currentDay: 1,
        minAge: 18, commitment: c
    };
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const valid = await snarkjs.groth16.verify(vKey, publicSignals, proof);
    ok("exactly-18 proof verifies", valid === true);
}

async function test_wrong_commitment_rejected() {
    console.log("\ntest_wrong_commitment_rejected");
    // Provide a mismatched commitment — fullProve should throw because constraint fails
    const wrongCommitment = "12345678901234567890"; // Not the real Poseidon hash
    const input = {
        birthYear: 1990, birthMonth: 1, birthDay: 1, salt: 123456789,
        currentYear: 2024, currentMonth: 6, currentDay: 1,
        minAge: 18, commitment: wrongCommitment
    };
    try {
        await snarkjs.groth16.fullProve(input, WASM, ZKEY);
        ok("bad commitment should have thrown", false);
    } catch(e) {
        ok("bad commitment throws constraint error", true);
    }
}

async function test_underage_rejected() {
    console.log("\ntest_underage_rejected");
    // born in 2010, asking for age >= 18 in 2024 → should fail (only 14)
    const c = await commitment(2010, 1, 1, 999);
    const input = {
        birthYear: 2010, birthMonth: 1, birthDay: 1, salt: 999,
        currentYear: 2024, currentMonth: 6, currentDay: 1,
        minAge: 18, commitment: c
    };
    try {
        await snarkjs.groth16.fullProve(input, WASM, ZKEY);
        ok("underage should have thrown", false);
    } catch(e) {
        ok("underage birthYear fails circuit constraint", true);
    }
}

async function test_age_21_check() {
    console.log("\ntest_age_21_check");
    const c = await commitment(1990, 1, 1, 77777);
    const input = {
        birthYear: 1990, birthMonth: 1, birthDay: 1, salt: 77777,
        currentYear: 2024, currentMonth: 6, currentDay: 1,
        minAge: 21, commitment: c
    };
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const valid = await snarkjs.groth16.verify(vKey, publicSignals, proof);
    ok("age_21 proof verifies for 1990-born user", valid === true);
}

async function test_tampered_proof_rejected() {
    console.log("\ntest_tampered_proof_rejected");
    const c = await commitment(1990, 1, 1, 123456789);
    const input = {
        birthYear: 1990, birthMonth: 1, birthDay: 1, salt: 123456789,
        currentYear: 2024, currentMonth: 6, currentDay: 1,
        minAge: 18, commitment: c
    };
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    // Tamper with the proof
    const tampered = JSON.parse(JSON.stringify(proof));
    tampered.pi_a[0] = "1";
    const valid = await snarkjs.groth16.verify(vKey, publicSignals, tampered);
    ok("tampered proof is rejected", valid === false);
}

async function test_proof_payload_size() {
    console.log("\ntest_proof_payload_size");
    const c = await commitment(1990, 1, 1, 123456789);
    const input = {
        birthYear: 1990, birthMonth: 1, birthDay: 1, salt: 123456789,
        currentYear: 2024, currentMonth: 6, currentDay: 1,
        minAge: 18, commitment: c
    };
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const total = Buffer.byteLength(JSON.stringify(proof) + JSON.stringify(publicSignals), "utf8");
    ok(`proof payload <2 KB (actual: ${total} bytes)`, total < 2048);
}

// ────────────────────────────────────────────────
async function main() {
    const fs = require("fs");
    vKey = JSON.parse(fs.readFileSync(VKEY, "utf8"));
    poseidon = await buildPoseidon();
    F = poseidon.F;

    console.log("=== tests/test_circuit.js ===");

    await test_valid_adult_proof();
    await test_valid_exactly_18();
    await test_wrong_commitment_rejected();
    await test_underage_rejected();
    await test_age_21_check();
    await test_tampered_proof_rejected();
    await test_proof_payload_size();

    console.log(`\n=== Circuit Tests: ${passed + failed} total | ${passed} passed | ${failed} failed ===`);
    process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => { console.error(err); process.exit(1); });
