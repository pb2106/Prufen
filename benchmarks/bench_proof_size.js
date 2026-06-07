const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const path = require("path");

const WASM_PATH = path.join(__dirname, "../circuits/build/age_verify_js/age_verify.wasm");
const ZKEY_PATH = path.join(__dirname, "../circuits/build/age_verify_final.zkey");

async function main() {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const hash = poseidon([1990, 1, 1, 123456789]);
    const commitment = F.toString(hash);

    const input = {
        birthYear: 1990,
        birthMonth: 1,
        birthDay: 1,
        salt: 123456789,
        currentYear: 2024,
        currentMonth: 1,
        currentDay: 1,
        minAge: 18,
        commitment
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH);

    const proofStr = JSON.stringify(proof);
    const pubStr = JSON.stringify(publicSignals);

    const proofBytes = Buffer.byteLength(proofStr, 'utf8');
    const pubBytes = Buffer.byteLength(pubStr, 'utf8');

    console.log("--- Proof Size Benchmark Results ---");
    console.log(`Proof Payload Size:        ${proofBytes} bytes`);
    console.log(`Public Signals Size:       ${pubBytes} bytes`);
    console.log(`Total Transmission Size:   ${proofBytes + pubBytes} bytes`);
    console.log("------------------------------------");
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
