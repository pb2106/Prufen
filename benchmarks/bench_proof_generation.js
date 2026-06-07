const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const fs = require("fs");
const path = require("path");

const WASM_PATH = path.join(__dirname, "../circuits/build/age_verify_js/age_verify.wasm");
const ZKEY_PATH = path.join(__dirname, "../circuits/build/age_verify_final.zkey");

async function main() {
    console.log("Initializing bench_proof_generation.js...");
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // Fixed dummy data
    const birthYear = 1990;
    const birthMonth = 1;
    const birthDay = 1;
    const salt = 123456789;
    const currentYear = 2024;
    const currentMonth = 1;
    const currentDay = 1;
    const minAge = 18;

    const hash = poseidon([birthYear, birthMonth, birthDay, salt]);
    const commitment = F.toString(hash);

    const input = {
        birthYear,
        birthMonth,
        birthDay,
        salt,
        currentYear,
        currentMonth,
        currentDay,
        minAge,
        commitment
    };

    console.log("Warming up...");
    // Warmup
    await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH);

    const iterations = 100;
    console.log(`Running ${iterations} iterations...`);
    const times = [];

    for (let i = 0; i < iterations; i++) {
        const start = process.hrtime.bigint();
        await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH);
        const end = process.hrtime.bigint();
        const durationMs = Number(end - start) / 1e6;
        times.push(durationMs);
        process.stdout.write(`\rProgress: ${i + 1}/${iterations}`);
    }
    console.log("\n");

    times.sort((a, b) => a - b);
    const sum = times.reduce((a, b) => a + b, 0);
    const mean = sum / times.length;
    const median = times[Math.floor(times.length / 2)];
    const p95 = times[Math.floor(times.length * 0.95)];
    const p99 = times[Math.floor(times.length * 0.99)];

    console.log("--- Proof Generation Benchmark Results ---");
    console.log(`Iterations: ${iterations}`);
    console.log(`Mean:   ${mean.toFixed(2)} ms`);
    console.log(`Median: ${median.toFixed(2)} ms`);
    console.log(`P95:    ${p95.toFixed(2)} ms`);
    console.log(`P99:    ${p99.toFixed(2)} ms`);
    console.log("------------------------------------------");
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
