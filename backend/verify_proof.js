/**
 * verify_proof.js - Verify a Groth16 proof using snarkjs
 * Usage: node verify_proof.js <verification_key_path> <public_signals_json_string> <proof_json_string>
 */
const snarkjs = require("snarkjs");
const fs = require("fs");

async function main() {
    const args = process.argv.slice(2);
    if (args.length !== 3) {
        console.error(JSON.stringify({ error: "Invalid number of arguments" }));
        process.exit(1);
    }

    const [vKeyPath, publicSignalsStr, proofStr] = args;

    try {
        const vKey = JSON.parse(fs.readFileSync(vKeyPath, "utf8"));
        const publicSignals = JSON.parse(publicSignalsStr);
        const proof = JSON.parse(proofStr);

        const res = await snarkjs.groth16.verify(vKey, publicSignals, proof);
        console.log(JSON.stringify({ valid: res }));
    } catch (err) {
        console.error(JSON.stringify({ error: err.message }));
        process.exit(1);
    }
}

main().catch(err => {
    console.error(JSON.stringify({ error: err.message }));
    process.exit(1);
});
