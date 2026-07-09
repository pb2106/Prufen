/**
 * sign_credential.js — Sign a Poseidon commitment with BabyJubJub EdDSA.
 */
const { buildEddsa, buildBabyjub } = require("circomlibjs");

async function main() {
  const args = process.argv.slice(2);
  if (args.length < 2) {
    console.error(
      JSON.stringify({ error: "Usage: node sign_credential.js <privkey_hex> <commitment_bigint>" })
    );
    process.exit(1);
  }

  const privKeyHex    = args[0];
  const commitmentStr = args[1];

  // Validate inputs
  if (!/^[0-9a-fA-F]{64}$/.test(privKeyHex)) {
    console.error(JSON.stringify({ error: "privkey_hex must be 64 hex characters (32 bytes)" }));
    process.exit(1);
  }

  let commitmentBigInt;
  try {
    commitmentBigInt = BigInt(commitmentStr);
  } catch {
    console.error(JSON.stringify({ error: "commitment must be a valid BigInt decimal string" }));
    process.exit(1);
  }

  const eddsa   = await buildEddsa();
  const babyJub = await buildBabyjub();
  const F = babyJub.F;

  const privKeyBuffer = Buffer.from(privKeyHex, "hex");

  // Derive public key (for embedding in the credential)
  const pub = eddsa.prv2pub(privKeyBuffer);

  // Sign using EdDSA-Poseidon — matches EdDSAPoseidonVerifier in circomlib
  const sig = eddsa.signPoseidon(privKeyBuffer, commitmentBigInt);

  const result = {
    R8x: F.toObject(sig.R8[0]).toString(),
    R8y: F.toObject(sig.R8[1]).toString(),
    S:   sig.S.toString(),
    Ax:  F.toObject(pub[0]).toString(),
    Ay:  F.toObject(pub[1]).toString(),
  };

  console.log(JSON.stringify(result));
}

main().catch((err) => {
  console.error(JSON.stringify({ error: err.message }));
  process.exit(1);
});
