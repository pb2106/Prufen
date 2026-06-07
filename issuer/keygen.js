/**
 * keygen.js — Generate BabyJubJub key pair for the Prüfen issuer.
 * Run once: node keygen.js
 * Keys are saved to ./keys/bjj_private_key.hex and ./keys/bjj_public_key.json
 */
const { buildEddsa, buildBabyjub } = require("circomlibjs");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

async function main() {
  const keysDir = path.join(__dirname, "keys");
  fs.mkdirSync(keysDir, { recursive: true });

  const privKeyPath = path.join(keysDir, "bjj_private_key.hex");
  const pubKeyPath  = path.join(keysDir, "bjj_public_key.json");

  // If keys already exist, just print the public key and exit
  if (fs.existsSync(privKeyPath) && fs.existsSync(pubKeyPath)) {
    const pubKey = JSON.parse(fs.readFileSync(pubKeyPath, "utf8"));
    console.log(JSON.stringify({ status: "exists", pubKey }));
    return;
  }

  const eddsa  = await buildEddsa();
  const babyJub = await buildBabyjub();
  const F = babyJub.F;

  // 32 random bytes — the raw BabyJubJub private key
  const privKey = crypto.randomBytes(32);
  const privKeyHex = privKey.toString("hex");

  // Derive public key
  const pub = eddsa.prv2pub(privKey);
  const pubKeyObj = {
    Ax: F.toObject(pub[0]).toString(),
    Ay: F.toObject(pub[1]).toString(),
  };

  fs.writeFileSync(privKeyPath, privKeyHex, "utf8");
  fs.writeFileSync(pubKeyPath, JSON.stringify(pubKeyObj, null, 2), "utf8");

  console.log(JSON.stringify({ status: "generated", pubKey: pubKeyObj }));
}

main().catch((err) => {
  console.error(JSON.stringify({ error: err.message }));
  process.exit(1);
});
