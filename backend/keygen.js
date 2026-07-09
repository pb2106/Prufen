/**
 * keygen.js — Generate BabyJubJub key pair for the Prüfen issuer.
 */
const { buildEddsa, buildBabyjub } = require("circomlibjs");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

async function main() {
  const args = process.argv.slice(2);
  if (args.length < 2) {
    console.error(JSON.stringify({ error: "Usage: node keygen.js <privKeyPath> <pubKeyPath>" }));
    process.exit(1);
  }

  const privKeyPath = args[0];
  const pubKeyPath  = args[1];

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
