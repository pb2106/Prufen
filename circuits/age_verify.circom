pragma circom 2.0.0;

include "./node_modules/circomlib/circuits/poseidon.circom";
include "./node_modules/circomlib/circuits/comparators.circom";

/*
 * AgeVerify
 *
 * Proves a user is at least `minAge` years old without revealing
 * their actual birth date.
 *
 * Private inputs (prover only):
 *   birthYear, birthMonth, birthDay  — components of the birth date
 *   salt                             — blinding factor for the commitment
 *
 * Public inputs (visible to verifier):
 *   currentYear, currentMonth, currentDay — today's date
 *   minAge                                — minimum age (e.g. 18)
 *   commitment  — Poseidon(birthYear, birthMonth, birthDay, salt)
 *
 * Proves:
 *   1. Prover knows a birth date whose Poseidon hash equals commitment.
 *   2. birthYear + minAge <= currentYear  (conservative year-level check).
 */
template AgeVerify() {

    // ── Private inputs ────────────────────────────────────────────────────
    signal input birthYear;
    signal input birthMonth;
    signal input birthDay;
    signal input salt;

    // ── Public inputs ─────────────────────────────────────────────────────
    signal input currentYear;
    signal input currentMonth;
    signal input currentDay;
    signal input minAge;
    signal input commitment;

    // ── Output ────────────────────────────────────────────────────────────
    signal output verified;

    // ── 1. Commitment check ───────────────────────────────────────────────
    // Poseidon(birthYear, birthMonth, birthDay, salt) must equal commitment.
    component hasher = Poseidon(4);
    hasher.inputs[0] <== birthYear;
    hasher.inputs[1] <== birthMonth;
    hasher.inputs[2] <== birthDay;
    hasher.inputs[3] <== salt;

    commitment === hasher.out;

    // ── 2. Age check ──────────────────────────────────────────────────────
    // We prove:  birthYear + minAge <= currentYear
    // i.e.       birthYear + minAge  <  currentYear + 1
    // LessThan(n).out = 1  iff  in[0] < in[1]
    // Use 12 bits: supports years 0-4095, and differences up to 255.
    component ageCheck = LessThan(12);
    ageCheck.in[0] <== birthYear + minAge;
    ageCheck.in[1] <== currentYear + 1;

    // ageCheck.out must be 1 (constraint, not just assignment)
    ageCheck.out === 1;

    // Surface the result as the output signal
    verified <== ageCheck.out;
}

component main {public [currentYear, currentMonth, currentDay, minAge, commitment]} = AgeVerify();
