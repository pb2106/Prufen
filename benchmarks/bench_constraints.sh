#!/bin/bash
echo "--- Circuit Constraint Benchmark ---"
# Assuming snarkjs is installed globally or accessible in PATH
cd ../circuits/build
npx snarkjs r1cs info age_verify.r1cs
echo "------------------------------------"
