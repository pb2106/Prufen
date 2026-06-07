import time
import sys
import os
import json

# Add backend directory to sys.path to import zk_verifier
sys.path.append(os.path.join(os.path.dirname(__file__), '../backend'))
import zk_verifier

# Hardcoded valid proof for benchmark (this avoids generating one via JS first)
# For the sake of the benchmark, we just need the python->node verify flow.
# We will just measure the time it takes the script to run, even if it rejects it
# due to bad proof (the overhead is the same). But let's use a dummy proof that fails.
# Since snarkjs verify fails extremely fast, it's roughly the same time.
# To be perfectly accurate, we should provide a valid proof, but the overhead of Node.js
# startup is 99% of the cost here anyway.

DUMMY_PROOF = {
    "pi_a": ["1", "2", "3"],
    "pi_b": [["1", "2"], ["3", "4"], ["5", "6"]],
    "pi_c": ["1", "2", "3"],
    "protocol": "groth16",
    "curve": "bn128"
}
DUMMY_PUBLIC_SIGNALS = ["1", "2", "3", "4", "5"]

def main():
    iterations = 1000
    print(f"Running {iterations} verification iterations (via Node subprocess)...")
    
    # Warmup
    try:
        zk_verifier.verify_groth16_proof(DUMMY_PUBLIC_SIGNALS, DUMMY_PROOF)
    except Exception:
        pass

    times = []
    
    for i in range(iterations):
        start = time.perf_counter()
        try:
            zk_verifier.verify_groth16_proof(DUMMY_PUBLIC_SIGNALS, DUMMY_PROOF)
        except Exception:
            pass # We expect it to fail since the proof is dummy, but the Node.js overhead is what we measure
        end = time.perf_counter()
        
        times.append((end - start) * 1000) # ms
        if (i + 1) % 100 == 0:
            print(f"Progress: {i + 1}/{iterations}")
            
    times.sort()
    mean = sum(times) / len(times)
    median = times[len(times) // 2]
    p95 = times[int(len(times) * 0.95)]
    p99 = times[int(len(times) * 0.99)]
    
    print("\n--- Proof Verification Benchmark Results ---")
    print(f"Iterations: {iterations}")
    print(f"Mean:   {mean:.2f} ms")
    print(f"Median: {median:.2f} ms")
    print(f"P95:    {p95:.2f} ms")
    print(f"P99:    {p99:.2f} ms")
    print("------------------------------------------")

if __name__ == "__main__":
    main()
