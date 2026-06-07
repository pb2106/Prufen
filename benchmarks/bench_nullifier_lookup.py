import sqlite3
import time
import random
import string

def generate_random_hash():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=64))

def setup_db(use_index=False):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE nullifier_registry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nullifier_hash TEXT NOT NULL,
            proof_id TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    if use_index:
        cursor.execute("CREATE UNIQUE INDEX idx_nullifier_hash ON nullifier_registry(nullifier_hash)")
        
    print(f"Populating DB with 100,000 records (Index={use_index})...")
    # Insert 100k
    records = [(generate_random_hash(), f"pf_{i}") for i in range(100000)]
    cursor.executemany("INSERT INTO nullifier_registry (nullifier_hash, proof_id) VALUES (?, ?)", records)
    conn.commit()
    
    # Pick a random hash to search for later
    random_target = records[50000][0]
    
    return conn, random_target

def measure_lookup(conn, target, iterations=1000):
    cursor = conn.cursor()
    
    # Warmup
    cursor.execute("SELECT * FROM nullifier_registry WHERE nullifier_hash=?", (target,)).fetchone()
    
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        cursor.execute("SELECT * FROM nullifier_registry WHERE nullifier_hash=?", (target,)).fetchone()
        end = time.perf_counter()
        times.append((end - start) * 1000)
        
    mean = sum(times) / len(times)
    return mean

def main():
    iterations = 1000
    
    # Non-indexed
    conn_no_idx, target_no_idx = setup_db(use_index=False)
    mean_no_idx = measure_lookup(conn_no_idx, target_no_idx, iterations)
    conn_no_idx.close()
    
    # Indexed
    conn_idx, target_idx = setup_db(use_index=True)
    mean_idx = measure_lookup(conn_idx, target_idx, iterations)
    conn_idx.close()
    
    print("\n--- Nullifier Lookup Benchmark Results ---")
    print(f"Table Size: 100,000 rows")
    print(f"Queries: {iterations}")
    print(f"Mean lookup time (No Index): {mean_no_idx:.4f} ms")
    print(f"Mean lookup time (Indexed):  {mean_idx:.4f} ms")
    print("------------------------------------------")

if __name__ == "__main__":
    main()
