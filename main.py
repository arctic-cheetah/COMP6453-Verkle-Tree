import verkle
import sys, time, random, pickle
from statistics import mean


def get_proof_size(proof) -> int:
    """Simply serialize the proof with pickle and measure the number of bytes"""
    return len(pickle.dumps(proof))


def bench_mark(branching: int, n_init: int, n_proof: int):
    random.seed(0)
    log_print = lambda msg: print(msg, file=sys.stderr)

    t1 = time.time()
    tree = verkle.VerkleTree(branching)

    # Batch Insert
    key_values = {}
    for _ in range(n_init):
        key = random.randint(0, 2 ** 256 - 1)
        value = random.randint(0, 2 ** 256 - 1)
        tree.insert(key, value)
        key_values[key] = value
    t2 = time.time()
    log_print(f"[insert-operation result]:{n_init:<9d} keys  {t2 - t1:9.4f}s time ")

    # Compute Root Commitment
    root = tree.root_commit()
    t3 = time.time()
    log_print(f"[root commit operation:]                {t3 - t2:9.4f}s")

    # Generate Proof
    keys_samples = random.sample(list(key_values.keys()), n_proof)
    proof_sizes=[]
    prove_times = []
    for key in keys_samples:
        begin = time.time()
        proof = tree.prove(key)
        prove_times.append(time.time() - begin)
        proof_sizes.append(get_proof_size(proof))
    t4 = time.time()
    log_print(f"[prove operation:]   {n_proof:<9d} keys   {t4 - t3:9.4f}s "
        f"(avg time  {mean(prove_times):.4f}s/ key)")

    # Verification Proof
    verify_times = []
    for key in keys_samples:
        begin = time.time()
        success = tree.verify(root, key_values[key], tree.prove(key))
        verify_times.append(time.time() - begin)
        assert success, "verification failed (unhappy)!"
    t5 = time.time()
    log_print(f"[verify operations ]  {n_proof:<7d} keys   {t5 - t4:7.3f}s "
        f"(avg time {mean(verify_times):.4f}s/ key)")

    # Tab result
    sum_proof_bits = sum(proof_sizes)
    print(f"{branching}\t{n_init}\t{n_proof}\t{sum_proof_bits}"
          f"\t{t2 - t1:.6f}\t{t3 - t2:.6f}\t{t4 - t3:.6f}\t{t5 - t4:.6f}")


def main():
    # Binary verkle tree (branching 2)
    tree1 = verkle.VerkleTree(2)
    # key 5 in base-2 is [1, 0, 1]
    tree1.insert(5, 100)
    # key 10 in base-2 is [1, 0, 1, 0]
    tree1.insert(10, 200)

    tree1_root_commit = tree1.root_commit()
    print(f"Root commitment of tree1: {tree1_root_commit}")

    # proof for key 10
    tree1_proof = tree1.prove(10)
    print(f"Proof steps for key 10: {len(tree1_proof)}")

    tree1_verfn = tree1.verify(tree1_root_commit, 2025, tree1_proof)

    tree2 = verkle.VerkleTree(16)
    # 2025 in base-16 is [7, E, 9] (7 * 16^2 + (E|14) * 16^1 + 9 * 16^0)
    tree2.insert(2025, 0xdeadbeef)

    tree2_root_commit = tree2.root_commit()
    print(f"Root commitment of tree2: {tree2_root_commit}")

    tree2_proof_key_2025 = tree2.prove(2025)
    print(f"Proof16 steps for key 2025: {len(tree2_proof_key_2025)}")

    tree2_verfn = tree2.verify(tree2_root_commit, 0xdeadbeef, tree2_proof_key_2025)

    branching, n_init, n_proof = 16, 2 ** 15, 5000
    if len(sys.argv) >= 4:
        branching = int(sys.argv[1])
        n_init = int(sys.argv[2])
        n_proof = int(sys.argv[3])

    bench_mark(branching, n_init, n_proof)




if __name__ == "__main__":
    main()
