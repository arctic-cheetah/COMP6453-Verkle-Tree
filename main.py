from time import time
from random import randint
from verkle import *

NUMBER_INITIAL_KEYS = 2**15
NUMBER_ADDED_KEYS = 512
NUMBER_KEYS_PROOF = 5000
# Testing umbers below
# NUMBER_INITIAL_KEYS = 10
# NUMBER_ADDED_KEYS = 10


def main():
    tree = VerkleTree()
    values = {}
    keys = []
    upper_limit = 2**256 - 1
    # This part is fine
    time_a = time()
    for i in range(NUMBER_INITIAL_KEYS):
        key = randint(0, upper_limit).to_bytes(32, "little")
        value = randint(0, upper_limit).to_bytes(32, "little")
        tree.insert(tree.root, key, value)
        values[key] = value
        keys.append(key)
    time_b = time()
    print(
        "Inserted {0} elements in {1:.3f}s".format(
            NUMBER_INITIAL_KEYS, time_b - time_a
        )
    )

    # Inserted
    time_a = time()
    add_node_hash(tree.root)
    # add_node_hash_parallel(tree.root)
    time_b = time()
    print("Computed verkle root (insert) in {0:.3f}s".format(time_b - time_a))

    
    
    # This returns True as it should
    # proof_for_definitely_existing_key = tree.make_verkle_proof(tree, [keys[4]])
    # print(
    #     "Computed proof for definitely existing key {0} as Proof:\n\t {1}".format(
    #         int.from_bytes(keys[4], "little"), proof_for_definitely_existing_key
    #     )
    # )

    # res = tree.check_verkle_proof(
    #     tree.root.commitment.compress(),
    #     [keys[4]],
    #     [values[keys[4]]],
    #     proof_for_definitely_existing_key,
    #     False,
    # )
    # print(
    #     "Computed verification for definitely existing key {0} with Success: {1}".format(
    #         int.from_bytes(keys[4], "little"), res
    # ))   


    # This part is fine
    key_list = []
    time_a = time()
    for _ in range(NUMBER_ADDED_KEYS):
        key = randint(0, upper_limit).to_bytes(32, "little")
        key_list.append(key)
        value = randint(0, upper_limit).to_bytes(32, "little")
        tree.insert_update_node(key, value)
        values[key] = value
    time_b = time()

    print(
        "Inserted and update {0} elements in {1:.3f}s".format(
            NUMBER_ADDED_KEYS, time_b - time_a
        )
    )

    # Inserted
    time_a = time()
    add_node_hash(tree.root)
    # add_node_hash_parallel(tree.root)
    time_b = time()
    print("Computed verkle root (insert_and_update) in {0:.3f}s".format(time_b - time_a))

    time_a = time()
    proof = tree.make_verkle_proof(tree, key_list[:NUMBER_KEYS_PROOF])
    time_b = time()
    print(
        "Computed proof for {0} in {1:.3f}s".format(
            NUMBER_KEYS_PROOF, time_b - time_a
        )
    )

    # Verify the proof
    # print(key_list[:])
    time_a = time()
    res = tree.check_verkle_proof(
        tree.root.commitment.compress(),
        key_list[:NUMBER_KEYS_PROOF],
        [values[k] for k in key_list[:NUMBER_KEYS_PROOF]],
        proof,
        False,
    )
    time_b = time()
    print("Computed verification for with Success: {0} in {1:.3f}s".format(res, time_b - time_a))

    # # Binary verkle tree (branching 2)
    # tree1 = verkle.VerkleTree(2)
    # # key 5 in base-2 is [1, 0, 1]
    # tree1.insert(5, 100)
    # # key 10 in base-2 is [1, 0, 1, 0]
    # tree1.insert(10, 200)

    # tree1_root_commit = tree1.root_commit()
    # print(f"Root commitment of tree1: {tree1_root_commit}")

    # # proof for key 10
    # tree1_proof = tree1.prove(10)
    # print(f"Proof steps for key 10: {len(tree1_proof)}")

    # tree1_verfn = tree1.verify(tree1_root_commit, 2025, tree1_proof)

    # tree2 = verkle.VerkleTree(16)
    # # 2025 in base-16 is [7, E, 9] (7 * 16^2 + (E|14) * 16^1 + 9 * 16^0)
    # tree2.insert(2025, 0xDEADBEEF)

    # tree2_root_commit = tree2.root_commit()
    # print(f"Root commitment of tree2: {tree2_root_commit}")

    # tree2_proof_key_2025 = tree2.prove(2025)
    # print(f"Proof16 steps for key 2025: {len(tree2_proof_key_2025)}")

    # tree2_verfn = tree2.verify(tree2_root_commit, 0xDEADBEEF, tree2_proof_key_2025)


# TODO: Enter via here:

if __name__ == "__main__":
    main()
