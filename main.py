from time import time
from random import randint, shuffle
from verkle import *

NUMBER_INITIAL_KEYS = 2**15
NUMBER_ADDED_KEYS = 512
NUMBER_KEYS_PROOF = 5000
NUMBER_DELETED_KEYS = 512
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
        "Inserted {0} elements in {1:.3f}s".format(NUMBER_INITIAL_KEYS, time_b - time_a)
    )

    # Inserted
    time_a = time()
    add_node_hash(tree.root)
    # add_node_hash_parallel(tree.root)
    time_b = time()
    print("Computed verkle root (insert) in {0:.3f}s".format(time_b - time_a))

    time_a = time()
    checkValidTree(tree.root)
    time_b = time()
    print("Check that verkle tree is valid in {0:.3f}s".format(time_b - time_a))

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
        try:
            key = randint(0, upper_limit).to_bytes(32, "little")
            value = randint(0, upper_limit).to_bytes(32, "little")
            val = tree.insert_update_node(key, value)
            if val == False:
                raise Exception("Insertion failed")
        except:
            while True:
                key = randint(0, upper_limit).to_bytes(32, "little")
                value = randint(0, upper_limit).to_bytes(32, "little")
                val = tree.insert_update_node(key, value)
                if val:
                    break
        finally:
            key_list.append(key)
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
    print(
        "Computed verkle root (insert_and_update) in {0:.3f}s".format(time_b - time_a)
    )

    time_a = time()
    proof = tree.make_verkle_proof(tree, key_list[:NUMBER_KEYS_PROOF])
    time_b = time()
    print(
        "Computed proof for {0} in {1:.3f}s".format(NUMBER_KEYS_PROOF, time_b - time_a)
    )

    # Verify the proof
    time_a = time()
    res = tree.check_verkle_proof(
        tree.root.commitment.compress(),
        key_list[:NUMBER_KEYS_PROOF],
        [values[k] for k in key_list[:NUMBER_KEYS_PROOF]],
        proof,
        False,
    )
    time_b = time()
    print(
        "Computed Successful verification: {0} in {1:.3f}s".format(res, time_b - time_a)
    )

    res = tree.check_verkle_proof(
        tree.root.commitment.compress(),
        key_list[:2],
        [values[k] for k in key_list[:2]],
        proof,
        False,
    )
    time_b = time()
    print(
        "Computed verification with wrong keys: {0} in {1:.3f}s".format(
            res, time_b - time_a
        )
    )

    # Node deletion:
    all_keys = list(values.keys())
    shuffle(all_keys)
    keys_to_delete = all_keys[:NUMBER_DELETED_KEYS]

    time_a = time()
    for key in keys_to_delete:
        tree.delete(key)
        del values[key]
    time_b = time()

    print(
        "Deleted {0} elements in {1:.3f} s".format(
            NUMBER_DELETED_KEYS, time_b - time_a
        ),
    )
    time_a = time()
    checkValidTree(tree.root)
    time_b = time()
    print("Check that verkle tree is valid in {0:.3f}s".format(time_b - time_a))

    # tree2_verfn = tree2.verify(tree2_root_commit, 0xDEADBEEF, tree2_proof_key_2025)


# TODO: Enter via here:

if __name__ == "__main__":
    main()
