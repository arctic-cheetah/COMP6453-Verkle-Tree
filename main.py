from time import time
from random import randint, shuffle
from verkle import *

NUMBER_INITIAL_KEYS = 2**15
NUMBER_ADDED_KEYS = 512
NUMBER_KEYS_PROOF = 5000
NUMBER_DELETED_KEYS = 512



def main():
    """
    Main function demonstrating Verkle tree operations.
    
    This function performs a comprehensive test of the Verkle tree implementation:
    1. Inserts initial set of key-value pairs
    2. Computes and validates the tree structure
    3. Inserts additional key-value pairs with immediate updates
    4. Creates and verifies proofs for a subset of keys
    5. Deletes a subset of keys and validates the tree
    
    The function measures and reports timing for each operation to assess performance.
    """
    tree = VerkleTree()
    values = {}
    keys = []
    upper_limit = 2**256 - 1
    
    # Insert initial set of key-value pairs
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

    # Compute root commitment for initial tree
    time_a = time()
    add_node_hash(tree.root)
    time_b = time()
    print("Computed verkle root (insert) in {0:.3f}s".format(time_b - time_a))

    # Validate the tree structure
    time_a = time()
    checkValidTree(tree.root)
    time_b = time()
    print("Check that verkle tree is valid in {0:.3f}s".format(time_b - time_a))

    # Insert additional key-value pairs with immediate updates
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

    # Compute root commitment for updated tree
    time_a = time()
    add_node_hash(tree.root)
    time_b = time()
    print(
        "Computed verkle root (insert_and_update) in {0:.3f}s".format(time_b - time_a)
    )

    # Create proof for a subset of keys
    time_a = time()
    proof = tree.make_verkle_proof(tree, key_list[:NUMBER_KEYS_PROOF])
    time_b = time()
    print(
        "Computed proof for {0} in {1:.3f}s".format(NUMBER_KEYS_PROOF, time_b - time_a)
    )

    # Verify the proof with correct keys
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

    # Verify the proof with incorrect keys (should fail)
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

    # Delete a subset of keys
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
    
    # Validate the tree after deletions
    time_a = time()
    checkValidTree(tree.root)
    time_b = time()
    print("Check that verkle tree is valid in {0:.3f}s".format(time_b - time_a))


if __name__ == "__main__":
    main()
