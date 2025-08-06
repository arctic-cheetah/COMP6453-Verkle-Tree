import verkle
from random import randint
from verkle import *

NUMBER_INITIAL_KEYS = 2**15
NUMBER_ADDED_KEYS = 512
# NUMBER_INITIAL_KEYS = 10
# NUMBER_ADDED_KEYS = 10


def main():
    root = VerkleTree()
    values = {}
    upper_limit = 2**256 - 1
    for _ in range(NUMBER_INITIAL_KEYS):
        key = randint(0, upper_limit).to_bytes(32, "little")
        value = randint(0, upper_limit).to_bytes(32, "little")
        root.insert(key, value)
        values[key] = value

    key_list = []
    for i in range(NUMBER_ADDED_KEYS):
        key = randint(0, upper_limit).to_bytes(32, "little")
        key_list.append(key)        
        value = randint(0, upper_limit).to_bytes(32, "little")
        root.insert_update_node(key, value)
        values[key] = value

    proof = root.make_verkle_proof(root, key_list[0])
    print("The proof formed-" + "\n" + f"{proof}")
    print("done")

    # Verify the proof

    
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
