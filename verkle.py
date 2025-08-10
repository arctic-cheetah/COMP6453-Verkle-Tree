from enum import Enum
from hashlib import sha256
import hashlib
from py_ecc.optimized_bls12_381 import optimized_curve as curve, pairing
from kzg_utils import KzgUtils
import kzg_utils
from fft import fft
from poly_utils import PrimeField
import pippenger
import blst
import hashlib
from typing import *
import numpy as np

NUMBER_KEYS_PROOF = 5000
MODULUS = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
PRIMITIVE_ROOT = 7
# Need to do ouble handling for branch factor ((MODULUS - 1) // 2**8)
ROOT_OF_UNITY = pow(PRIMITIVE_ROOT, (MODULUS - 1) // 2**4, MODULUS)


def generate_setup(size, secret) -> Dict[str, List[blst.P1 | blst.P2]]:
    """
    Using the default setup from ethereum
    Generates a setup in the G1 group and G2 group,
    Where G1 is the polynomial commitment group and G2 is the pairing group
    as well as the Lagrange polynomials in G1 (via FFT)
    """
    g1_setup = np.array([blst.G1().mult(pow(secret, i, MODULUS)) for i in range(size)])
    g2_setup = np.array([blst.G2().mult(pow(secret, i, MODULUS)) for i in range(size)])
    g1_lagrange = np.array(fft(g1_setup, MODULUS, ROOT_OF_UNITY, inv=True))
    return {"g1": g1_setup, "g2": g2_setup, "g1_lagrange": g1_lagrange}



"""
A hash function for bytes, integers and blst.P1 objects.
If the input is a list, then hash each element and concatenate the results
"""


def hash(x):

    if isinstance(x, bytes):
        return hashlib.sha256(x).digest()
    elif isinstance(x, int):
        # encode as fixed 32 bytes (little-endian) before hashing
        return hashlib.sha256(x.to_bytes(32, "little", signed=False)).digest()
    elif isinstance(x, blst.P1):
        return hash(x.compress())
    elif isinstance(x, (list, tuple, np.ndarray)):
        b = b""
        for a in x:
            if isinstance(a, bytes):
                b += a
            elif isinstance(a, int):
                b += a.to_bytes(32, "little", signed=False)
            elif isinstance(a, blst.P1):
                b += hash(a.compress())
            else:
                raise TypeError(f"Unsupported type in hash list: {type(a)}")
        return hashlib.sha256(b).digest()
    else:
        raise TypeError(f"Unsupported type for hash(): {type(x)}")


# helper function
def hash_to_int(data):
    return int.from_bytes(hash(data), "little")


# Commitment is 256 bits

# websites
# https://lucasmartincalderon.medium.com/verkle-trees-everything-you-need-to-know-321c9c8bc2f6
# https://blog.ethereum.org/2021/12/02/verkle-tree-structure

## A verkle tree is a Merkle tree with polynomial commitments at each node.
"""
    Need the following constructs:
    - Verkle tree data structure
    - Prove and verify functions
"""

"""
Store ur proofs here
"""


class Proof:
    depths: np.ndarray = np.array([], dtype=object)
    commitsSortedByIndex: np.ndarray = np.array([], dtype=object)
    polySerialised: bytes = b""
    challenge: bytes = b""
    compressedMultiProof: bytes = b""

    def __init__(
        self,
        depths: List[bytes],
        commitsSortedByIndex: List[bytes],
        polySerialised: bytes,
        challenge: bytes,
        compressedMultiProof: bytes,
    ):
        self.depths = np.array(depths, dtype=object)
        self.commitsSortedByIndex = np.array(commitsSortedByIndex, dtype=object)
        self.polySerialised = polySerialised
        self.challenge = challenge
        self.compressedMultiProof = compressedMultiProof

    def __str__(self):
        stringBuilt = f"\n\tDepths: {self.depths[:10]}\n\tCommitsSortedByIndex: {self.commitsSortedByIndex[:10]}\n\tChallenges: {self.challenge}"
        return stringBuilt


class NodeType(Enum):
    # Every node is either
    # (ii) a leaf node containing a key and value, or
    # (iii) an intermediate node that has some fixed number of children
    # (the "width" of the tree)
    INNER = 1
    LEAF = 2


class VerkleTree:

    # Empty || Leaf(Key, Value) || Node(Commitment, Children)
    def __init__(
        self,
        KEY_LEN: int = 256,
        WIDTH_BITS: int = 8,
    ):
        self.KEY_LEN = KEY_LEN
        self.WIDTH_BITS = WIDTH_BITS
        self.WIDTH = 2**WIDTH_BITS
        self.branch_factor = self.WIDTH # 2**WIDTH_BITS children
        # one SRS for all nodes
        # self.srs = generate_setup(branch_factor)
        # making an empty node
        self.root = VerkleNode(self.branch_factor, node_type=NodeType.INNER)
        self.SECRET = 8927347823478352432985
        self.PRIMITIVE_ROOT = 7
        self.MODULUS = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
        self.primefield = PrimeField(self.MODULUS)
        self.ROOT_OF_UNITY = pow(self.PRIMITIVE_ROOT, (self.MODULUS - 1) // self.branch_factor, self.MODULUS)
        self.DOMAIN = np.array(
            [pow(self.ROOT_OF_UNITY, i, self.MODULUS) for i in range(self.WIDTH)]
        )
        self.SETUP = generate_setup(self.branch_factor, self.SECRET)
        self.DOMAIN = np.array([pow(self.ROOT_OF_UNITY, i, self.MODULUS) for i in range(self.branch_factor)], dtype=np.object_)
        self.kzg_utils = KzgUtils(self.MODULUS, self.branch_factor, self.DOMAIN, self.SETUP, self.primefield)

    def insert(self, currRoot: "VerkleNode", key: bytes, value: bytes):
        """
        Insert without updating the hashes/commmits/ this is to allow us to build a full trie
        """
        currNode = currRoot
        indices = iter(self.getVerkleIndex(key))
        currIndex = None
        prevNode = None
        while currNode.node_type == NodeType.INNER:
            prevNode = currNode
            prevIndex = currIndex
            currIndex = next(indices)
            if currNode.children[currIndex] is not None:
                currNode = currNode.children[currIndex]
            else:
                # when the child is none, just insert a new node here
                currNode.children[currIndex] = VerkleNode(
                    self.branch_factor, value, key, NodeType.LEAF
                )
                return

        # If we are here, then we are at a leaf node
        if currNode.key == key:
            currNode.value = value
        else:
            # Key collision (different keys map to the same path)
            # We need to split the leaf node.
            # Keep the old leaf's data
            old_leaf_key = currNode.key
            old_leaf_value = currNode.value
            # Replace the leaf with a new inner node
            assert prevNode is not None, "prevNode should not be None"
            prevNode.children[currIndex] = VerkleNode(self.branch_factor, node_type=NodeType.INNER)
            # Re-insert both the old and new keys from the root.
            # This will correctly build the new branch under the new inner node.
            self.insert(self.root, key, value)
            self.insert(self.root, old_leaf_key, old_leaf_value)

    def insert_update_node(self, key: bytes, value: bytes):
        node = self.root
        indices = iter(self.getVerkleIndex(key))
        newNode = VerkleNode(self.branch_factor, value, key, NodeType.LEAF)
        # descend and allocate internal nodes
        # valueChange: int = -1
        path: List[Tuple[int, VerkleNode]] = []
        add_node_hash(self.kzg_utils, newNode)

        while True:
            index = next(indices)
            path.append((index, node))
            if node.children[index] is not None:
                # Check if leafnode
                if node.children[index].node_type == NodeType.LEAF:
                    # Perform cases:
                    # 1) Does the keymatch? Yes
                    oldNode: VerkleNode = node.children[index]
                    if node.children[index].key == key:
                        # Update value and hash
                        node.children[index] = newNode
                        valueChange = (
                            hash(
                                self.MODULUS
                                + int.from_bytes(newNode.hash, "little")
                                - int.from_bytes(oldNode.hash, "little")
                            )
                            % self.MODULUS
                        )
                        break
                    # 2) No, Then split the node
                    else:
                        newIndex = next(indices)
                        oldIndex = self.getVerkleIndex(oldNode.key)[len(path)]
                        newInnerNode = VerkleNode(self.branch_factor, node_type=NodeType.INNER)
                        # getting error here sometimes
                        assert oldIndex != newIndex
                        newInnerNode.children[newIndex] = newNode
                        newInnerNode.children[oldIndex] = oldNode
                        add_node_hash(self.kzg_utils, newInnerNode)
                        node.children[index] = newInnerNode
                        valueChange = (
                            self.MODULUS
                            + int.from_bytes(newInnerNode.hash, "little")
                            - int.from_bytes(oldNode.hash, "little")
                        ) % self.MODULUS
                        # newIndex = self.getVerkleIndex(oldNode
                        # Make a new inner node and place the old and new leaf under the
                        break

                node = node.children[index]
            else:
                # It is empty so just add it
                node.children[index] = newNode
                valueChange = int.from_bytes(newNode.hash, "little") % self.MODULUS
                break
                # Just insert at the inner node location

        # DONE: Updates all the parent commits along the path
        for index, currNode in reversed(path):
            # NOTE: Error is fixed!
            # print("Before: " + str(currNode.commitment.compress()))

            currNode.commitment = currNode.commitment.add(
                self.SETUP["g1_lagrange"][index].dup().mult(valueChange)
            )
            currNode.commitmentCompressed = currNode.commitment.compress()
            # print("After: " + str(currNode.commitment.compress()))
            # print("______________________________")

            oldHash = currNode.hash
            newHash = hash(currNode.commitment)
            currNode.hash = newHash
            valueChange = (
                self.MODULUS
                + int.from_bytes(newHash, "little")
                - int.from_bytes(oldHash, "little")
            ) % self.MODULUS

    def getVerkleIndex(self, key: bytes) -> Tuple[int]:
        """
        Generates the list of verkle indices for key
        """
        width = self.branch_factor          # == 2**self.WIDTH_BITS
        depth = (self.KEY_LEN + self.WIDTH_BITS - 1) // self.WIDTH_BITS
        mask = (1 << self.KEY_LEN) - 1
        x = int.from_bytes(key, "little") & mask  # match main.py

        # collect base-WIDTH digits LSB-first
        digits = []
        for _ in range(depth):
            digits.append(x % width)
            x //= width

        # return MSB-first for top-down traversal
        return tuple(reversed(digits))

    def root_commit(self):
        return self.root.commitment

    def check_kzg_multiproof(self, Cs, indices, ys, proof, display_times=False):
        """
        Verifies a KZG multiproof according to the schema described here:
        https://dankradfeist.de/ethereum/2021/06/18/pcs-multiproofs.html
        """
        D_serialized, y, sigma_serialized = proof
        D = blst.P1(D_serialized)
        sigma = blst.P1(sigma_serialized)

        ys_bytes = [val.to_bytes(32, 'little') for val in ys]

        # Step 1
        r = (
            hash_to_int(
                [hash(C.compress()) for C in Cs] + ys_bytes + [self.kzg_utils.DOMAIN[i] for i in indices]
            )
            % self.MODULUS
        )

        # log_time_if_eligible("   Computed r hash", 30, display_times)

        # Step 2
        t = hash_to_int([r, D]) % self.MODULUS
        E_coefficients = []
        g_2_of_t = 0
        power_of_r = 1

        for index, y_val in zip(indices, ys):
            E_coefficient = self.primefield.div(power_of_r, (t - self.DOMAIN[index]) % self.MODULUS)
            E_coefficients.append(E_coefficient)
            g_2_of_t = (g_2_of_t + E_coefficient * y_val) % self.MODULUS
            power_of_r = (power_of_r * r) % self.MODULUS

        # log_time_if_eligible("   Computed g2 and e coeffs", 30, display_times)

        E = pippenger.pippenger_simple(Cs, E_coefficients)

        # log_time_if_eligible("  Computed E commitment", 30, display_times)

        # Step 3 (Check KZG proofs)
        w = (y - g_2_of_t) % self.MODULUS

        q = hash_to_int([E, D, y, w])

        if not self.kzg_utils.check_kzg_proof(
            E.dup().add(D.dup().mult(q)), t, (y + q * w) % self.MODULUS, sigma
        ):
            return False

        # log_time_if_eligible("   Checked KZG proofs", 30, display_times)

        return True

    # TODO:
    # This function is good!
    #  This does not need to be optimised? peraps we can use cython
    def make_kzg_multiproof(self, Cs, fs, indices, ys, display_times=True):
        """
        Computes a KZG multiproof according to the schema described here:
        https://dankradfeist.de/ethereum/2021/06/18/pcs-multiproofs.html

        zs[i] = DOMAIN[indexes[i]]
        D = polynomial commitment g(x) in serialised evaluation form
        y is the challenge
        sigma is the compressed KZG multiproof
        """

        # Step 1: Construct g(X) polynomial in evaluation form
        r = (
            hash_to_int(
                [hash(C) for C in Cs] + [y.to_bytes(32, "little") for y in ys] + [self.kzg_utils.DOMAIN[i] for i in indices]
            )
            % self.MODULUS
        )

        # log_time_if_eligible("   Hashed to r", 30, display_times)

        g = np.zeros(self.branch_factor, dtype=np.object_)
        power_of_r = 1
        for f, index in zip(fs, indices):
            quotient = self.kzg_utils.compute_inner_quotient_in_evaluation_form(f, index)
            quotient = np.array(quotient, dtype=np.object_)
            g = g + (power_of_r * quotient)
            power_of_r = power_of_r * r % self.MODULUS

        # log_time_if_eligible("   Computed g polynomial", 30, display_times)

        D = self.kzg_utils.compute_commitment_lagrange({i: v for i, v in enumerate(g)})

        # log_time_if_eligible("   Computed commitment D", 30, display_times)

        # Step 2: Compute h in evaluation form

        t = hash_to_int([r, D]) % self.MODULUS

        h = np.zeros(self.branch_factor, dtype=np.object_)
        power_of_r = 1

        for f, index in zip(fs, indices):
            denominator_inv = self.primefield.inv((t - self.DOMAIN[index]) % self.MODULUS)
            f_arr = np.array(f, dtype=np.object_)
            h = (h + (power_of_r * f_arr * denominator_inv)) % self.MODULUS
            power_of_r = power_of_r * r % self.MODULUS

        # log_time_if_eligible("   Computed h polynomial", 30, display_times)

        # Step 3: Evaluate and compute KZG proofs

        y, pi = self.kzg_utils.evaluate_and_compute_kzg_proof(h, t)
        w, rho = self.kzg_utils.evaluate_and_compute_kzg_proof(g, t)

        # Compress both proofs into one

        E = self.kzg_utils.compute_commitment_lagrange({i: v for i, v in enumerate(h)})
        q = hash_to_int([E, D, y, w])
        sigma = pi.dup().add(rho.dup().mult(q))

        # log_time_if_eligible("   Computed KZG proofs", 30, display_times)

        return D.compress(), y, sigma.compress()

    def find_node_with_path(self, node: "VerkleNode", key: bytes):
        """
        As 'find_node', but returns the path of all nodes on the way to 'key' as well as their index
        """
        current_node = node
        indices = iter(self.getVerkleIndex(key))
        path = []
        current_index_path = []
        while current_node.node_type == NodeType.INNER:
            index = next(indices)
            path.append((tuple(current_index_path), index, current_node))
            current_index_path.append(index)
            if current_node.children[index] is not None:
                current_node = current_node.children[index]
            else:
                return path, None
        if current_node.key == key:
            return path, current_node
        return path, None

    def make_verkle_proof(
        self, tree: "VerkleTree", keys: List[bytes], display_times=False
    ) -> Proof:
        """
        Creates a proof for the 'keys' in the verkle tree given by 'tree'
        """
        # Step 0: Find all keys in the trie
        #
        assert (len(tree.root.children) == tree.branch_factor) if tree.root.node_type == NodeType.INNER else True
        nodesByIndex = {}
        nodesByIndexSubIndex = {}
        values: np.ndarray = np.array([], dtype=object)
        depths: np.ndarray = np.array([], dtype=int)
        for key in keys:
            path, node = self.find_node_with_path(tree.root, key)
            assert (len(node.children) == tree.branch_factor) if (node and node.node_type == NodeType.INNER) else True
            depths = np.append(depths, len(path))
            values = np.append(
                values,
                (
                    node.value
                    if (node != None and node.node_type == NodeType.LEAF)
                    else None
                ),
            )
            for index, subindex, node in path:
                assert (len(node.children) == tree.branch_factor) if (node and node.node_type == NodeType.INNER) else True
                nodesByIndex[index] = node
                nodesByIndexSubIndex[(index, subindex)] = node
        # log_time_if_eligible("   Computed key paths", 30, display_times)

        # All commitments, but without any duplications. These are for sending over the wire as part of the proof
        nodesSortedByIndex = np.array(
            list(map(lambda x: x[1], sorted(nodesByIndex.items()))), dtype=object
        )
        nodesCompressedSortedByIndex = np.array(
            list(
                map(lambda x: x[1].commitment.compress(), sorted(nodesByIndex.items()))
            ),
            dtype=object,
        )
        nodesSortedByIndexAndSubIndex = np.array(
            list(map(lambda x: x[1], sorted(nodesByIndexSubIndex.items()))),
            dtype=object,
        )
        indices = np.array(
            list(map(lambda x: x[0][1], sorted(nodesByIndexSubIndex.items()))),
            dtype=int,
        )
        ys = np.array(
            list(
                map(
                    lambda x: (
                        int.from_bytes((x[1].children[x[0][1]]).hash, "little")
                        if x[1].children[x[0][1]] is not None
                        else 0
                    ),
                    sorted(nodesByIndexSubIndex.items()),
                )
            ),
            dtype=object,
        )

        # log_time_if_eligible("   Sorted all commitments", 30, display_times)

        fs = []
        Cs = np.array(
            [x.commitment for x in nodesSortedByIndexAndSubIndex], dtype=object
        )
        for node in nodesSortedByIndexAndSubIndex:
            if node.node_type == NodeType.LEAF:
                assert False # should never happen
                fs.append(int.from_bytes(node.value, "little"))
            else:
                fs.append(
                    np.array(
                        [
                            (
                                int.from_bytes(node.children[i].hash, "little")
                                if node.children[i] is not None
                                else 0
                            )
                            for i in range(self.branch_factor)
                        ],
                        dtype=object,
                    )
                )

        polySerialised, challenge, compressedMultiProof = self.make_kzg_multiproof(
            Cs, fs, indices, ys, display_times
        )
        commitsSortedIndexSerialised = np.array(
            [x.commitment.compress() for x in nodesSortedByIndex[1:]], dtype=np.object_
        )
        proof: Proof = Proof(
            depths,
            commitsSortedIndexSerialised,
            polySerialised,
            challenge,
            compressedMultiProof,
        )
        return proof

    # NOTE: decide if class interface for proof should be made YES
    # Tis function checks for all commits given
    # If u do one by one then it is not efficient
    def check_verkle_proof(
        self,
        rootCommit: bytes,
        keys: List[bytes],
        values: List[bytes],
        proof: Proof,
        displayTime: bool = False,
    ):
        # Reconstruct commitments list
        commitSortByIndex = [blst.P1(rootCommit)] + [
            blst.P1(c) for c in proof.commitsSortedByIndex
        ]

        everyIndices = set()
        IndicesAndSubIndicies = set()
        leafValByIndexSubIndex = {}

        # Find all required indices
        for key, value, depth in zip(keys, values, proof.depths):
            verkleIndex = self.getVerkleIndex(key)
            for i in range(depth):
                everyIndices.add(verkleIndex[:i])
                IndicesAndSubIndicies.add((verkleIndex[:i], verkleIndex[i]))
            leafValByIndexSubIndex[
                (verkleIndex[: depth - 1], verkleIndex[depth - 1])
            ] = hash([key, value])

        everyIndices = sorted(everyIndices)
        IndicesAndSubIndicies = sorted(IndicesAndSubIndicies)

        # create the commitment list and sort them by index
        commitsByIndex = {
            index: commitment
            for index, commitment in zip(everyIndices, commitSortByIndex)
        }
        commitsByIndexAndSubIndex = {
            IndexAndSubIndex: commitsByIndex[IndexAndSubIndex[0]]
            for IndexAndSubIndex in IndicesAndSubIndicies
        }

        subhashes_by_IndexAndSubIndex = {}
        for IndexAndSubIndex in IndicesAndSubIndicies:
            fullSubIndex = IndexAndSubIndex[0] + (IndexAndSubIndex[1],)
            if fullSubIndex in commitsByIndex:
                subhashes_by_IndexAndSubIndex[IndexAndSubIndex] = hash(
                    commitsByIndex[fullSubIndex]
                )
            else:
                subhashes_by_IndexAndSubIndex[IndexAndSubIndex] = (
                    leafValByIndexSubIndex[IndexAndSubIndex]
                )

        Cs = [x[1] for x in sorted(commitsByIndexAndSubIndex.items())]
        indices = [x[1] for x in sorted(IndicesAndSubIndicies)]
        ys = [
            int.from_bytes(x[1], "little")
            for x in sorted(subhashes_by_IndexAndSubIndex.items())
        ]

        # The actual multiproof check would go here (not implemented)
        return self.check_kzg_multiproof(
            Cs,
            indices,
            ys,
            [proof.polySerialised, proof.challenge, proof.compressedMultiProof],
            displayTime,
        )

    """
    Checks Verkle tree proof according to
    https://notes.ethereum.org/nrQqhVpQRi6acQckwm1Ryg?both
    """


## A verkle tree is a Merkle tree with polynomial commitments at each node.
"""
    Need the following constructs:
    - Verkle tree data structure
    - Prove and verify functions
"""


class NodeType(Enum):
    # Every node is either
    # (i) empty,
    # (ii) a leaf node containing a key and value, or
    # (iii) an intermediate node that has some fixed number of children
    # (the "width" of the tree)
    EMPTY = 0
    INNER = 1
    LEAF = 2


# Use KZG settings as seen in verkle_trie
class VerkleNode:
    # TODO: THIS IS POTENTIAL OF SPACE COMPLEXITY COST HERE BECAUSE LIST[NONE] *256
    # children: List["VerkleNode"] = [None] * VerkleTree.KEY_LEN
    children: np.ndarray = np.array([None], dtype=object)

    commitment: blst.P1 = blst.G1().mult(0)
    commitmentCompressed: bytes = b""
    value: bytes = b""
    key: bytes = b""
    hash: bytes = b""

    # Empty || Leaf(Key, Value) || Node(Commitment, Children)
    # Commitment is a polynomial commitment to the values in the children nodes.
    # Children is a list of verkleNode objects.
    # Value is the value at the leaf node, or None for non-leaf nodes.
    def __init__(
        self,
        branch_factor: int = 256,
        value: bytes = None,
        key: bytes = None,
        node_type: NodeType = NodeType.INNER,
    ):
        """
        Initializes a verkle node.
        User provides a value if its a leaf node.
        If value is None, it is a non-leaf node and children will be initialized.
        """
        self.key = key
        self.branch_factor = branch_factor
        self.value = value
        if node_type == NodeType.INNER:
            self.children = np.array([None] * self.branch_factor, dtype=object)
        else:
            self.children = None

        self.node_type = node_type
        self.commitment = blst.G1().mult(0)
        self.commitmentCompressed = self.commitment.compress()


# KZG Commitment (https://raw.githubusercontent.com/giuliop/plonk/main/kzg.py)
# Curve order
factorization = [
    2**32,
    3,
    11,
    19,
    10177,
    125527,
    859267,
    906349,
    906349,
    2508409,
    2529403,
    52437899,
    254760293,
    254760293,
]
q_1 = 1
for f in factorization:
    q_1 *= f
assert q_1 == curve.curve_order - 1

"""Code from giuliop/plonk"""


# Use this
def add_node_hash(kzg_utils, node: VerkleNode):
    """
    DONE:
    Recursively adds all missing commitments and hashes to a verkle trie structure.
    # NOTE WE ARE USING ETHEREUM'S IMPLEMENTATION OF KZG COMPUTATION.
    """
    if node.node_type == NodeType.LEAF:
        node.hash = hash([node.key, node.value])
    if node.node_type == NodeType.INNER:
        values = {}
        for i in range(node.branch_factor):
            if node.children[i] is not None:
                if node.children[i].hash == b"":
                    add_node_hash(kzg_utils, node.children[i])
                values[i] = int.from_bytes(node.children[i].hash, "little")
        node.commitment = kzg_utils.compute_commitment_lagrange(values)
        node.hash = hash(node.commitment.compress())


from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed