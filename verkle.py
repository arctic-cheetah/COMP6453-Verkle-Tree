from enum import Enum
from hashlib import sha256
import hashlib, secrets, sympy
from py_ecc.optimized_bls12_381 import optimized_curve as curve, pairing
from verkle_trie.kzg_utils import KzgUtils
import kzg_utils
from fft import fft
from poly_utils import PrimeField
import pippenger
import blst
import hashlib
from typing import *

NUMBER_KEYS_PROOF = 5000


def generate_setup(size, secret) -> Dict[str, List[blst.P1 | blst.P2]]:
    """
    Using the default setup from ethereum
    Generates a setup in the G1 group and G2 group,
    Where G1 is the polynomial commitment group and G2 is the pairing group
    as well as the Lagrange polynomials in G1 (via FFT)
    """
    g1_setup = [blst.G1().mult(pow(secret, i, MODULUS)) for i in range(size)]
    g2_setup = [blst.G2().mult(pow(secret, i, MODULUS)) for i in range(size)]
    g1_lagrange = fft(g1_setup, MODULUS, ROOT_OF_UNITY, inv=True)
    return {"g1": g1_setup, "g2": g2_setup, "g1_lagrange": g1_lagrange}


SECRET = 8927347823478352432985
KEY_LEN = 256
WIDTH_BITS = 8
# Width is the branch factor
WIDTH = 2**WIDTH_BITS
PRIMITIVE_ROOT = 7
MODULUS = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
primefield = PrimeField(MODULUS)
ROOT_OF_UNITY = pow(PRIMITIVE_ROOT, (MODULUS - 1) // WIDTH, MODULUS)
SETUP = generate_setup(WIDTH, SECRET)
DOMAIN = [pow(ROOT_OF_UNITY, i, MODULUS) for i in range(WIDTH)]
kzg_utils = KzgUtils(MODULUS, WIDTH, DOMAIN, SETUP, primefield)


"""
A hash function for bytes, integers and blst.P1 objects.
If the input is a list, then hash each element and concatenate the results"""


def hash(x):
    if isinstance(x, bytes):
        return hashlib.sha256(x).digest()
    elif isinstance(x, blst.P1):
        return hash(x.compress())
    b = b""
    for a in x:
        if isinstance(a, bytes):
            b += a
        elif isinstance(a, int):
            b += a.to_bytes(32, "little")
        elif isinstance(a, blst.P1):
            b += hash(a.compress())
    return hash(b)


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
    depths: List[bytes] = []
    commitsSortedByIndex: List[bytes] = []
    polySerialised: bytes = b""
    # challenge represents the y value for the KZG polynomial
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
        self.depths = depths
        self.commitsSortedByIndex = commitsSortedByIndex
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
    # Verkle Trie parameters kept the same as Ethereum's implementation
    KEY_LEN = 256
    WIDTH_BITS = 8
    WIDTH = 2**WIDTH_BITS
    PRIMITIVE_ROOT = 7
    MODULUS = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
    primefield = PrimeField(MODULUS)
    branch_factor = -1
    ROOT_OF_UNITY = pow(PRIMITIVE_ROOT, (MODULUS - 1) // WIDTH, MODULUS)
    DOMAIN = []
    root: "VerkleNode" = None

    # Empty || Leaf(Key, Value) || Node(Commitment, Children)
    def __init__(
        self,
    ):
        self.DOMAIN = [
            pow(self.ROOT_OF_UNITY, i, self.MODULUS) for i in range(self.WIDTH)
        ]
        self.branch_factor = KEY_LEN // WIDTH_BITS
        # one SRS for all nodes
        # self.srs = generate_setup(branch_factor)
        # making an empty node
        self.root = VerkleNode(self.branch_factor, NodeType.INNER)

    def insert(self, currRoot: "VerkleNode", key: bytes, value: bytes):
        """
        Insert without updating the hashes/commmits/ this is to allow us to build a full trie
        """
        currNode = currRoot
        indices = iter(self.getVerkleIndex(key))
        currIndex = None
        while currNode.node_type == NodeType.INNER:
            prevNode = currNode
            prevIndex = currIndex
            currIndex = next(indices)
            if currNode.children[currIndex] is not None:
                currNode = currNode.children[currIndex]
            else:
                # when the child is none, just insert a new node here
                currNode.children[currIndex] = VerkleNode(
                    KEY_LEN, value, key, NodeType.LEAF
                )
                return

        # If we are here, then we are at a leaf node
        if currNode.key == key:
            currNode.value = value
        else:
            # Split the node
            newInnerNode = VerkleNode(node_type=NodeType.INNER)
            prevNode.children[currIndex] = newInnerNode
            self.insert(currRoot, key, value)
            self.insert(currRoot, currNode.key, currNode.value)

    def insert_update_node(self, key: bytes, value: bytes):
        node = self.root
        indices = iter(self.getVerkleIndex(key))
        newNode = VerkleNode(self.branch_factor, value, key, NodeType.LEAF)
        # descend and allocate internal nodes
        # valueChange: int = -1
        path: List[Tuple[int, VerkleNode]] = []
        add_node_hash(newNode)

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
                                MODULUS
                                + int.from_bytes(newNode.hash, "little")
                                - int.from_bytes(oldNode.hash, "little")
                            )
                            % MODULUS
                        )
                        break
                    # 2) No, Then split the node
                    else:
                        newIndex = next(indices)
                        oldIndex = self.getVerkleIndex(oldNode.key)[len(path)]
                        newInnerNode = VerkleNode(node_type=NodeType.INNER)
                        # getting error here sometimes
                        assert oldIndex != newIndex
                        newInnerNode.children[newIndex] = newNode
                        newInnerNode.children[oldIndex] = oldNode
                        add_node_hash(newInnerNode)
                        node.children[index] = newInnerNode
                        valueChange = (
                            MODULUS
                            + int.from_bytes(newInnerNode.hash, "little")
                            - int.from_bytes(oldNode.hash, "little")
                        ) % MODULUS
                        # newIndex = self.getVerkleIndex(oldNode
                        # Make a new inner node and place the old and new leaf under the
                        break

                node = node.children[index]
            else:
                # It is empty so just add it
                node.children[index] = newNode
                valueChange = int.from_bytes(newNode.hash, "little") % MODULUS
                break
                # Just insert at the inner node location

        # DONE: Updates all the parent commits along the path
        for index, currNode in reversed(path):
            # NOTE: Error is fixed!
            # print("Before: " + str(currNode.commitment.compress()))

            currNode.commitment = currNode.commitment.add(
                SETUP["g1_lagrange"][index].dup().mult(valueChange)
            )
            currNode.commitmentCompressed = currNode.commitment.compress()
            # print("After: " + str(currNode.commitment.compress()))
            # print("______________________________")

            oldHash = currNode.hash
            newHash = hash(currNode.commitment)
            currNode.hash = newHash
            valueChange = (
                MODULUS
                + int.from_bytes(newHash, "little")
                - int.from_bytes(oldHash, "little")
            ) % MODULUS

    def getVerkleIndex(self, key: bytes) -> Tuple[int]:
        """
        Generates the list of verkle indices for key
        """
        x = int.from_bytes(key, "little")
        last_index_bits = KEY_LEN % WIDTH_BITS
        index = (x % (2**last_index_bits)) << (WIDTH_BITS - last_index_bits)
        x //= 2**last_index_bits
        indices = [index]
        for _ in range((KEY_LEN - 1) // WIDTH_BITS):
            index = x % WIDTH
            x //= WIDTH
            indices.append(index)
        return tuple(reversed(indices))

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

        # Step 1
        r = (
            hash_to_int(
                [hash(C) for C in Cs] + ys + [kzg_utils.DOMAIN[i] for i in indices]
            )
            % MODULUS
        )

        # log_time_if_eligible("   Computed r hash", 30, display_times)

        # Step 2
        t = hash_to_int([r, D])
        E_coefficients = []
        g_2_of_t = 0
        power_of_r = 1

        for index, y in zip(indices, ys):
            E_coefficient = primefield.div(power_of_r, t - DOMAIN[index])
            E_coefficients.append(E_coefficient)
            g_2_of_t += E_coefficient * y % MODULUS

            power_of_r = power_of_r * r % MODULUS

        # log_time_if_eligible("   Computed g2 and e coeffs", 30, display_times)

        E = pippenger.pippenger_simple(Cs, E_coefficients)

        # log_time_if_eligible("  Computed E commitment", 30, display_times)

        # Step 3 (Check KZG proofs)
        w = (y - g_2_of_t) % MODULUS

        q = hash_to_int([E, D, y, w])

        if not kzg_utils.check_kzg_proof(
            E.dup().add(D.dup().mult(q)), t, y + q * w, sigma
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
                [hash(C) for C in Cs] + ys + [kzg_utils.DOMAIN[i] for i in indices]
            )
            % MODULUS
        )

        # log_time_if_eligible("   Hashed to r", 30, display_times)

        g = [0 for _ in range(WIDTH)]
        power_of_r = 1
        for f, index in zip(fs, indices):
            quotient = kzg_utils.compute_inner_quotient_in_evaluation_form(f, index)
            for i in range(WIDTH):
                g[i] += power_of_r * quotient[i]

            power_of_r = power_of_r * r % MODULUS

        # log_time_if_eligible("   Computed g polynomial", 30, display_times)

        D = kzg_utils.compute_commitment_lagrange({i: v for i, v in enumerate(g)})

        # log_time_if_eligible("   Computed commitment D", 30, display_times)

        # Step 2: Compute h in evaluation form

        t = hash_to_int([r, D]) % MODULUS

        h = [0 for _ in range(WIDTH)]
        power_of_r = 1

        for f, index in zip(fs, indices):
            denominator_inv = primefield.inv(t - DOMAIN[index])
            for i in range(WIDTH):
                h[i] += power_of_r * f[i] * denominator_inv % MODULUS

            power_of_r = power_of_r * r % MODULUS

        # log_time_if_eligible("   Computed h polynomial", 30, display_times)

        # Step 3: Evaluate and compute KZG proofs

        y, pi = kzg_utils.evaluate_and_compute_kzg_proof(h, t)
        w, rho = kzg_utils.evaluate_and_compute_kzg_proof(g, t)

        # Compress both proofs into one

        E = kzg_utils.compute_commitment_lagrange({i: v for i, v in enumerate(h)})
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
        nodesByIndex = {}
        nodesByIndexSubIndex = {}
        values: list[bytes] = []
        depths: list[int] = []
        for key in keys:
            path, node = self.find_node_with_path(tree.root, key)
            depths.append(len(path))
            values.append(
                node.value
                if (node != None and node.node_type == NodeType.LEAF)
                else None
            )
            for index, subindex, node in path:  # TODO: CHECK line 447 OR 440 for bug!
                nodesByIndex[index] = node
                nodesByIndexSubIndex[(index, subindex)] = node
        # log_time_if_eligible("   Computed key paths", 30, display_times)

        # All commitments, but without any duplications. These are for sending over the wire as part of the proof
        nodesSortedByIndex = list(map(lambda x: x[1], sorted(nodesByIndex.items())))
        nodesCompressedSortedByIndex = list(
            map(lambda x: x[1].commitment.compress(), sorted(nodesByIndex.items()))
        )

        # Nodes sorted
        nodesSortedByIndexAndSubIndex = list(
            map(lambda x: x[1], sorted(nodesByIndexSubIndex.items()))
        )

        indices = list(map(lambda x: x[0][1], sorted(nodesByIndexSubIndex.items())))

        ys = list(
            map(
                lambda x: (
                    int.from_bytes((x[1].children[x[0][1]]).hash, "little")
                    if x[1].children[x[0][1]] is not None
                    else 0
                ),
                sorted(nodesByIndexSubIndex.items()),
            )
        )

        # log_time_if_eligible("   Sorted all commitments", 30, display_times)

        fs = []
        # TODO: CHECK
        Cs = [x.commitment for x in nodesSortedByIndexAndSubIndex]

        for node in nodesSortedByIndexAndSubIndex:
            if node.node_type == NodeType.LEAF:
                fs.append(int.from_bytes(node.value, "little"))
            else:
                fs.append(
                    [
                        (
                            int.from_bytes(node.children[i].hash, "little")
                            if node.children[i] is not None
                            else 0
                        )
                        for i in range(WIDTH)
                    ]
                )

        polySerialised, challenge, compressedMultiProof = self.make_kzg_multiproof(
            Cs, fs, indices, ys, display_times
        )
        # TODO: THIS IS BUG
        commitsSortedIndexSerialised = [
            x.commitment.compress() for x in nodesSortedByIndex[1:]
        ]

        # log_time_if_eligible("   Serialized commitments", 30, display_times)
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
        # TODO: possibly improve this code below:
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
    children: List["VerkleNode"] = [None] * VerkleTree.KEY_LEN
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
        branch_factor: int = KEY_LEN,
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
        self.branch_factor = KEY_LEN
        self.value = value
        if node_type == NodeType.INNER:
            self.children = [None] * KEY_LEN
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
def add_node_hash(node: VerkleNode):
    """
    DONE:
    Recursively adds all missing commitments and hashes to a verkle trie structure.
    # NOTE WE ARE USING ETHEREUM'S IMPLEMENTATION OF KZG COMPUTATION.
    """
    if node.node_type == NodeType.LEAF:
        node.hash = hash([node.key, node.value])
    if node.node_type == NodeType.INNER:
        values = {}
        for i in range(WIDTH):
            if node.children[i] != None:
                if node.children[i].hash == b"":
                    add_node_hash(node.children[i])
                values[i] = int.from_bytes(node.children[i].hash, "little")
        node.commitment = kzg_utils.compute_commitment_lagrange(values)
        node.hash = hash(node.commitment.compress())


# def add_node_hash(node: "VerkleNode"):
#     """
#     Recursively adds all missing commitments and hashes to a Verkle tree node.
#     """
#     if node.node_type == NodeType.LEAF:
#         node.hash = hash([node.key, node.value])
#     elif node.node_type == NodeType.INNER:
#         values = {}
#         for i, child in enumerate(node.children):
#             if child is not None:
#                 if not hasattr(child, "hash") or child.hash is None:
#                     add_node_hash(child)
#                 values[i] = int.from_bytes(child.hash, "little")
#         node.commitment = kzg_utils.compute_commitment_lagrange(values)
#         node.hash = hash(node.commitment.compress())
