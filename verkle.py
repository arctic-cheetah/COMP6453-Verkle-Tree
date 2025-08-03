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
DOMAIN = []
KEY_LEN = 256
WIDTH_BITS = 8
# Width is the branch factor
WIDTH = 2**WIDTH_BITS
PRIMITIVE_ROOT = 7
MODULUS = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
primefield = PrimeField(MODULUS)
ROOT_OF_UNITY = pow(PRIMITIVE_ROOT, (MODULUS - 1) // WIDTH, MODULUS)
SETUP = generate_setup(WIDTH, SECRET)
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


class NodeType(Enum):
    # Every node is either
    # (i) empty,
    # (ii) a leaf node containing a key and value, or
    # (iii) an intermediate node that has some fixed number of children
    # (the "width" of the tree)
    EMPTY = 0
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

    # Empty || Leaf(Key, Value) || Node(Commitment, Children)
    def __init__(self, branch_factor: int):
        self.DOMAIN = [
            pow(self.ROOT_OF_UNITY, i, self.MODULUS) for i in range(self.WIDTH)
        ]
        self.branch_factor = KEY_LEN // WIDTH_BITS
        # one SRS for all nodes
        self.srs = generate_setup(branch_factor)
        # making an empty node
        self.root = VerkleNode(branch_factor)

    # Insert function acts as a prover according to video.
    def insert(self, key: int, value: int):
        """ """
        node = self.root
        path = self.key_path(key)
        newNode = VerkleNode(self.branch_factor, NodeType.LEAF)
        # descend and allocate internal nodes
        for i in path[:-1]:
            if node.children[i] is None:
                node.children[i] = newNode
            node = node.children[i]
        # final slot becomes leaf
        leaf_index = path[-1]
        node.children[leaf_index]
        node.children[leaf_index].value = value
        # recompute all commitments
        self.recommit(self.root)

    """
    Update or insert node and update all commitments and hashes
    """

    def insert_update_node(self, key: bytes, value: bytes):
        node = self.root
        indices = self.get_verkle_indices(key)
        newNode = VerkleNode(self.branch_factor, value, key, NodeType.LEAF)
        # descend and allocate internal nodes
        valueChange: int = -1
        path: List[Tuple[int, VerkleNode]] = []

        while True:
            index = indices.pop(0)
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
                        newIndex = indices.pop(0)
                        oldIndex = self.get_verkle_indices(oldNode.key)[len(path)]
                        newInnerNode = VerkleNode(
                            KEY_LEN // WIDTH_BITS, node_type=NodeType.INNER
                        )
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
                        # newIndex = self.get_verkle_indices(oldNode
                        # Make a new inner node and place the old and new leaf under the
                        break

                node = node.children[index]
            else:
                # It is an inner node so just add it
                node.children[index] = newNode
                valueChange = int.from_bytes(newNode.hash, "little") % MODULUS
                break
                # Just insert at the inner node location

            break
        # DONE: Updates all the parent commits along the path
        for index, currNode in reversed(path):
            currNode.commitment.add(
                SETUP["g1_langrange"][index].dup().mult(valueChange)
            )
            oldHash = node.hash
            newHash = hash(currNode.commitment)
            node.hash = newHash
            valueChange = (
                MODULUS
                + int.from_bytes(newHash, "little")
                - int.from_bytes(oldHash, "little")
            ) % MODULUS

    def get_verkle_indices(self, key: bytes) -> Tuple[int]:
        """
        Generates the list of verkle indices for key
        """
        # TODO: Possible bug here! WHY SHOULD IT BE BIG ENDIAN
        x = int.from_bytes(key, "big")
        last_index_bits = KEY_LEN % WIDTH_BITS
        index = (x % (2**last_index_bits)) << (WIDTH_BITS - last_index_bits)
        x //= 2**last_index_bits
        indices = [index]
        for i in range((KEY_LEN - 1) // WIDTH_BITS):
            index = x % WIDTH
            x //= WIDTH
            indices.append(index)
        return tuple(reversed(indices))

    def recommit(self, node: "VerkleNode"):
        """Recomputes the commitment for the given node and all its children. (Post-order)"""
        if node.children is None:
            return
        for child in node.children:
            if child is not None:
                self._recommit(child)
        poly = []
        for child in node.children:
            if child is None:
                poly.append(0)
            elif child.children is None:
                poly.append(child.value % curve.curve_order)
            else:
                # commitment to a scalar (TODO)
                pass

        node.commitment = commit(poly, self.srs)

    def root_commit(self):
        return self.root.commitment

    def prove(self, key: int):
        path = self._key_path(key)
        node = self.root
        proof = []
        for idx in path:
            # build node's polynomial
            poly = []
            for child in node.children:
                if child is None:
                    poly.append(0)
                elif child.children is None:
                    poly.append(child.value % curve.curve_order)
                else:
                    poly.append(hash_point_to_field(child.commitment))
            # open at index idx
            v, pi = open_poly(poly, idx, self.srs)
            proof.append({"C": node.commitment, "i": idx, "v": v, "pi": pi})
            # descend
            nxt = node.children[idx]
            if nxt is None:
                raise KeyError(f"No entry for key {key}")
            if nxt.children is None:
                break
            node = nxt
        return proof

    @staticmethod
    # TODO: Joules
    # TODO: WARNING BECAREFUL IF BUG OCCCURS
    def verify(self, key: int, value: int, proof):
        pass


# Use KZG settings as seen in verkle_trie
class VerkleNode:
    type: NodeType = NodeType.EMPTY
    # TODO: THIS IS POTENTIAL OF SPACE COMPLEXITY COST HERE BECAUSE LIST[NONe] *256
    children: List["VerkleNode" | None] = [None] * VerkleTree.KEY_LEN
    commitment: blst.P1 = blst.G1().mult(0)
    value: bytes = b""
    key: bytes = b""
    hash: bytes = b""

    # Empty || Leaf(Key, Value) || Node(Commitment, Children)
    # Commitment is a polynomial commitment to the values in the children nodes.
    # Children is a list of verkleNode objects.
    # Value is the value at the leaf node, or None for non-leaf nodes.
    def __init__(
        self,
        branch_factor: int = KEY_LEN // WIDTH_BITS,
        value: bytes = None,
        key: bytes = None,
        node_type: NodeType = NodeType.EMPTY,
    ):
        """
        Initializes a verkle node.
        User provides a value if its a leaf node.
        If value is None, it is a non-leaf node and children will be initialized.
        """
        self.key = key
        self.branch_factor = branch_factor
        self.value = value
        self.children = None if (value is not None) else [None] * branch_factor
        self.node_type = node_type
        # Omar you fucking retard, set the commitment to the identity element
        self.commitment = blst.G1().mult(0)


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


# Fk this shit omar
def commit(poly, h):
    """
    Commit to a polynomial.
    Args:
        poly: The polynomial to commit to as a list of coefficients,
        starting from the highest degree, or as a sympy Poly.
        h: parameters of the trusted setup
    Returns:
        The commitment to the polynomial, a point in G1.
    """
    if isinstance(poly, sympy.Poly):
        poly = [x % curve.curve_order for x in poly.all_coeffs()]

    degree = len(poly) - 1
    com_f = curve.Z1

    for i, pi in enumerate(poly):
        pi = pi % curve.curve_order
        d = degree - i
        com_f = curve.add(com_f, curve.multiply(h[0][d], pi))

    return com_f


# Use this
def add_node_hash(node: VerkleNode):
    """
    DONE:
    Recursively adds all missing commitments and hashes to a verkle trie structure.
    """
    if node.node_type == NodeType.LEAF:
        node.hash = hash([node.key, node.value])
    if node.node_type == NodeType.INNER:
        values = {}
        for i in range(WIDTH):
            if i in node:
                if "hash" not in node[i]:
                    # Recurse below until we reach the leaf node
                    add_node_hash(node[i])
                values[i] = int.from_bytes(node.children[i].hash, "little")
        commitment = kzg_utils.compute_commitment_lagrange(values)
        node.commitment = commitment
        node.hash = hash(commitment.compress())


def generate_setup(s):
    pass


def hash_point_to_field(pt):
    pass


def layer_commit(values, setup):
    pass


def generate_quotient(values, index):
    pass


def generate_tree(data, setup):
    pass


def generate_proof(data_tree, commitment_tree, indices, setup):
    pass


def verify_proof(proof, commitment_root, indices, values, setup):
    pass


def test():
    pass
