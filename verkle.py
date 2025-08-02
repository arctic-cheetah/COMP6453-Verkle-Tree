from enum import Enum
from hashlib import sha256
import hashlib, secrets, sympy
from py_ecc.optimized_bls12_381 import optimized_curve as curve, pairing
from verkle_trie.kzg_utils import KzgUtils
from fft import fft
from poly_utils import PrimeField
import pippenger
import blst
import hashlib
from typing import *

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


# Use KZG settings as seen in verkle_trie
class VerkleNode:
    node_type: NodeType = NodeType.EMPTY
    children: List["VerkleNode"] = []
    commitment = blst.G1().mult(0)
    value = -1

    # Empty || Leaf(Key, Value) || Node(Commitment, Children)
    # Commitment is a polynomial commitment to the values in the children nodes.
    # Children is a list of verkleNode objects.
    # Value is the value at the leaf node, or None for non-leaf nodes.
    def __init__(
        self, branch_factor: int, value=None, node_type: NodeType = NodeType.EMPTY
    ):
        """
        Initializes a verkle node.
        User provides a value if its a leaf node.
        If value is None, it is a non-leaf node and children will be initialized.
        """
        self.branch_factor = branch_factor
        self.value = value
        self.children = None if (value is not None) else [None] * branch_factor
        self.node_type = node_type
        # Omar you fucking retard, set the commitment to the identity element
        self.commitment = blst.G1().mult(0)


class VerkleTree:
    # Verkle Trie parameters kept the same as Ethereum's implementation
    KEY_LEN = 256
    WIDTH = 16
    PRIMITIVE_ROOT = 7
    MODULUS = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
    primefield = PrimeField(MODULUS)

    ROOT_OF_UNITY = pow(PRIMITIVE_ROOT, (MODULUS - 1) // WIDTH, MODULUS)
    DOMAIN = []

    # Empty || Leaf(Key, Value) || Node(Commitment, Children)
    def __init__(self, branch_factor: int):
        self.DOMAIN = [
            pow(self.ROOT_OF_UNITY, i, self.MODULUS) for i in range(self.WIDTH)
        ]
        self.branch_factor = branch_factor
        # one SRS for all nodes
        self.srs = generate_setup(branch_factor)
        # making an empty node
        self.root = VerkleNode(branch_factor)

    # Insert function acts as a prover according to video.

    def insert(self, key: int, value: int):
        node = self.root
        path = self.key_path(key)
        # descend and allocate internal nodes
        for i in path[:-1]:
            if node.children[i] is None:
                node.children[i] = VerkleNode(self.branch_factor)
            node = node.children[i]
        # final slot becomes leaf
        leaf_index = path[-1]
        node.children[leaf_index] = VerkleNode(self.branch_factor, NodeType.LEAF)
        node.children[leaf_index].value = value
        # recompute all commitments
        self.recommit(self.root)

    def key_path(self, key: int):
        """Returns the path to the key in the verkle tree."""
        path = []
        while key > 0:
            path.append(key % self.branch_factor)
            key //= self.branch_factor
        path.reverse()
        return path

    def recommit(self, node: VerkleNode):
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


def generate_setup(s):
    pass


def hash(x):
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
