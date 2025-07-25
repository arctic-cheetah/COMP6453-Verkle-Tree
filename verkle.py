# TODO: Add verkle tree here
from hashlib import sha256
import hashlib, secrets, sympy
from py_ecc.optimized_bls12_381 import optimized_curve as curve, pairing

# Commitment is 256 bits

## A verkle tree is a Merkle tree with polynomial commitments at each node.
'''
    Need the following constructs:
    - Verkle tree data structure
    - Prove and verify functions
'''

class VerkleNode:
    # Empty || Leaf(Key, Value) || Node(Commitment, Children)
    # Commitment is a polynomial commitment to the values in the children nodes.
    # Children is a list of verkleNode objects.
    # Value is the value at the leaf node, or None for non-leaf nodes.
    def __init__(self, branch_factor: int, value=None):
        '''
            Initializes a verkle node.
            User provides a value if its a leaf node.
            If value is None, it is a non-leaf node and children will be initialized.
        '''
        self.branch_factor = branch_factor
        self.value = value
        self.children = None if (value is not None) else [None] * branch_factor
        self.commitment = None
        

class VerkleTree:
    # Empty || Leaf(Key, Value) || Node(Commitment, Children)
    def __init__(self, branch_factor : int):
        self.branch_factor = branch_factor
        # making an empty node
        self.root = VerkleNode(branch_factor)  

    def insert(self, key: int, value: int):
        node = self.root
        path = self.key_path(key)
        # descend and allocate internal nodes
        for i in path[:-1]:
            if node.children[i] is None:
                node.children[i] = VerkleNode(self.b)
            node = node.children[i]
        # final slot becomes leaf
        leaf_index = path[-1]
        node.children[leaf_index] = VerkleNode(self.b, is_leaf=True)
        node.children[leaf_index].value = value
        # recompute all commitments
        self.recommit(self.root)

    def key_path(self, key: int):
        path = []
        while key > 0:
            path.append(key % self.branch_factor)
            key //= self.branch_factor
        return path.reverse()

    def recommit(self, node: VerkleNode):
        pass

    def root_commit(self): 
        return self.root.commitment

    def prove(self, key: int): 
        pass

    def verify(self, key: int, value: int, proof):
        pass


#           KZG Commitment (https://raw.githubusercontent.com/giuliop/plonk/main/kzg.py)

# Curve order
factorization = [
    2**32, 3, 11, 19, 10177, 125527, 859267, 906349, 906349,
    2508409, 2529403, 52437899, 254760293, 254760293
]
q_1 = 1
for f in factorization: q_1 *= f
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
