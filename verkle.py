# TODO: Add verkle tree here
from hashlib import sha256

# Commitment is 256 bits


class verkleNode:
    pass


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
