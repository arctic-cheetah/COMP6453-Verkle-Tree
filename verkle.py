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


def generate_setup(size: int, secret: int) -> Dict[str, List[blst.P1 | blst.P2]]:
    """
    Generate KZG setup parameters for polynomial commitments.
    
    Creates setup elements in G1 and G2 groups using the given secret,
    where G1 is the polynomial commitment group and G2 is the pairing group.
    Also generates Lagrange polynomials in G1 via FFT.
    
    Args:
        size: Number of setup elements to generate
        secret: Secret value for generating the setup
        
    Returns:
        Dictionary containing 'g1', 'g2', and 'g1_lagrange' arrays
    """

    g1_setup = np.array([blst.G1().mult(pow(secret, i, MODULUS)) for i in range(size)])
    g2_setup = np.array([blst.G2().mult(pow(secret, i, MODULUS)) for i in range(size)])
    g1_lagrange = np.array(fft(g1_setup, MODULUS, ROOT_OF_UNITY, inv=True))
    return {"g1": g1_setup, "g2": g2_setup, "g1_lagrange": g1_lagrange}


# Global constants for Verkle tree parameters
SECRET = 8927347823478352432985
KEY_LEN = 256
WIDTH_BITS = 8
WIDTH = 2**WIDTH_BITS
PRIMITIVE_ROOT = 7
MODULUS = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
primefield = PrimeField(MODULUS)
ROOT_OF_UNITY = pow(PRIMITIVE_ROOT, (MODULUS - 1) // WIDTH, MODULUS)
SETUP = generate_setup(WIDTH, SECRET)
DOMAIN = np.array(
    [pow(ROOT_OF_UNITY, i, MODULUS) for i in range(WIDTH)], dtype=np.object_
)
kzg_utils = KzgUtils(MODULUS, WIDTH, DOMAIN, SETUP, primefield)


def hash(x):
    """
    Hash function for bytes, integers, blst.P1 objects, and lists.
    
    If input is a list, hashes each element and concatenates the results.
    For blst.P1 objects, compresses them first before hashing.
    
    Args:
        x: Input to hash (bytes, int, blst.P1, or list of these types)
        
    Returns:
        SHA256 hash digest as bytes
    """
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


def hash_to_int(data) -> int:
    """
    Convert hash digest to integer.
    
    Args:
        data: Data to hash and convert
        
    Returns:
        Integer representation of the hash
    """
    return int.from_bytes(hash(data), "little")


class Proof:
    """
    Represents a Verkle tree proof containing all necessary data for verification.
    
    Attributes:
        depths: Array of depths for each key in the proof
        commitsSortedByIndex: Array of commitments sorted by index
        polySerialised: Serialized polynomial commitment
        challenge: Challenge value for the proof
        compressedMultiProof: Compressed KZG multiproof
    """
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
    # (i) a leaf node containing a key and value, or
    # (ii) an intermediate node that has some fixed number of children
    INNER = 1
    LEAF = 2


class VerkleTree:
    """
    Implementation of a Verkle tree with polynomial commitments at each node.
    
    A Verkle tree is a Merkle tree where each node contains a polynomial commitment
    to its children's values, enabling efficient batch proofs.
    """
    KEY_LEN = 256
    WIDTH_BITS = 8
    WIDTH = 2**WIDTH_BITS
    PRIMITIVE_ROOT = 7
    MODULUS = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
    primefield = PrimeField(MODULUS)
    branch_factor = -1
    ROOT_OF_UNITY = pow(PRIMITIVE_ROOT, (MODULUS - 1) // WIDTH, MODULUS)
    DOMAIN = np.array([], dtype=object)
    root: "VerkleNode" = None

    def __init__(self):
        """Initialize an empty Verkle tree."""
        self.DOMAIN = np.array(
            [pow(self.ROOT_OF_UNITY, i, self.MODULUS) for i in range(self.WIDTH)]
        )
        self.branch_factor = KEY_LEN // WIDTH_BITS
        self.root = VerkleNode(self.branch_factor, NodeType.INNER)

    def insert(self, currRoot: "VerkleNode", key: bytes, value: bytes):
        """
        Insert a key-value pair without updating hashes/commitments.
        
        This method allows building a full trie before computing commitments.
        Handles key collisions by splitting leaf nodes when necessary.
        
        Args:
            currRoot: Root node to start insertion from
            key: Key to insert
            value: Value associated with the key
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
                    KEY_LEN, value, key, NodeType.LEAF
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
            assert prevNode is not None
            prevNode.children[currIndex] = VerkleNode(node_type=NodeType.INNER)
            # Re-insert both the old and new keys from the root.
            # This will correctly build the new branch under the new inner node.
            self.insert(self.root, key, value)
            self.insert(self.root, old_leaf_key, old_leaf_value)

    def insert_update_node(self, key: bytes, value: bytes) -> bool:
        """
        Insert or update a key-value pair with immediate commitment updates.
        
        This method updates all parent commitments along the insertion path
        and handles key collisions by splitting nodes when necessary.
        
        Args:
            key: Key to insert or update
            value: Value associated with the key
            
        Returns:
            True if insertion was successful, False if index collision occurred
        """
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
                        # If index is the same we need to split the node until
                        # the indices are different
                        # But ethereum's implementation did not do so
                        # So we won't do it too.
                        if newIndex == oldIndex:
                            # print("Insertion Error: Index Collision! Try again")
                            return False
                        newInnerNode.children[newIndex] = newNode
                        newInnerNode.children[oldIndex] = oldNode
                        add_node_hash(newInnerNode)
                        node.children[index] = newInnerNode
                        valueChange = (
                            MODULUS
                            + int.from_bytes(newInnerNode.hash, "little")
                            - int.from_bytes(oldNode.hash, "little")
                        ) % MODULUS
                        break

                node = node.children[index]
            else:
                # It is empty so just add it
                node.children[index] = newNode
                valueChange = int.from_bytes(newNode.hash, "little") % MODULUS
                break

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
        return True

    def getVerkleIndex(self, key: bytes) -> Tuple[int]:
        """
        Generate Verkle indices for a given key.
        
        Converts the key into a sequence of indices used for tree traversal.
        
        Args:
            key: Key to convert to indices
            
        Returns:
            Tuple of indices for tree traversal
        """
        x = int.from_bytes(key, "big")
        last_index_bits = KEY_LEN % WIDTH_BITS
        index = (x % (2**last_index_bits)) << (WIDTH_BITS - last_index_bits)
        x //= 2**last_index_bits
        indices = [index]
        for _ in range((KEY_LEN - 1) // WIDTH_BITS):
            index = x % WIDTH
            x //= WIDTH
            indices.append(index)
        return tuple(np.array(list(reversed(indices)), dtype=int))


    def check_kzg_multiproof(self, Cs, indices, ys, proof):
        """
        Verify a KZG multiproof according to the schema described in:
        https://dankradfeist.de/ethereum/2021/06/18/pcs-multiproofs.html
        
        Args:
            Cs: List of commitments
            indices: List of indices
            ys: List of y-values
            proof: Tuple containing (D_serialized, y, sigma_serialized)
            
        Returns:
            True if proof is valid, False otherwise
        """
        D_serialized, y, sigma_serialized = proof
        D = blst.P1(D_serialized)
        sigma = blst.P1(sigma_serialized)

        ys_bytes = [val.to_bytes(32, "little") for val in ys]

        # Step 1: Hash the commitments, ys, and indices to get r
        r = (
            hash_to_int(
                [hash(C.compress()) for C in Cs]
                + ys_bytes
                + [kzg_utils.DOMAIN[i] for i in indices]
            )
            % MODULUS
        )

        # Step 2: Compute t = hash(r, D)
        t = hash_to_int([r, D]) % MODULUS
        E_coefficients = []
        g_2_of_t = 0
        power_of_r = 1

        for index, y_val in zip(indices, ys):
            E_coefficient = primefield.div(power_of_r, (t - DOMAIN[index]) % MODULUS)
            E_coefficients.append(E_coefficient)
            g_2_of_t = (g_2_of_t + E_coefficient * y_val) % MODULUS
            power_of_r = (power_of_r * r) % MODULUS

        E = pippenger.pippenger_simple(Cs, E_coefficients)

        # Step 3: Compute w = y - g_2_of_t
        # Step 4: Compute q = hash(E, D, y, w)
        # Step 5: Check KZG proofs
        w = (y - g_2_of_t) % MODULUS
        q = hash_to_int([E, D, y, w])

        if not kzg_utils.check_kzg_proof(
            E.dup().add(D.dup().mult(q)), t, (y + q * w) % MODULUS, sigma
        ):
            return False

        return True

    def make_kzg_multiproof(self, Cs, fs, indices, ys):
        """
        Compute a KZG multiproof according to the schema described in:
        https://dankradfeist.de/ethereum/2021/06/18/pcs-multiproofs.html
        
        Args:
            Cs: List of commitments
            fs: List of polynomials
            indices: List of indices
            ys: List of y-values
            
        Returns:
            Tuple containing (D_serialized, y, sigma_serialized)
        """

        # Step 1: Construct g(X) polynomial in evaluation form
        r = (
            hash_to_int(
                [hash(C) for C in Cs]
                + [y.to_bytes(32, "little") for y in ys]
                + [kzg_utils.DOMAIN[i] for i in indices]
            )
            % MODULUS
        )

        g = np.zeros(WIDTH, dtype=np.object_)
        power_of_r = 1
        for f, index in zip(fs, indices):
            quotient = kzg_utils.compute_inner_quotient_in_evaluation_form(f, index)
            quotient = np.array(quotient, dtype=np.object_)
            g = g + (power_of_r * quotient)
            power_of_r = power_of_r * r % MODULUS

        D = kzg_utils.compute_commitment_lagrange({i: v for i, v in enumerate(g)})

        # Step 2: Compute h in evaluation form

        t = hash_to_int([r, D]) % MODULUS

        h = np.zeros(WIDTH, dtype=np.object_)
        power_of_r = 1

        for f, index in zip(fs, indices):
            denominator_inv = primefield.inv((t - DOMAIN[index]) % MODULUS)
            f_arr = np.array(f, dtype=np.object_)
            h = (h + (power_of_r * f_arr * denominator_inv)) % MODULUS
            power_of_r = power_of_r * r % MODULUS

        # Step 3: Evaluate and compute KZG proofs

        y, pi = kzg_utils.evaluate_and_compute_kzg_proof(h, t)
        w, rho = kzg_utils.evaluate_and_compute_kzg_proof(g, t)

        # Compress both proofs into one

        E = kzg_utils.compute_commitment_lagrange({i: v for i, v in enumerate(h)})
        q = hash_to_int([E, D, y, w])
        sigma = pi.dup().add(rho.dup().mult(q))

        return D.compress(), y, sigma.compress()

    def find_node_with_path(self, node: "VerkleNode", key: bytes):
        """
        Find a node with the given key and return the path to it.
        
        Args:
            node: Starting node for search
            key: Key to search for
            
        Returns:
            Tuple of (path, node) where path contains (index_path, index, node) tuples
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
        self, tree: "VerkleTree", keys: List[bytes]
    ) -> Proof:
        """
        Create a proof for the given keys in the Verkle tree.
        
        Args:
            tree: The Verkle tree to create proof for
            keys: List of keys to include in the proof
            
        Returns:
            Proof object containing all necessary data for verification
        """
        # Step 0: Find all keys in the trie
        nodesByIndex = {}
        nodesByIndexSubIndex = {}
        values: np.ndarray = np.array([], dtype=object)
        depths: np.ndarray = np.array([], dtype=int)
        for key in keys:
            path, node = self.find_node_with_path(tree.root, key)
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
                nodesByIndex[index] = node
                nodesByIndexSubIndex[(index, subindex)] = node

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

        # Step 1: Compress the proofs and make them into bytes
        fs = []
        Cs = np.array(
            [x.commitment for x in nodesSortedByIndexAndSubIndex], dtype=object
        )
        for node in nodesSortedByIndexAndSubIndex:
            if node.node_type == NodeType.LEAF:
                assert False  # should never happen
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
                            for i in range(WIDTH)
                        ],
                        dtype=object,
                    )
                )

        polySerialised, challenge, compressedMultiProof = self.make_kzg_multiproof(
            Cs, fs, indices, ys
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
    ):
        """
        Verify a Verkle tree proof.
        
        Args:
            rootCommit: Root commitment of the tree
            keys: List of keys in the proof
            values: List of values corresponding to the keys
            proof: Proof object to verify
            
        Returns:
            True if proof is valid, False otherwise
        """
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

        return self.check_kzg_multiproof(
            Cs,
            indices,
            ys,
            [proof.polySerialised, proof.challenge, proof.compressedMultiProof]
        )

    def delete(self, key: bytes) -> bool:
        """
        Delete a key-value pair from the Verkle tree.
        
        Removes the leaf with the given key and prunes empty/single-leaf inner nodes.
        Recomputes commitments and hashes for affected nodes.
        
        Args:
            key: Key to delete
            
        Returns:
            True if key was found and deleted, False otherwise
        """
        # Special case: empty tree
        if self.root is None:
            return False

        # If root is a leaf
        if self.root.node_type == NodeType.LEAF:
            if self.root.key == key:
                # Reset to empty inner root
                self.root = VerkleNode(node_type=NodeType.INNER)
                add_node_hash(self.root)
                return True
            return False

        indices = iter(self.getVerkleIndex(key))
        parent = None
        node = self.root
        path: List[Tuple[int, VerkleNode, Optional[VerkleNode]]] = []

        # Descend to leaf
        try:
            while node.node_type == NodeType.INNER:
                idx = next(indices)
                path.append((idx, node, parent))
                if node.children[idx] is None:
                    return False  # Key not present
                parent = node
                node = node.children[idx]
        except StopIteration:
            return False

        # Now at a leaf
        if node.node_type != NodeType.LEAF or node.key != key:
            return False

        # Remove leaf from its parent
        if not path:
            return False  # Should not happen (root leaf handled earlier)
        leaf_parent_index, leaf_parent_node, _ = path[-1]
        leaf_parent_node.children[leaf_parent_index] = None

        # Prune upwards: remove empty inner nodes / collapse single-leaf inner nodes
        for idx, curr, curr_parent in reversed(path):
            if curr.node_type != NodeType.INNER:
                continue
            # Count non-empty children
            non_empty = [c for c in curr.children if c is not None]
            if len(non_empty) == 0:
                if curr_parent is not None:
                    curr_parent.children[idx] = None
                # If root becomes empty, keep as empty inner node
            elif (
                len(non_empty) == 1
                and non_empty[0].node_type == NodeType.LEAF
                and curr_parent is not None
            ):
                # Collapse single leaf child upward
                curr_parent.children[idx] = non_empty[0]

        # Recompute (full) – could be optimized to incremental
        add_node_hash(self.root)
        return True


class VerkleNode:
    """
    Represents a node in the Verkle tree.
    
    Each node can be either an inner node (with children) or a leaf node
    (with a key-value pair). Inner nodes contain polynomial commitments
    to their children's values.
    """
    children: np.ndarray["VerkleNode"] = np.array(
        [None] * VerkleTree.KEY_LEN, dtype=object
    )

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
        Initialize a Verkle node.
        
        Args:
            branch_factor: Number of children for inner nodes
            value: Value for leaf nodes
            key: Key for leaf nodes
            node_type: Type of node (INNER or LEAF)
        """
        self.key = key
        self.branch_factor = KEY_LEN
        self.value = value
        if node_type == NodeType.INNER:
            self.children = np.array([None] * KEY_LEN, dtype=object)
        else:
            self.children = None

        self.node_type = node_type
        self.commitment = blst.G1().mult(0)
        self.commitmentCompressed = self.commitment.compress()


def add_node_hash(node: VerkleNode):
    """
    Recursively compute commitments and hashes for a Verkle tree structure.
    
    Uses Ethereum's implementation of KZG computation for polynomial commitments.
    For leaf nodes, computes hash of key-value pair.
    For inner nodes, computes polynomial commitment to children's hashes.
    
    Args:
        node: Root node to start computation from
    """
    if node.node_type == NodeType.LEAF:
        node.hash = hash([node.key, node.value])
    if node.node_type == NodeType.INNER:
        values = {}
        for i in range(WIDTH):
            if node.children[i] is not None:
                if node.children[i].hash == b"":
                    add_node_hash(node.children[i])
                values[i] = int.from_bytes(node.children[i].hash, "little")
        node.commitment = kzg_utils.compute_commitment_lagrange(values)
        node.hash = hash(node.commitment.compress())


def checkValidTree(root: VerkleNode):
    """
    Validate the entire Verkle tree structure.
    
    Recursively checks that all commitments and hashes are correctly computed
    throughout the tree.
    
    Args:
        root: Root node of the tree to validate
    """
    if root.node_type == NodeType.INNER:
        values = {}
        for i in range(WIDTH):
            if root.children[i] is not None:
                if root.children[i].hash == b"":
                    add_node_hash(root.children[i])
                values[i] = int.from_bytes(root.children[i].hash, "little")
        commit = kzg_utils.compute_commitment_lagrange(values)

        for i in range(WIDTH):
            if root.children[i] is not None:
                checkValidTree(root.children[i])
    else:
        assert root.hash == hash([root.key, root.value])


#from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed

# Parallel processing confers no advantage here


# def add_node_hash_parallel(node: VerkleNode, max_workers=8):
#     """
#     Recursively adds all missing commitments and hashes to a verkle trie structure in parallel.
#     """
#     if node.node_type == NodeType.LEAF:
#         node.hash = hash([node.key, node.value])
#         return

#     if node.node_type == NodeType.INNER:
#         values = {}
#         futures = []
#         with ThreadPoolExecutor(max_workers=max_workers) as executor:
#             for i in range(WIDTH):
#                 child = node.children[i]
#                 if child is not None:
#                     if child.hash == b"":
#                         futures.append(
#                             executor.submit(add_node_hash_parallel, child, max_workers)
#                         )
#             for future in as_completed(futures):
#                 future.result()
#             for i in range(WIDTH):
#                 child = node.children[i]
#                 if child is not None:
#                     values[i] = int.from_bytes(child.hash, "little")
#         node.commitment = kzg_utils.compute_commitment_lagrange(values)
#         node.hash = hash(node.commitment.compress())
#         node.commitment = kzg_utils.compute_commitment_lagrange(values)
#         node.hash = hash(node.commitment.compress())
#             for future in as_completed(futures):
#                 future.result()
#             for i in range(WIDTH):
#                 child = node.children[i]
#                 if child is not None:
#                     values[i] = int.from_bytes(child.hash, "little")
#         node.commitment = kzg_utils.compute_commitment_lagrange(values)
#         node.hash = hash(node.commitment.compress())
#         node.commitment = kzg_utils.compute_commitment_lagrange(values)
#         node.hash = hash(node.commitment.compress())

