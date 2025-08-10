# Verkle Tree Implementation

A comprehensive implementation of Verkle trees with polynomial commitments, featuring KZG (Kate-Zaverucha-Goldberg) proofs for efficient batch verification.

## Overview

This project implements a Verkle tree data structure, which is a Merkle tree where each node contains a polynomial commitment to its children's values. This enables efficient batch proofs and verification, making it suitable for blockchain applications and other systems requiring scalable cryptographic proofs.

### Key Features

- **Polynomial Commitments**: Uses KZG commitments for efficient proof generation
- **Batch Proofs**: Generate and verify proofs for multiple keys simultaneously
- **Efficient Operations**: Insert, update, delete, and query operations
- **Cryptographic Security**: Based on BLS12-381 elliptic curve
- **Performance Optimized**: Includes FFT and Pippenger algorithms for fast computation

## Project Structure

```
COMP6453-Verkle-Tree/
├── verkle.py              # Main Verkle tree implementation
├── main.py                # Demonstration and testing script
├── requirements.txt       # Python dependencies
├── .venv/                 # Virtual environment
├── blst.py               # BLS12-381 curve operations
├── kzg_utils.py          # KZG commitment utilities
├── fft.py                # Fast Fourier Transform implementation
├── poly_utils.py         # Polynomial arithmetic utilities
├── pippenger.py          # Pippenger algorithm for multi-scalar multiplication
├── verkle_trie/          # Ethereum Verkle trie implementation (using KZG commitment scheme)
├── verkle_trie_ethereum/ # Ethereum Verkle Trie implementation (using the IPA commitment scheme)
├── libraries/            # Additional library files
└── research/             # Research and documentation
```

## Prerequisites

- **Python 3.10** (required for compatibility with compiled extensions)
- **pip** (Python package installer)
- **Git** (for cloning the repository)

## Installation

### Step 1: Clone the Repository

```bash
git clone <repository-url>
cd COMP6453-Verkle-Tree
```

### Step 2: Create Virtual Environment

```bash
python3.10 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

**Note**: If you encounter issues with the virtual environment's pip, use:
```bash
python -m pip install -r requirements.txt
```

### Step 4: Verify Installation

```bash
python main.py
```

You should see output similar to:
```
Inserted 32768 elements in 0.828s
Computed verkle root (insert) in 23.808s
Check that verkle tree is valid in 28.458s
...
```

## Usage

### Basic Operations

#### 1. Creating a Verkle Tree

```python
from verkle import VerkleTree

# Create an empty Verkle tree
tree = VerkleTree()
```

#### 2. Inserting Key-Value Pairs

```python
# Insert without immediate commitment updates (for batch operations)
key = b"example_key"
value = b"example_value"
tree.insert(tree.root, key, value)

# Insert with immediate commitment updates
success = tree.insert_update_node(key, value)
```

#### 3. Computing Root Commitment

```python
from verkle import add_node_hash

# Compute all commitments and hashes
add_node_hash(tree.root)

# Get the root commitment
root_commitment = tree.root.commitment
```

#### 4. Creating Proofs

```python
# Create a proof for multiple keys
keys = [b"key1", b"key2", b"key3"]
proof = tree.make_verkle_proof(tree, keys)
```

#### 5. Verifying Proofs

```python
# Verify a proof
values = [b"value1", b"value2", b"value3"]
is_valid = tree.check_verkle_proof(
    tree.root.commitment.compress(),
    keys,
    values,
    proof
)
```

#### 6. Deleting Keys

```python
# Delete a key-value pair
success = tree.delete(key)
```

### Advanced Usage

#### Batch Operations

```python
# Insert multiple keys efficiently
for i in range(1000):
    key = f"key_{i}".encode()
    value = f"value_{i}".encode()
    tree.insert(tree.root, key, value)

# Compute all commitments at once
add_node_hash(tree.root)
```

#### Tree Validation

```python
from verkle import checkValidTree

# Validate the entire tree structure
checkValidTree(tree.root)
```

## Performance Characteristics

Based on the demonstration in `main.py`:

- **Insertion**: ~32,768 elements in ~0.8 seconds
- **Root Computation**: ~24 seconds for 32,768 elements
- **Tree Validation**: ~28 seconds for 32,768 elements
- **Proof Generation**: ~2 seconds for 5,000 keys
- **Proof Verification**: ~0.24 seconds for 5,000 keys
- **Deletion**: ~22 seconds for 512 elements

## Technical Details

### Cryptographic Parameters

Same cryptographic parameters as etheirums verkle tree

- **Curve**: BLS12-381
- **Field Modulus**: 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
- **Key Length**: 256 bits
- **Width**: 256 (branch factor)
- **Primitive Root**: 7

### KZG Commitment Scheme

The implementation uses the KZG (Kate-Zaverucha-Goldberg) commitment scheme for polynomial commitments:

1. **Setup**: Trusted setup parameters for G1 and G2 elliptic curve groups
2. **Commitment**: Polynomial commitment using Lagrange basis
3. **Proof Generation**: Multi-proof generation for batch verification
4. **Verification**: Efficient batch verification of multiple proofs

### Tree Structure

- **Inner Nodes**: Contain polynomial commitments to children's hashes
- **Leaf Nodes**: Contain key-value pairs
- **Collision Handling**: Automatic node splitting for key collisions
- **Pruning**: Automatic removal of empty nodes during deletion

## API Reference

### VerkleTree Class

#### Methods

- `__init__()`: Initialize an empty Verkle tree
- `insert(root, key, value)`: Insert key-value pair without commitment updates
- `insert_update_node(key, value)`: Insert with immediate commitment updates
- `delete(key)`: Delete a key-value pair
- `getVerkleIndex(key)`: Generate Verkle indices for a key
- `make_verkle_proof(tree, keys)`: Create a proof for multiple keys
- `check_verkle_proof(root_commit, keys, values, proof)`: Verify a proof
- `check_kzg_multiproof(Cs, indices, ys, proof)`: Verify KZG multiproof
- `make_kzg_multiproof(Cs, fs, indices, ys)`: Generate KZG multiproof

### Utility Functions

- `add_node_hash(node)`: Compute commitments and hashes recursively
- `checkValidTree(root)`: Validate tree structure
- `hash(data)`: Universal hash function
- `generate_setup(size, secret)`: Generate KZG setup parameters

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure you're using Python 3.10 and the virtual environment is activated

### Debugging

Enable timing information in proof operations:
```python
proof = tree.make_verkle_proof(tree, keys)
```

## License

GNU General Public License 3.0 or later

[Liecense](https://www.gnu.org/licenses/gpl-3.0.txt)


## Acknowledgments

- Based on Ethereum's Verkle tree implementation
- Uses BLS12-381 curve operations from the `blst` library
- KZG commitment scheme implementation following Dankrad Feist's specifications

## References

- [Verkle Trees: Everything You Need to Know](https://lucasmartincalderon.medium.com/verkle-trees-everything-you-need-to-know-321c9c8bc2f6)
- [Ethereum Verkle Tree Structure](https://blog.ethereum.org/2021/12/02/verkle-tree-structure)
- [Ethereum Github](https://github.com/ethereum/research/tree/master)
- [KZG Multiproofs](https://dankradfeist.de/ethereum/2021/06/18/pcs-multiproofs.html)
- [Merkle Tree](https://www.youtube.com/watch?v=3AcQyTs_Es4)
    - Merkle + Patricia Trie
        - [Long](https://www.youtube.com/watch?v=QlawpoK4g5A)
        - [Short](https://youtu.be/DGvRY9BjLRs)

- [Tries](https://www.youtube.com/watch?v=zIjfhVPRZCg&pp=ygUNUGF0cmljaWEgVHJpZdIHCQm-CQGHKiGM7w%3D%3D)
    - [Compressed Tries](https://www.youtube.com/watch?v=dbTVU8jR0Vs&pp=ygUNUGF0cmljaWEgVHJpZdIHCQm-CQGHKiGM7w%3D%3D)
    - [Second video](https://www.youtube.com/watch?v=qakGXuOW1S8&pp=ygUNUGF0cmljaWEgVHJpZQ%3D%3D)

- [Verkle Trie](https://www.youtube.com/watch?v=3PyDkMYrzAs)
- [Research Paper 1 Verkle Trees](https://math.mit.edu/research/highschool/primes/materials/2018/Kuszmaul.pdf)
- [Research Paper 2 Ver(y Short Mer)kle Trees](https://math.mit.edu/research/highschool/primes/materials/2019/conf/12-5-Kuszmaul.pdf)
- [Research Paper 3 Ethereum blog](https://blog.ethereum.org/2021/12/02/verkle-tree-structure)



