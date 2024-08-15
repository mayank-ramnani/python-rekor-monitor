import hashlib
import binascii

# domain separation prefixes according to the RFC
RFC6962_LEAF_HASH_PREFIX = 0
RFC6962_NODE_HASH_PREFIX = 1

class Hasher:
    def __init__(self, hash_func=hashlib.sha256):
        self.hash_func = hash_func

    def new(self):
        return self.hash_func()

    def empty_root(self):
        return self.new().digest()

    def hash_leaf(self, leaf):
        h = self.new()
        h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        h.update(leaf)
        return h.digest()

    def hash_children(self, l, r):
        h = self.new()
        b = bytes([RFC6962_NODE_HASH_PREFIX]) + l + r
        h.update(b)
        return h.digest()

    def size(self):
        return self.new().digest_size

# DefaultHasher is a SHA256 based LogHasher
DefaultHasher = Hasher(hashlib.sha256)

def verify_consistency(hasher, size1, size2, proof, root1, root2):
    # change format of args to be bytearray instead of hex strings
    root1 = bytes.fromhex(root1)
    root2 = bytes.fromhex(root2)
    bytearray_proof = []
    for elem in proof:
        bytearray_proof.append(bytes.fromhex(elem))
    proof = bytearray_proof

    if size2 < size1:
        raise ValueError(f"size2 ({size2}) < size1 ({size1})")
    if size1 == size2:
        if proof:
            raise ValueError("size1=size2, but proof is not empty")
        verify_match(root1, root2)
        return
    if size1 == 0:
        if proof:
            raise ValueError(f"expected empty proof, but got {len(proof)} components")
        return
    if not proof:
        raise ValueError("empty proof")

    inner, border = decomp_incl_proof(size1 - 1, size2)
    shift = (size1 & -size1).bit_length() - 1
    inner -= shift

    if size1 == 1 << shift:
        seed, start = root1, 0
    else:
        seed, start = proof[0], 1

    if len(proof) != start + inner + border:
        raise ValueError(f"wrong proof size {len(proof)}, want {start + inner + border}")

    proof = proof[start:]

    mask = (size1 - 1) >> shift
    hash1 = chain_inner_right(hasher, seed, proof[:inner], mask)
    hash1 = chain_border_right(hasher, hash1, proof[inner:])
    verify_match(hash1, root1)

    hash2 = chain_inner(hasher, seed, proof[:inner], mask)
    hash2 = chain_border_right(hasher, hash2, proof[inner:])
    verify_match(hash2, root2)

def verify_match(calculated, expected):
    if calculated != expected:
        raise RootMismatchError(expected, calculated)

def decomp_incl_proof(index, size):
    inner = inner_proof_size(index, size)
    border = bin(index >> inner).count('1')
    return inner, border

def inner_proof_size(index, size):
    return (index ^ (size - 1)).bit_length()

def chain_inner(hasher, seed, proof, index):
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 0:
            seed = hasher.hash_children(seed, h)
        else:
            seed = hasher.hash_children(h, seed)
    return seed

def chain_inner_right(hasher, seed, proof, index):
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 1:
            seed = hasher.hash_children(h, seed)
    return seed

def chain_border_right(hasher, seed, proof):
    for h in proof:
        seed = hasher.hash_children(h, seed)
    return seed

class RootMismatchError(Exception):
    def __init__(self, expected_root, calculated_root):
        self.expected_root = binascii.hexlify(bytearray(expected_root))
        self.calculated_root = binascii.hexlify(bytearray(calculated_root))

    def __str__(self):
        return f"calculated root:\n{self.calculated_root}\n does not match expected root:\n{self.expected_root}"
