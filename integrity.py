"""
Integrity Verification Module

Features:
- Merkle tree for chunk-level integrity
- Full-file HMAC verification
- Anti-tampering detection
- Chunk reordering detection
"""

import hashlib
import struct
from typing import List, Optional


class MerkleTree:
    """
    Merkle tree for chunk-level integrity verification.
    Allows verification of individual chunks without decrypting entire file.
    """

    def __init__(self):
        self.leaves: List[bytes] = []
        self._tree: List[List[bytes]] = []

    def add_leaf(self, data: bytes, chunk_index: int) -> bytes:
        """Add a chunk hash as a leaf node."""
        # Include chunk index in hash to prevent reordering
        leaf_hash = hashlib.blake2b(
            struct.pack(">Q", chunk_index) + data,
            digest_size=32
        ).digest()
        self.leaves.append(leaf_hash)
        return leaf_hash

    def build(self) -> bytes:
        """Build the Merkle tree and return root hash."""
        if not self.leaves:
            return b"\x00" * 32

        # Build tree bottom-up
        current_level = list(self.leaves)
        self._tree = [current_level[:]]

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent = hashlib.blake2b(
                    b"\x01" + left + right, digest_size=32
                ).digest()
                next_level.append(parent)
            self._tree.append(next_level[:])
            current_level = next_level

        return current_level[0]

    def get_proof(self, leaf_index: int) -> List[tuple]:
        """Get Merkle proof for a specific leaf."""
        if not self._tree:
            self.build()

        proof = []
        index = leaf_index

        for level in self._tree[:-1]:
            if index % 2 == 0:
                sibling_index = index + 1
                direction = 'right'
            else:
                sibling_index = index - 1
                direction = 'left'

            if sibling_index < len(level):
                proof.append((direction, level[sibling_index]))
            else:
                proof.append((direction, level[index]))

            index //= 2

        return proof

    @staticmethod
    def verify_proof(
        leaf_hash: bytes,
        proof: List[tuple],
        root_hash: bytes
    ) -> bool:
        """Verify a Merkle proof."""
        current = leaf_hash
        for direction, sibling in proof:
            if direction == 'right':
                current = hashlib.blake2b(
                    b"\x01" + current + sibling, digest_size=32
                ).digest()
            else:
                current = hashlib.blake2b(
                    b"\x01" + sibling + current, digest_size=32
                ).digest()

        return current == root_hash

    def serialize(self) -> bytes:
        """Serialize the leaf hashes for storage."""
        data = struct.pack(">I", len(self.leaves))
        for leaf in self.leaves:
            data += leaf
        return data

    @classmethod
    def deserialize(cls, data: bytes) -> 'MerkleTree':
        """Deserialize leaf hashes and rebuild tree."""
        tree = cls()
        count = struct.unpack(">I", data[:4])[0]
        offset = 4
        for _ in range(count):
            tree.leaves.append(data[offset:offset + 32])
            offset += 32
        tree.build()
        return tree


class IntegrityVerifier:
    """High-level integrity verification."""

    @staticmethod
    def create_canary(key: bytes) -> bytes:
        """
        Create a canary value that changes if the key is wrong.
        Used for fast wrong-password detection.
        """
        return hashlib.blake2b(
            b"CANARY:" + key,
            digest_size=16
        ).digest()

    @staticmethod
    def verify_canary(key: bytes, canary: bytes) -> bool:
        """Verify the canary value."""
        expected = hashlib.blake2b(
            b"CANARY:" + key,
            digest_size=16
        ).digest()
        return hmac_compare(expected, canary)


def hmac_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
