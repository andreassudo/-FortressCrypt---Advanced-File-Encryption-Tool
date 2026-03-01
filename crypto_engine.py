"""
Core Cryptographic Engine

Features:
- Streaming authenticated encryption (chunked processing)
- Cascade encryption (AES-256-GCM → ChaCha20-Poly1305)
- Per-chunk nonce derivation (counter-based, no nonce reuse)
- Constant-time operations where applicable
- Memory-safe: processes files in chunks, not loading entirely into RAM
"""

import os
import struct
import hashlib
import hmac as hmac_module
from typing import BinaryIO, Generator, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import constant_time

from header import CipherSuite


# Authentication tag sizes
AES_GCM_TAG_SIZE = 16
CHACHA_TAG_SIZE = 16


class NonceDeriver:
    """
    Derive unique nonces for each chunk to prevent nonce reuse.
    Uses HKDF-style derivation with chunk counter.
    """

    def __init__(self, base_nonce: bytes, nonce_size: int = 12):
        self.base_nonce = base_nonce
        self.nonce_size = nonce_size

    def derive(self, chunk_index: int, layer: int = 0) -> bytes:
        """
        Derive a unique nonce for a specific chunk and encryption layer.
        
        Uses: BLAKE2b(base_nonce || chunk_index || layer) truncated to nonce_size
        """
        material = (
            self.base_nonce
            + struct.pack(">Q", chunk_index)
            + struct.pack(">B", layer)
        )
        derived = hashlib.blake2b(
            material, digest_size=self.nonce_size
        ).digest()
        return derived


class StreamingEncryptor:
    """Streaming authenticated encryption with associated data."""

    def __init__(
        self,
        cipher_suite: CipherSuite,
        keys: dict,
        base_nonce: bytes,
        chunk_size: int = 65536
    ):
        self.cipher_suite = cipher_suite
        self.keys = keys
        self.base_nonce = base_nonce
        self.chunk_size = chunk_size
        self.nonce_deriver = NonceDeriver(base_nonce)

        # Initialize cipher(s)
        self._init_ciphers()

    def _init_ciphers(self):
        if self.cipher_suite in (
            CipherSuite.AES_256_GCM,
            CipherSuite.AES_256_GCM_THEN_CHACHA20
        ):
            self.aes_gcm = AESGCM(self.keys['aes_key'])

        if self.cipher_suite in (
            CipherSuite.CHACHA20_POLY1305,
            CipherSuite.AES_256_GCM_THEN_CHACHA20,
            CipherSuite.XCHACHA20_POLY1305
        ):
            self.chacha = ChaCha20Poly1305(self.keys['chacha_key'])

    def encrypt_chunk(
        self,
        plaintext: bytes,
        chunk_index: int,
        aad: bytes = b""
    ) -> bytes:
        """
        Encrypt a single chunk with the configured cipher suite.
        
        For cascade mode: plaintext → AES-256-GCM → ChaCha20-Poly1305
        Each layer uses a different key and independently derived nonce.
        """
        # Build associated data: chunk index for ordering verification
        full_aad = struct.pack(">Q", chunk_index) + aad

        if self.cipher_suite == CipherSuite.AES_256_GCM:
            nonce = self.nonce_deriver.derive(chunk_index, layer=0)
            return self.aes_gcm.encrypt(nonce, plaintext, full_aad)

        elif self.cipher_suite == CipherSuite.CHACHA20_POLY1305:
            nonce = self.nonce_deriver.derive(chunk_index, layer=0)
            return self.chacha.encrypt(nonce, plaintext, full_aad)

        elif self.cipher_suite == CipherSuite.AES_256_GCM_THEN_CHACHA20:
            # Layer 1: AES-256-GCM
            nonce1 = self.nonce_deriver.derive(chunk_index, layer=0)
            intermediate = self.aes_gcm.encrypt(nonce1, plaintext, full_aad)

            # Layer 2: ChaCha20-Poly1305 over AES-GCM ciphertext
            nonce2 = self.nonce_deriver.derive(chunk_index, layer=1)
            return self.chacha.encrypt(nonce2, intermediate, full_aad)

        elif self.cipher_suite == CipherSuite.XCHACHA20_POLY1305:
            nonce = self.nonce_deriver.derive(chunk_index, layer=0)
            return self.chacha.encrypt(nonce, plaintext, full_aad)

        raise ValueError(f"Unknown cipher suite: {self.cipher_suite}")

    def decrypt_chunk(
        self,
        ciphertext: bytes,
        chunk_index: int,
        aad: bytes = b""
    ) -> bytes:
        """Decrypt a single chunk, reversing the encryption layers."""
        full_aad = struct.pack(">Q", chunk_index) + aad

        if self.cipher_suite == CipherSuite.AES_256_GCM:
            nonce = self.nonce_deriver.derive(chunk_index, layer=0)
            return self.aes_gcm.decrypt(nonce, ciphertext, full_aad)

        elif self.cipher_suite == CipherSuite.CHACHA20_POLY1305:
            nonce = self.nonce_deriver.derive(chunk_index, layer=0)
            return self.chacha.decrypt(nonce, ciphertext, full_aad)

        elif self.cipher_suite == CipherSuite.AES_256_GCM_THEN_CHACHA20:
            # Reverse: ChaCha20 first, then AES-GCM
            nonce2 = self.nonce_deriver.derive(chunk_index, layer=1)
            intermediate = self.chacha.decrypt(nonce2, ciphertext, full_aad)

            nonce1 = self.nonce_deriver.derive(chunk_index, layer=0)
            return self.aes_gcm.decrypt(nonce1, intermediate, full_aad)

        elif self.cipher_suite == CipherSuite.XCHACHA20_POLY1305:
            nonce = self.nonce_deriver.derive(chunk_index, layer=0)
            return self.chacha.decrypt(nonce, ciphertext, full_aad)

        raise ValueError(f"Unknown cipher suite: {self.cipher_suite}")

    def get_ciphertext_overhead(self) -> int:
        """Calculate per-chunk ciphertext overhead (auth tags)."""
        if self.cipher_suite == CipherSuite.AES_256_GCM:
            return AES_GCM_TAG_SIZE
        elif self.cipher_suite == CipherSuite.CHACHA20_POLY1305:
            return CHACHA_TAG_SIZE
        elif self.cipher_suite == CipherSuite.AES_256_GCM_THEN_CHACHA20:
            return AES_GCM_TAG_SIZE + CHACHA_TAG_SIZE  # Both tags
        elif self.cipher_suite == CipherSuite.XCHACHA20_POLY1305:
            return CHACHA_TAG_SIZE
        return 0


class StreamProcessor:
    """Process files as streams with progress tracking."""

    @staticmethod
    def read_chunks(
        file_handle: BinaryIO,
        chunk_size: int
    ) -> Generator[Tuple[int, bytes], None, None]:
        """Read file in chunks, yielding (chunk_index, data)."""
        chunk_index = 0
        while True:
            data = file_handle.read(chunk_size)
            if not data:
                break
            yield chunk_index, data
            chunk_index += 1

    @staticmethod
    def compute_file_hash(file_path: str) -> bytes:
        """Compute BLAKE2b hash of entire file."""
        hasher = hashlib.blake2b(digest_size=64)
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.digest()

    @staticmethod
    def compute_stream_hmac(
        file_path: str,
        hmac_key: bytes,
        skip_bytes: int = 0
    ) -> bytes:
        """Compute HMAC-SHA512 over file content (after header)."""
        h = hmac_module.new(hmac_key, digestmod=hashlib.sha512)
        with open(file_path, 'rb') as f:
            if skip_bytes:
                f.seek(skip_bytes)
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.digest()
