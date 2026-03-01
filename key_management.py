"""
Advanced Key Derivation & Management

Features:
- Argon2id with aggressive parameters
- Optional double derivation (Argon2id → HKDF)
- Key splitting for cascade ciphers
- Ephemeral key exchange support
- Anti-brute-force design
"""

import os
import hashlib
import hmac as hmac_module
import secrets
from typing import Tuple

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from header import KDFParams, KDFType


class KeyDerivationEngine:
    """High-security key derivation with multiple strategies."""

    @staticmethod
    def derive_argon2id(
        password: bytes,
        salt: bytes,
        params: KDFParams
    ) -> bytes:
        """Derive key using Argon2id - memory-hard, GPU/ASIC resistant."""
        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_cost,
            parallelism=params.parallelism,
            hash_len=params.key_length,
            type=Type.ID
        )

    @staticmethod
    def derive_scrypt(
        password: bytes,
        salt: bytes,
        params: KDFParams
    ) -> bytes:
        """Derive key using scrypt."""
        kdf = Scrypt(
            salt=salt,
            length=params.key_length,
            n=params.n,
            r=params.r,
            p=params.p,
            backend=default_backend()
        )
        return kdf.derive(password)

    @staticmethod
    def derive_hkdf_expand(
        key_material: bytes,
        info: bytes,
        length: int,
        salt: bytes = None
    ) -> bytes:
        """HKDF expansion for key splitting."""
        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(key_material)

    @classmethod
    def derive_master_key(
        cls,
        password: str,
        salt: bytes,
        params: KDFParams
    ) -> bytes:
        """Derive master key from password using specified KDF strategy."""
        password_bytes = password.encode("utf-8")

        # Add pepper - application-specific secret mixed in
        pepper = b"FortressCrypt-v2-pepper-2024"
        peppered_password = hmac_module.new(
            pepper, password_bytes, hashlib.sha512
        ).digest()

        if params.kdf_type == KDFType.ARGON2ID:
            return cls.derive_argon2id(peppered_password, salt, params)

        elif params.kdf_type == KDFType.SCRYPT:
            return cls.derive_scrypt(peppered_password, salt, params)

        elif params.kdf_type == KDFType.ARGON2ID_THEN_HKDF:
            # Double derivation: Argon2id → HKDF
            intermediate = cls.derive_argon2id(peppered_password, salt, params)
            return cls.derive_hkdf_expand(
                intermediate,
                info=b"FortressCrypt-double-derivation",
                length=params.key_length,
                salt=salt
            )

        raise ValueError(f"Unknown KDF type: {params.kdf_type}")

    @classmethod
    def split_key_material(
        cls,
        master_key: bytes,
        salt: bytes
    ) -> dict:
        """
        Split master key into purpose-specific subkeys.
        
        Returns dict with:
        - 'aes_key': 32 bytes for AES-256-GCM
        - 'chacha_key': 32 bytes for ChaCha20-Poly1305
        - 'hmac_key': 32 bytes for HMAC authentication
        - 'header_key': 32 bytes for header HMAC
        - 'meta_key': 32 bytes for metadata encryption
        """
        keys = {}
        purposes = [
            ('aes_key', b"aes-256-gcm-encryption-key"),
            ('chacha_key', b"chacha20-poly1305-encryption-key"),
            ('hmac_key', b"hmac-authentication-key"),
            ('header_key', b"header-hmac-key"),
            ('meta_key', b"metadata-encryption-key"),
        ]

        for name, info in purposes:
            keys[name] = cls.derive_hkdf_expand(
                master_key, info=info, length=32, salt=salt
            )

        return keys


class KeyfileManager:
    """Manage optional keyfile-based authentication."""

    @staticmethod
    def generate_keyfile(path: str, size: int = 4096) -> None:
        """Generate a cryptographically random keyfile."""
        key_data = secrets.token_bytes(size)
        with open(path, 'wb') as f:
            f.write(key_data)

    @staticmethod
    def read_keyfile(path: str) -> bytes:
        """Read and hash a keyfile."""
        with open(path, 'rb') as f:
            data = f.read()
        # Hash the keyfile content to normalize length
        return hashlib.blake2b(data, digest_size=64).digest()

    @staticmethod
    def combine_password_keyfile(
        password: str,
        keyfile_hash: bytes
    ) -> str:
        """Combine password and keyfile into a single authentication factor."""
        password_hash = hashlib.blake2b(
            password.encode('utf-8'), digest_size=64
        ).digest()
        # XOR and hash combination
        combined = bytes(a ^ b for a, b in zip(password_hash, keyfile_hash))
        return hashlib.blake2b(combined, digest_size=64).hexdigest()


class SecurePasswordValidator:
    """Validate password strength before encryption."""

    @staticmethod
    def estimate_entropy(password: str) -> float:
        """Estimate password entropy in bits."""
        import math
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(not c.isalnum() for c in password):
            charset_size += 32

        if charset_size == 0:
            return 0

        entropy = len(password) * math.log2(charset_size)
        
        # Penalize repeated characters
        unique_ratio = len(set(password)) / len(password)
        entropy *= unique_ratio

        return entropy

    @classmethod
    def validate(cls, password: str, min_entropy: float = 60.0) -> Tuple[bool, str]:
        """Validate password meets minimum security requirements."""
        if len(password) < 12:
            return False, "Password must be at least 12 characters"

        entropy = cls.estimate_entropy(password)
        if entropy < min_entropy:
            return False, (
                f"Password entropy too low: {entropy:.1f} bits "
                f"(minimum {min_entropy:.1f} bits)"
            )

        return True, f"Password entropy: {entropy:.1f} bits - OK"
