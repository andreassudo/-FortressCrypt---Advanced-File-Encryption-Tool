"""
FortressCrypt Encrypted File Header Format

Layout (binary):
┌─────────────────────────────────────────────────────┐
│ Magic Bytes (8)        : FORTCRYPT                   │
│ Version (2)            : uint16                      │
│ Header Length (4)      : uint32                      │
│ Cipher Suite (1)       : enum byte                   │
│ KDF ID (1)             : enum byte                   │
│ KDF Params (variable)  : serialized                  │
│ Salt (32)              : bytes                        │
│ Nonce/IV (variable)    : bytes                        │
│ Ephemeral PubKey (32)  : bytes (optional, for ECDH)  │
│ Chunk Size (4)         : uint32                      │
│ Total Chunks (8)       : uint64                      │
│ Original Size (8)      : uint64                      │
│ Original Hash (64)     : BLAKE2b of plaintext        │
│ Metadata (variable)    : encrypted JSON              │
│ Header HMAC (32)       : HMAC-SHA256 of header       │
└─────────────────────────────────────────────────────┘
"""

import struct
import json
import os
import hashlib
import hmac as hmac_module
from enum import IntEnum
from dataclasses import dataclass, field
from typing import Optional


MAGIC = b"FORTCRPT"
VERSION = 2


class CipherSuite(IntEnum):
    AES_256_GCM = 0x01
    CHACHA20_POLY1305 = 0x02
    AES_256_GCM_THEN_CHACHA20 = 0x03  # Cascade encryption
    XCHACHA20_POLY1305 = 0x04


class KDFType(IntEnum):
    ARGON2ID = 0x01
    SCRYPT = 0x02
    ARGON2ID_THEN_HKDF = 0x03  # Double derivation


@dataclass
class KDFParams:
    kdf_type: KDFType = KDFType.ARGON2ID
    # Argon2 params
    time_cost: int = 4
    memory_cost: int = 262144  # 256 MB
    parallelism: int = 8
    # Scrypt params
    n: int = 2**20
    r: int = 8
    p: int = 1
    # Key length
    key_length: int = 64  # 512-bit for cascade

    def serialize(self) -> bytes:
        data = json.dumps({
            "kdf_type": int(self.kdf_type),
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
            "n": self.n,
            "r": self.r,
            "p": self.p,
            "key_length": self.key_length
        }).encode()
        return struct.pack(">H", len(data)) + data

    @classmethod
    def deserialize(cls, data: bytes) -> tuple['KDFParams', int]:
        length = struct.unpack(">H", data[:2])[0]
        params_dict = json.loads(data[2:2 + length].decode())
        params = cls(
            kdf_type=KDFType(params_dict["kdf_type"]),
            time_cost=params_dict["time_cost"],
            memory_cost=params_dict["memory_cost"],
            parallelism=params_dict["parallelism"],
            n=params_dict["n"],
            r=params_dict["r"],
            p=params_dict["p"],
            key_length=params_dict["key_length"]
        )
        return params, 2 + length


@dataclass
class FileHeader:
    cipher_suite: CipherSuite = CipherSuite.AES_256_GCM_THEN_CHACHA20
    kdf_params: KDFParams = field(default_factory=KDFParams)
    salt: bytes = field(default_factory=lambda: os.urandom(32))
    nonce: bytes = field(default_factory=lambda: os.urandom(12))
    ephemeral_pubkey: bytes = b""
    chunk_size: int = 65536  # 64KB chunks
    total_chunks: int = 0
    original_size: int = 0
    original_hash: bytes = b"\x00" * 64
    metadata: dict = field(default_factory=dict)
    header_hmac: bytes = b"\x00" * 32

    def serialize(self, hmac_key: bytes) -> bytes:
        """Serialize header to bytes with HMAC authentication."""
        kdf_bytes = self.kdf_params.serialize()

        # Determine nonce size based on cipher
        nonce_size = len(self.nonce)
        ephemeral_size = len(self.ephemeral_pubkey)

        # Metadata encryption placeholder (encrypted separately)
        meta_json = json.dumps(self.metadata).encode()
        meta_length = len(meta_json)

        # Build header body
        body = bytearray()
        body += MAGIC
        body += struct.pack(">H", VERSION)
        # Placeholder for header length (will fill in)
        header_len_pos = len(body)
        body += struct.pack(">I", 0)

        body += struct.pack(">B", int(self.cipher_suite))
        body += struct.pack(">B", int(self.kdf_params.kdf_type))
        body += kdf_bytes
        body += self.salt

        body += struct.pack(">B", nonce_size)
        body += self.nonce

        body += struct.pack(">B", ephemeral_size)
        if ephemeral_size > 0:
            body += self.ephemeral_pubkey

        body += struct.pack(">I", self.chunk_size)
        body += struct.pack(">Q", self.total_chunks)
        body += struct.pack(">Q", self.original_size)
        body += self.original_hash

        body += struct.pack(">I", meta_length)
        body += meta_json

        # Calculate total header length (body + 32 bytes HMAC)
        total_len = len(body) + 32
        struct.pack_into(">I", body, header_len_pos - len(MAGIC) - 2 + len(MAGIC) + 2, total_len)
        # Fix: recalculate position
        struct.pack_into(">I", body, 10, total_len)

        # Compute HMAC
        h = hmac_module.new(hmac_key, bytes(body), hashlib.sha256)
        self.header_hmac = h.digest()

        return bytes(body) + self.header_hmac

    @classmethod
    def deserialize(cls, data: bytes, hmac_key: bytes) -> tuple['FileHeader', int]:
        """Deserialize header and verify HMAC."""
        offset = 0

        magic = data[offset:offset + 8]
        if magic != MAGIC:
            raise ValueError("Invalid file format: bad magic bytes")
        offset += 8

        version = struct.unpack(">H", data[offset:offset + 2])[0]
        if version > VERSION:
            raise ValueError(f"Unsupported version: {version}")
        offset += 2

        header_length = struct.unpack(">I", data[offset:offset + 4])[0]
        offset += 4

        cipher_suite = CipherSuite(struct.unpack(">B", data[offset:offset + 1])[0])
        offset += 1

        kdf_type_byte = struct.unpack(">B", data[offset:offset + 1])[0]
        offset += 1

        kdf_params, kdf_consumed = KDFParams.deserialize(data[offset:])
        offset += kdf_consumed

        salt = data[offset:offset + 32]
        offset += 32

        nonce_size = struct.unpack(">B", data[offset:offset + 1])[0]
        offset += 1
        nonce = data[offset:offset + nonce_size]
        offset += nonce_size

        ephemeral_size = struct.unpack(">B", data[offset:offset + 1])[0]
        offset += 1
        ephemeral_pubkey = b""
        if ephemeral_size > 0:
            ephemeral_pubkey = data[offset:offset + ephemeral_size]
            offset += ephemeral_size

        chunk_size = struct.unpack(">I", data[offset:offset + 4])[0]
        offset += 4

        total_chunks = struct.unpack(">Q", data[offset:offset + 8])[0]
        offset += 8

        original_size = struct.unpack(">Q", data[offset:offset + 8])[0]
        offset += 8

        original_hash = data[offset:offset + 64]
        offset += 64

        meta_length = struct.unpack(">I", data[offset:offset + 4])[0]
        offset += 4
        metadata = json.loads(data[offset:offset + meta_length].decode())
        offset += meta_length

        # Verify HMAC
        header_body = data[:offset]
        stored_hmac = data[offset:offset + 32]

        h = hmac_module.new(hmac_key, header_body, hashlib.sha256)
        computed_hmac = h.digest()

        if not hmac_module.compare_digest(stored_hmac, computed_hmac):
            raise ValueError("Header HMAC verification failed - tampered or wrong password")

        offset += 32

        header = cls(
            cipher_suite=cipher_suite,
            kdf_params=kdf_params,
            salt=salt,
            nonce=nonce,
            ephemeral_pubkey=ephemeral_pubkey,
            chunk_size=chunk_size,
            total_chunks=total_chunks,
            original_size=original_size,
            original_hash=original_hash,
            metadata=metadata,
            header_hmac=stored_hmac
        )

        return header, offset
