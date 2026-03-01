# 🔐 FortressCrypt - Advanced File Encryption Tool

## Security Features

| Feature | Description |
|---------|-------------|
| **Cascade Encryption** | AES-256-GCM → ChaCha20-Poly1305 (dual-layer) |
| **Argon2id KDF** | Memory-hard key derivation (up to 1GB RAM, 10 iterations) |
| **Double Derivation** | Argon2id → HKDF-SHA512 chain |
| **Per-Chunk Nonces** | BLAKE2b-derived unique nonces prevent reuse |
| **Merkle Tree** | Chunk-level integrity with tamper detection |
| **Header HMAC** | Authenticated header prevents metadata tampering |
| **BLAKE2b Hashing** | 512-bit file integrity verification |
| **Secure Erasure** | 7-pass overwrite + rename + delete |
| **Keyfile Support** | Two-factor authentication |
| **Password Validation** | Entropy-based strength checking |
| **Memory Wiping** | Sensitive data cleared after use |

## Installation

```bash
pip install -r requirements.txt
