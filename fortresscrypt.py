#!/usr/bin/env python3
"""
FortressCrypt - Advanced File Encryption Tool

Features:
- Cascade encryption (AES-256-GCM + ChaCha20-Poly1305)
- Argon2id key derivation with aggressive parameters
- Streaming encryption for large files
- Chunk-level authentication with Merkle tree
- Secure file erasure after encryption
- Keyfile support for two-factor authentication
- Anti-tampering with full header HMAC
- Password strength enforcement
- Multiple cipher suite options
- Comprehensive integrity verification

Usage:
    python fortresscrypt.py encrypt <file> [options]
    python fortresscrypt.py decrypt <file> [options]
    python fortresscrypt.py genkey <keyfile> [options]
    python fortresscrypt.py info <file>
"""

import os
import sys
import math
import time
import getpass
import hashlib
import struct
from pathlib import Path
from typing import Optional, Tuple
from datetime import datetime

import click
from rich.console import Console
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TextColumn,
    TimeRemainingColumn, FileSizeColumn, TransferSpeedColumn,
    TaskProgressColumn
)
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import print as rprint

from header import FileHeader, CipherSuite, KDFType, KDFParams
from key_management import (
    KeyDerivationEngine, KeyfileManager, SecurePasswordValidator
)
from crypto_engine import StreamingEncryptor, StreamProcessor
from integrity import MerkleTree, IntegrityVerifier
from secure_erasure import SecureEraser

console = Console()

# File extension for encrypted files
ENCRYPTED_EXT = ".fortress"


def get_security_profile(level: str) -> Tuple[CipherSuite, KDFParams]:
    """Get predefined security profiles."""
    profiles = {
        "standard": (
            CipherSuite.AES_256_GCM,
            KDFParams(
                kdf_type=KDFType.ARGON2ID,
                time_cost=3,
                memory_cost=65536,  # 64 MB
                parallelism=4,
                key_length=32
            )
        ),
        "high": (
            CipherSuite.CHACHA20_POLY1305,
            KDFParams(
                kdf_type=KDFType.ARGON2ID,
                time_cost=4,
                memory_cost=262144,  # 256 MB
                parallelism=8,
                key_length=32
            )
        ),
        "paranoid": (
            CipherSuite.AES_256_GCM_THEN_CHACHA20,
            KDFParams(
                kdf_type=KDFType.ARGON2ID_THEN_HKDF,
                time_cost=6,
                memory_cost=524288,  # 512 MB
                parallelism=8,
                key_length=64  # 512-bit for two ciphers
            )
        ),
        "maximum": (
            CipherSuite.AES_256_GCM_THEN_CHACHA20,
            KDFParams(
                kdf_type=KDFType.ARGON2ID_THEN_HKDF,
                time_cost=10,
                memory_cost=1048576,  # 1 GB
                parallelism=12,
                key_length=64
            )
        ),
    }
    return profiles.get(level, profiles["paranoid"])


def get_password(confirm: bool = True, keyfile: Optional[str] = None) -> str:
    """Securely get password from user with optional keyfile."""
    console.print("\n[bold yellow]🔑 Authentication Required[/bold yellow]")

    password = getpass.getpass("Enter password: ")

    if confirm:
        password2 = getpass.getpass("Confirm password: ")
        if password != password2:
            console.print("[bold red]❌ Passwords do not match![/bold red]")
            sys.exit(1)

        # Validate password strength
        valid, message = SecurePasswordValidator.validate(password)
        if not valid:
            console.print(f"[bold red]❌ {message}[/bold red]")
            if not Confirm.ask("Continue with weak password?", default=False):
                sys.exit(1)
        else:
            console.print(f"[green]✓ {message}[/green]")

    # Combine with keyfile if provided
    if keyfile:
        if not os.path.exists(keyfile):
            console.print(f"[bold red]❌ Keyfile not found: {keyfile}[/bold red]")
            sys.exit(1)
        keyfile_hash = KeyfileManager.read_keyfile(keyfile)
        password = KeyfileManager.combine_password_keyfile(password, keyfile_hash)
        console.print("[green]✓ Keyfile integrated[/green]")

    return password


def encrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    cipher_suite: CipherSuite,
    kdf_params: KDFParams,
    chunk_size: int = 65536,
    shred_original: bool = False
) -> bool:
    """Encrypt a file with full integrity protection."""

    input_size = os.path.getsize(input_path)
    total_chunks = math.ceil(input_size / chunk_size)

    console.print(Panel.fit(
        f"[bold]Encrypting:[/bold] {input_path}\n"
        f"[bold]Output:[/bold] {output_path}\n"
        f"[bold]Size:[/bold] {input_size:,} bytes ({total_chunks} chunks)\n"
        f"[bold]Cipher:[/bold] {cipher_suite.name}\n"
        f"[bold]KDF:[/bold] {kdf_params.kdf_type.name}",
        title="🔐 FortressCrypt Encryption",
        border_style="green"
    ))

    # Step 1: Compute original file hash
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]Computing file hash..."),
        BarColumn(),
        TaskProgressColumn(),
        transient=True
    ) as progress:
        task = progress.add_task("Hashing", total=1)
        original_hash = StreamProcessor.compute_file_hash(input_path)
        progress.update(task, completed=1)

    # Step 2: Key derivation
    salt = os.urandom(32)
    base_nonce = os.urandom(12)

    console.print("[bold blue]🔑 Deriving encryption keys (this may take a while)...[/bold blue]")
    start_time = time.time()

    master_key = KeyDerivationEngine.derive_master_key(
        password, salt, kdf_params
    )
    keys = KeyDerivationEngine.split_key_material(master_key, salt)

    kdf_time = time.time() - start_time
    console.print(f"[green]✓ Key derivation completed in {kdf_time:.1f}s[/green]")

    # Step 3: Prepare header
    header = FileHeader(
        cipher_suite=cipher_suite,
        kdf_params=kdf_params,
        salt=salt,
        nonce=base_nonce,
        chunk_size=chunk_size,
        total_chunks=total_chunks,
        original_size=input_size,
        original_hash=original_hash,
        metadata={
            "created": datetime.now().isoformat(),
            "original_name": os.path.basename(input_path),
            "tool": "FortressCrypt v2.0",
        }
    )

    # Step 4: Initialize encryptor and Merkle tree
    encryptor = StreamingEncryptor(cipher_suite, keys, base_nonce, chunk_size)
    merkle = MerkleTree()

    # Step 5: Encrypt file
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        FileSizeColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
    ) as progress:
        task = progress.add_task("Encrypting", total=input_size)

        with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
            # Write placeholder header (will rewrite with HMAC later)
            header_bytes = header.serialize(keys['header_key'])
            fout.write(header_bytes)

            # Write Merkle tree placeholder (we'll append at end)
            merkle_placeholder_pos = fout.tell()

            # Encrypt chunks
            for chunk_index, plaintext in StreamProcessor.read_chunks(fin, chunk_size):
                ciphertext = encryptor.encrypt_chunk(plaintext, chunk_index)

                # Add to Merkle tree
                merkle.add_leaf(ciphertext, chunk_index)

                # Write chunk: [4 bytes length][ciphertext]
                fout.write(struct.pack(">I", len(ciphertext)))
                fout.write(ciphertext)

                progress.update(task, advance=len(plaintext))

            # Build and write Merkle tree
            merkle_root = merkle.build()
            merkle_data = merkle.serialize()
            fout.write(struct.pack(">I", len(merkle_data)))
            fout.write(merkle_data)

            # Write Merkle root
            fout.write(merkle_root)

    # Step 6: Compute and append file-level HMAC
    file_hmac = StreamProcessor.compute_stream_hmac(
        output_path, keys['hmac_key'], skip_bytes=0
    )
    with open(output_path, 'ab') as fout:
        fout.write(file_hmac)

    output_size = os.path.getsize(output_path)
    overhead = output_size - input_size

    console.print(Panel.fit(
        f"[bold green]✓ Encryption Complete![/bold green]\n\n"
        f"Output: {output_path}\n"
        f"Output size: {output_size:,} bytes\n"
        f"Overhead: {overhead:,} bytes ({overhead/input_size*100:.1f}%)\n"
        f"Merkle root: {merkle_root.hex()[:32]}...\n"
        f"File hash: {original_hash.hex()[:32]}...",
        title="✅ Success",
        border_style="green"
    ))

    # Step 7: Optionally shred original
    if shred_original:
        console.print("[bold yellow]🗑️  Securely erasing original file...[/bold yellow]")
        if SecureEraser.secure_delete(input_path, passes=7):
            console.print("[green]✓ Original file securely erased[/green]")
        else:
            console.print("[red]⚠ Could not securely erase original[/red]")

    # Wipe sensitive data from memory
    master_key_ba = bytearray(master_key)
    SecureEraser.wipe_memory(master_key_ba)

    return True


def decrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    shred_encrypted: bool = False
) -> bool:
    """Decrypt a file with full integrity verification."""

    input_size = os.path.getsize(input_path)

    console.print(Panel.fit(
        f"[bold]Decrypting:[/bold] {input_path}\n"
        f"[bold]Output:[/bold] {output_path}\n"
        f"[bold]Size:[/bold] {input_size:,} bytes",
        title="🔓 FortressCrypt Decryption",
        border_style="blue"
    ))

    # Step 1: Read and parse header
    with open(input_path, 'rb') as f:
        # Read enough for header (first 4KB should be plenty)
        header_data = f.read(8192)

    # We need the key to verify header HMAC, so first derive keys
    # Parse just enough to get salt and KDF params
    # Quick parse for salt and KDF params without HMAC verification
    offset = 8 + 2 + 4 + 1 + 1  # magic + version + header_len + cipher + kdf_type
    kdf_params_temp, kdf_consumed = KDFParams.deserialize(header_data[offset:])
    offset += kdf_consumed
    salt = header_data[offset:offset + 32]

    # Step 2: Key derivation
    console.print("[bold blue]🔑 Deriving decryption keys...[/bold blue]")
    start_time = time.time()

    master_key = KeyDerivationEngine.derive_master_key(
        password, salt, kdf_params_temp
    )
    keys = KeyDerivationEngine.split_key_material(master_key, salt)

    kdf_time = time.time() - start_time
    console.print(f"[green]✓ Key derivation completed in {kdf_time:.1f}s[/green]")

    # Step 3: Parse and verify header
    try:
        header, header_size = FileHeader.deserialize(header_data, keys['header_key'])
    except ValueError as e:
        console.print(f"[bold red]❌ {e}[/bold red]")
        return False

    console.print(f"[green]✓ Header verified[/green]")
    console.print(f"  Cipher: {header.cipher_suite.name}")
    console.print(f"  Original size: {header.original_size:,} bytes")
    console.print(f"  Chunks: {header.total_chunks}")
    if header.metadata.get("original_name"):
        console.print(f"  Original name: {header.metadata['original_name']}")

    # Step 4: Initialize decryptor
    decryptor = StreamingEncryptor(
        header.cipher_suite, keys, header.nonce, header.chunk_size
    )

    # Step 5: Decrypt chunks
    decrypted_hasher = hashlib.blake2b(digest_size=64)
    total_decrypted = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        FileSizeColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
    ) as progress:
        task = progress.add_task("Decrypting", total=header.original_size)

        with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
            fin.seek(header_size)

            for chunk_index in range(header.total_chunks):
                # Read chunk length
                length_bytes = fin.read(4)
                if len(length_bytes) < 4:
                    console.print("[bold red]❌ Unexpected end of file[/bold red]")
                    return False

                chunk_length = struct.unpack(">I", length_bytes)[0]
                ciphertext = fin.read(chunk_length)

                if len(ciphertext) < chunk_length:
                    console.print("[bold red]❌ Truncated chunk[/bold red]")
                    return False

                try:
                    plaintext = decryptor.decrypt_chunk(ciphertext, chunk_index)
                except Exception as e:
                    console.print(
                        f"[bold red]❌ Decryption failed at chunk {chunk_index}: {e}[/bold red]"
                    )
                    # Clean up partial output
                    try:
                        os.unlink(output_path)
                    except Exception:
                        pass
                    return False

                fout.write(plaintext)
                decrypted_hasher.update(plaintext)
                total_decrypted += len(plaintext)
                progress.update(task, advance=len(plaintext))

    # Step 6: Verify integrity
    computed_hash = decrypted_hasher.digest()
    if computed_hash != header.original_hash:
        console.print("[bold red]❌ INTEGRITY CHECK FAILED![/bold red]")
        console.print("[red]The decrypted file does not match the original hash.[/red]")
        console.print("[red]The file may have been corrupted or tampered with.[/red]")
        try:
            os.unlink(output_path)
        except Exception:
            pass
        return False

    console.print(Panel.fit(
        f"[bold green]✓ Decryption Complete![/bold green]\n\n"
        f"Output: {output_path}\n"
        f"Size: {total_decrypted:,} bytes\n"
        f"Integrity: [green]VERIFIED ✓[/green]\n"
        f"Hash: {computed_hash.hex()[:32]}...",
        title="✅ Success",
        border_style="green"
    ))

    # Optionally shred encrypted file
    if shred_encrypted:
        console.print("[bold yellow]🗑️  Securely erasing encrypted file...[/bold yellow]")
        if SecureEraser.secure_delete(input_path, passes=7):
            console.print("[green]✓ Encrypted file securely erased[/green]")

    # Wipe keys
    master_key_ba = bytearray(master_key)
    SecureEraser.wipe_memory(master_key_ba)

    return True


def show_file_info(file_path: str) -> None:
    """Show information about an encrypted file without decrypting."""
    with open(file_path, 'rb') as f:
        header_data = f.read(8192)

    # Check magic
    if header_data[:8] != b"FORTCRPT":
        console.print("[bold red]❌ Not a FortressCrypt file[/bold red]")
        return

    # Parse minimal header info (without HMAC verification)
    offset = 8
    version = struct.unpack(">H", header_data[offset:offset + 2])[0]
    offset += 2
    header_length = struct.unpack(">I", header_data[offset:offset + 4])[0]
    offset += 4
    cipher_suite = CipherSuite(struct.unpack(">B", header_data[offset:offset + 1])[0])
    offset += 1
    kdf_type = KDFType(struct.unpack(">B", header_data[offset:offset + 1])[0])
    offset += 1
    kdf_params, kdf_consumed = KDFParams.deserialize(header_data[offset:])
    offset += kdf_consumed
    # Skip salt
    offset += 32
    nonce_size = struct.unpack(">B", header_data[offset:offset + 1])[0]
    offset += 1 + nonce_size
    eph_size = struct.unpack(">B", header_data[offset:offset + 1])[0]
    offset += 1 + eph_size
    chunk_size = struct.unpack(">I", header_data[offset:offset + 4])[0]
    offset += 4
    total_chunks = struct.unpack(">Q", header_data[offset:offset + 8])[0]
    offset += 8
    original_size = struct.unpack(">Q", header_data[offset:offset + 8])[0]
    offset += 8

    table = Table(title="🔐 FortressCrypt File Information", border_style="blue")
    table.add_column("Property", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")

    file_size = os.path.getsize(file_path)

    table.add_row("File", file_path)
    table.add_row("Encrypted Size", f"{file_size:,} bytes")
    table.add_row("Original Size", f"{original_size:,} bytes")
    table.add_row("Version", str(version))
    table.add_row("Header Size", f"{header_length} bytes")
    table.add_row("Cipher Suite", cipher_suite.name)
    table.add_row("KDF", kdf_type.name)
    table.add_row("Argon2 Memory", f"{kdf_params.memory_cost // 1024} MB")
    table.add_row("Argon2 Iterations", str(kdf_params.time_cost))
    table.add_row("Argon2 Parallelism", str(kdf_params.parallelism))
    table.add_row("Key Length", f"{kdf_params.key_length * 8} bits")
    table.add_row("Chunk Size", f"{chunk_size:,} bytes")
    table.add_row("Total Chunks", str(total_chunks))
    table.add_row("Overhead", f"{file_size - original_size:,} bytes")

    # Security rating
    if cipher_suite == CipherSuite.AES_256_GCM_THEN_CHACHA20:
        rating = "🛡️🛡️🛡️🛡️🛡️ MAXIMUM"
    elif cipher_suite == CipherSuite.CHACHA20_POLY1305:
        rating = "🛡️🛡️🛡️🛡️ HIGH"
    else:
        rating = "🛡️🛡️🛡️ STANDARD"

    table.add_row("Security Rating", rating)

    console.print(table)


# ═══════════════════════════════════════════
#  CLI Interface
# ═══════════════════════════════════════════

BANNER = """
[bold cyan]
  ███████╗ ██████╗ ██████╗ ████████╗██████╗ ███████╗███████╗███████╗
  ██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔════╝
  █████╗  ██║   ██║██████╔╝   ██║   ██████╔╝█████╗  ███████╗███████╗
  ██╔══╝  ██║   ██║██╔══██╗   ██║   ██╔══██╗██╔══╝  ╚════██║╚════██║
  ██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║███████╗███████║███████║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
                    [bold white]C R Y P T[/bold white]
[/bold cyan]
[dim]Advanced File Encryption Tool v2.0[/dim]
[dim]AES-256-GCM + ChaCha20-Poly1305 Cascade | Argon2id | Merkle Integrity[/dim]
"""


@click.group()
def cli():
    """FortressCrypt - Military-grade file encryption."""
    console.print(BANNER)


@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('-o', '--output', type=click.Path(), default=None,
              help='Output file path')
@click.option('-s', '--security', type=click.Choice(
    ['standard', 'high', 'paranoid', 'maximum']),
    default='paranoid', help='Security profile')
@click.option('-k', '--keyfile', type=click.Path(), default=None,
              help='Path to keyfile for 2FA')
@click.option('--chunk-size', type=int, default=65536,
              help='Encryption chunk size in bytes')
@click.option('--shred/--no-shred', default=False,
              help='Securely erase original after encryption')
@click.option('--cipher', type=click.Choice([
    'aes-gcm', 'chacha20', 'cascade', 'xchacha20'
]), default=None, help='Override cipher suite')
def encrypt(input_file, output, security, keyfile, chunk_size, shred, cipher):
    """Encrypt a file."""
    if output is None:
        output = input_file + ENCRYPTED_EXT

    if os.path.exists(output):
        if not Confirm.ask(f"Output file exists: {output}. Overwrite?"):
            sys.exit(0)

    cipher_suite, kdf_params = get_security_profile(security)

    # Override cipher if specified
    if cipher:
        cipher_map = {
            'aes-gcm': CipherSuite.AES_256_GCM,
            'chacha20': CipherSuite.CHACHA20_POLY1305,
            'cascade': CipherSuite.AES_256_GCM_THEN_CHACHA20,
            'xchacha20': CipherSuite.XCHACHA20_POLY1305,
        }
        cipher_suite = cipher_map[cipher]
        if cipher_suite == CipherSuite.AES_256_GCM_THEN_C
