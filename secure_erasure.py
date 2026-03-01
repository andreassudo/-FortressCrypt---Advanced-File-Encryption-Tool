"""
Secure File Erasure Module

Features:
- Multi-pass overwrite (Gutmann-inspired)
- Filename obfuscation before deletion
- Memory wiping for sensitive data
- Cross-platform support
"""

import os
import sys
import ctypes
import secrets
import string
from pathlib import Path
from typing import Optional


class SecureEraser:
    """Securely erase files beyond recovery."""

    # Overwrite patterns (subset of Gutmann method + random)
    PATTERNS = [
        None,         # Random
        b"\x00",      # Zeros
        b"\xFF",      # Ones
        None,         # Random
        b"\x55",      # 01010101
        b"\xAA",      # 10101010
        None,         # Random
    ]

    @classmethod
    def secure_delete(
        cls,
        file_path: str,
        passes: int = 7,
        verify: bool = True
    ) -> bool:
        """
        Securely delete a file with multiple overwrite passes.
        
        1. Overwrite content with patterns
        2. Truncate to zero
        3. Rename with random name
        4. Delete
        """
        path = Path(file_path)
        if not path.exists():
            return False

        file_size = path.stat().st_size

        try:
            # Phase 1: Overwrite
            with open(file_path, 'r+b') as f:
                for pass_num in range(passes):
                    pattern_idx = pass_num % len(cls.PATTERNS)
                    pattern = cls.PATTERNS[pattern_idx]

                    f.seek(0)
                    remaining = file_size

                    while remaining > 0:
                        chunk_size = min(65536, remaining)
                        if pattern is None:
                            data = secrets.token_bytes(chunk_size)
                        else:
                            data = pattern * chunk_size
                        f.write(data[:chunk_size])
                        remaining -= chunk_size

                    f.flush()
                    os.fsync(f.fileno())

                # Phase 2: Truncate
                f.seek(0)
                f.truncate(0)
                f.flush()
                os.fsync(f.fileno())

            # Phase 3: Rename to random name before deletion
            random_name = ''.join(
                secrets.choice(string.ascii_lowercase) for _ in range(16)
            )
            random_path = path.parent / random_name
            path.rename(random_path)

            # Phase 4: Delete
            random_path.unlink()

            return True

        except (PermissionError, OSError) as e:
            # Fallback: simple deletion
            try:
                path.unlink()
            except Exception:
                pass
            return False

    @staticmethod
    def wipe_memory(data: bytearray) -> None:
        """
        Attempt to securely wipe a bytearray from memory.
        Note: Python's GC makes this imperfect, but it's better than nothing.
        """
        if not isinstance(data, (bytearray, memoryview)):
            return

        for i in range(len(data)):
            data[i] = 0

        # Try using ctypes for more thorough wiping
        try:
            ctypes.memset(
                ctypes.addressof(
                    (ctypes.c_char * len(data)).from_buffer(data)
                ),
                0,
                len(data)
            )
        except Exception:
            pass

    @staticmethod
    def secure_temp_file(suffix: str = ".tmp") -> str:
        """Create a secure temporary file path."""
        import tempfile
        fd, path = tempfile.mkstemp(suffix=suffix, prefix="fc_")
        os.close(fd)
        return path
