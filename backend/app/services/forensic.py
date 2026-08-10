import hashlib
from pathlib import Path
from typing import Tuple


def compute_sha256(file_path: Path) -> str:
    """Return SHA-256 hex digest of file."""
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_sha256(file_path: Path, expected_hash: str) -> bool:
    """Return True if file's SHA-256 matches expected_hash (case-insensitive)."""
    return compute_sha256(file_path).lower() == expected_hash.lower()


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()