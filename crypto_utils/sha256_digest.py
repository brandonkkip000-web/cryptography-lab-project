from __future__ import annotations

import hashlib


def compute_sha256(file_path: str, *, chunk_size: int = 1024 * 1024) -> str:
    """Compute the SHA-256 hex digest of a file by streaming in chunks.

    Parameters
    ----------
    file_path: str
        Path to the file to hash.
    chunk_size: int
        Read size in bytes per iteration. Defaults to 1 MiB.
    """

    digest = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


