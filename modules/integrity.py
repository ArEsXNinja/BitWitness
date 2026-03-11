#!/usr/bin/env python3
"""
integrity.py — Multi-algorithm file hashing and comparison.
Supports MD5, SHA-1, SHA-256, SHA-512, and ssdeep fuzzy hashing.
"""

import hashlib
import os

# Optional: ssdeep for fuzzy hashing
try:
    import ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False


def get_file_hash(file_path, algorithm="sha256"):
    """
    Compute a single hash of a file.

    Args:
        file_path: Path to file
        algorithm: One of 'md5', 'sha1', 'sha256', 'sha512'

    Returns:
        Hex digest string, or error string.
    """
    try:
        h = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                h.update(block)
        return h.hexdigest()
    except FileNotFoundError:
        return "File not found."
    except Exception as e:
        return f"Error: {e}"


def get_all_hashes(file_path):
    """
    Compute MD5, SHA-1, SHA-256, and SHA-512 hashes of a file.

    Returns:
        dict with keys: md5, sha1, sha256, sha512
        Each value is the hex digest string.
    """
    algorithms = {
        "md5":    hashlib.md5(),
        "sha1":   hashlib.sha1(),
        "sha256": hashlib.sha256(),
        "sha512": hashlib.sha512(),
    }

    try:
        with open(file_path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                for h in algorithms.values():
                    h.update(block)
    except FileNotFoundError:
        return {"error": "File not found."}
    except Exception as e:
        return {"error": f"Cannot read file: {e}"}

    result = {}
    for name, h in algorithms.items():
        result[name] = h.hexdigest()

    return result


def get_fuzzy_hash(file_path):
    """
    Compute ssdeep fuzzy hash of a file.

    Returns:
        Fuzzy hash string, or None if ssdeep is not available.
    """
    if not SSDEEP_AVAILABLE:
        return None

    try:
        return ssdeep.hash_from_file(file_path)
    except Exception:
        return None


def compare_hashes(file1, file2):
    """
    Compare hashes of two files side-by-side.

    Returns:
        dict with keys: file1_hashes, file2_hashes, match (bool),
                        fuzzy_similarity (int 0-100 if ssdeep available)
    """
    h1 = get_all_hashes(file1)
    h2 = get_all_hashes(file2)

    if "error" in h1 or "error" in h2:
        return {
            "error": h1.get("error") or h2.get("error"),
            "file1_hashes": h1,
            "file2_hashes": h2,
        }

    exact_match = h1["sha256"] == h2["sha256"]

    result = {
        "file1_hashes": h1,
        "file2_hashes": h2,
        "match": exact_match,
    }

    # Fuzzy comparison
    if SSDEEP_AVAILABLE:
        fh1 = get_fuzzy_hash(file1)
        fh2 = get_fuzzy_hash(file2)
        if fh1 and fh2:
            try:
                result["fuzzy_hash1"] = fh1
                result["fuzzy_hash2"] = fh2
                result["fuzzy_similarity"] = ssdeep.compare(fh1, fh2)
            except Exception:
                pass

    return result