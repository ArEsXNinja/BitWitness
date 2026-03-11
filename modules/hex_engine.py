#!/usr/bin/env python3
"""
hex_engine.py — File signature analysis, hex dump viewer, and entropy calculator.
Supports 50+ file signatures for forensic identification.
"""

import binascii
import math
import os


# ══════════════════════════════════════════════════════════════
#  FILE SIGNATURES DATABASE  (50+ formats)
# ══════════════════════════════════════════════════════════════

SIGNATURES = {
    # ── Images ──
    "JPG":      "FFD8FF",
    "PNG":      "89504E47",
    "GIF87a":   "474946383761",
    "GIF89a":   "474946383961",
    "BMP":      "424D",
    "TIFF-LE":  "49492A00",
    "TIFF-BE":  "4D4D002A",
    "WEBP":     "52494646",       # RIFF....WEBP (first 4 bytes)
    "ICO":      "00000100",
    "PSD":      "38425053",

    # ── Documents ──
    "PDF":      "25504446",
    "RTF":      "7B5C727466",
    "DOCX/XLSX/PPTX": "504B0304",  # ZIP-based Office
    "DOC/XLS":  "D0CF11E0A1B11AE1",  # OLE2 compound
    "XML":      "3C3F786D6C",

    # ── Executables ──
    "EXE/DLL":  "4D5A",           # MZ header
    "ELF":      "7F454C46",
    "Mach-O32": "FEEDFACE",
    "Mach-O64": "FEEDFACF",
    "DEX":      "6465780A",       # Android Dalvik
    "JavaClass":"CAFEBABE",

    # ── Archives ──
    "ZIP":      "504B0304",
    "RAR4":     "526172211A0700",
    "RAR5":     "526172211A070100",
    "7Z":       "377ABCAF271C",
    "GZIP":     "1F8B08",
    "BZIP2":    "425A68",
    "XZ":       "FD377A585A00",
    "TAR":      "7573746172",     # at offset 257
    "ZSTD":     "28B52FFD",
    "LZ4":      "04224D18",
    "CAB":      "4D534346",       # Microsoft Cabinet

    # ── Audio ──
    "MP3-ID3":  "494433",
    "MP3-SYNC": "FFFB",
    "WAV":      "52494646",       # RIFF
    "FLAC":     "664C6143",
    "OGG":      "4F676753",
    "MIDI":     "4D546864",

    # ── Video ──
    "AVI":      "52494646",       # RIFF....AVI
    "MP4/M4A":  "00000018",       # ftyp box (approximate)
    "MKV":      "1A45DFA3",       # EBML/Matroska
    "FLV":      "464C5601",
    "WMV/ASF":  "3026B2758E66CF11",

    # ── Database / Data ──
    "SQLite":   "53514C69746520666F726D6174",
    "PCAP":     "D4C3B2A1",
    "PCAPNG":   "0A0D0D0A",

    # ── Disk / Forensic ──
    "ISO9660":  "4344303031",     # at offset 32769
    "VMDK":     "4B444D56",
    "VHD":      "636F6E6563746978",
    "LUKS":     "4C554B53",       # Linux encrypted

    # ── Other ──
    "WASM":     "0061736D",
    "LNK":      "4C00000001140200",  # Windows shortcut
    "REG":      "52454745444954",     # Windows Registry
    "SWF":      "465753",            # Flash
    "SWF-CMP":  "435753",            # Compressed Flash
}

# Reverse lookup: signature hex → list of format names
# Handle duplicates (e.g. ZIP and DOCX share PK header)
_SIG_BY_HEX = {}
for _name, _hex in SIGNATURES.items():
    _SIG_BY_HEX.setdefault(_hex, []).append(_name)


# ══════════════════════════════════════════════════════════════
#  HEADER / SIGNATURE CHECKING
# ══════════════════════════════════════════════════════════════

def check_header(file_path):
    """
    Read the first bytes and identify the file type by magic number.
    Returns a string describing the match or 'UNKNOWN'.
    """
    try:
        with open(file_path, 'rb') as f:
            header = f.read(32)
    except Exception as e:
        return f"ERROR: Cannot read file — {e}"

    hex_val = binascii.hexlify(header).upper().decode()

    # Check longest signatures first for best match
    sorted_sigs = sorted(SIGNATURES.items(), key=lambda x: len(x[1]), reverse=True)

    for name, sig in sorted_sigs:
        if hex_val.startswith(sig.upper()):
            return f"Valid {name} file."

    return f"UNKNOWN/CORRUPT Header: {hex_val[:16]}"


def identify_file_type(file_path):
    """
    Identify file type(s) from magic bytes.
    Returns a list of dicts: [{"type": "...", "signature": "...", "confidence": "HIGH/MEDIUM"}]
    """
    try:
        with open(file_path, 'rb') as f:
            header = f.read(32)
    except Exception as e:
        return [{"type": "ERROR", "signature": "", "confidence": "NONE", "detail": str(e)}]

    hex_val = binascii.hexlify(header).upper().decode()
    matches = []

    sorted_sigs = sorted(SIGNATURES.items(), key=lambda x: len(x[1]), reverse=True)

    for name, sig in sorted_sigs:
        if hex_val.startswith(sig.upper()):
            confidence = "HIGH" if len(sig) >= 8 else "MEDIUM"
            matches.append({
                "type": name,
                "signature": sig,
                "confidence": confidence,
            })

    if not matches:
        matches.append({
            "type": "UNKNOWN",
            "signature": hex_val[:16],
            "confidence": "NONE",
        })

    return matches


# ══════════════════════════════════════════════════════════════
#  HEX DUMP VIEWER
# ══════════════════════════════════════════════════════════════

def hex_dump(file_path, offset=0, length=256, width=16):
    """
    Generate a formatted hex dump of a file region (like xxd).

    Args:
        file_path: Path to file
        offset:    Starting byte offset
        length:    Number of bytes to dump
        width:     Bytes per line (default 16)

    Returns:
        List of dicts with keys: offset, hex, ascii
    """
    lines = []
    try:
        with open(file_path, 'rb') as f:
            f.seek(offset)
            data = f.read(length)
    except Exception as e:
        return [{"offset": "ERROR", "hex": str(e), "ascii": ""}]

    for i in range(0, len(data), width):
        chunk = data[i:i + width]

        # Hex portion
        hex_parts = []
        for j in range(width):
            if j < len(chunk):
                hex_parts.append(f"{chunk[j]:02X}")
            else:
                hex_parts.append("  ")
            # Add extra space every 8 bytes for readability
            if j == 7:
                hex_parts.append("")

        hex_str = " ".join(hex_parts)

        # ASCII portion
        ascii_chars = []
        for b in chunk:
            if 0x20 <= b <= 0x7E:
                ascii_chars.append(chr(b))
            else:
                ascii_chars.append(".")

        ascii_str = "".join(ascii_chars)

        lines.append({
            "offset": f"{offset + i:08X}",
            "hex": hex_str,
            "ascii": ascii_str,
        })

    return lines


def hex_dump_string(file_path, offset=0, length=256, width=16):
    """Return hex dump as a formatted multi-line string."""
    lines = hex_dump(file_path, offset, length, width)
    output = []
    for line in lines:
        output.append(f"  {line['offset']}  │ {line['hex']}  │ {line['ascii']}")
    return "\n".join(output)


# ══════════════════════════════════════════════════════════════
#  ENTROPY CALCULATOR
# ══════════════════════════════════════════════════════════════

def get_file_entropy(file_path, block_size=None):
    """
    Compute Shannon entropy of a file.

    Args:
        file_path:  Path to file
        block_size: If None, compute entropy of entire file.
                    If set, compute per-block entropy and return list.

    Returns:
        float (overall entropy 0.0-8.0) or list of (offset, entropy) tuples.
    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except Exception as e:
        return -1.0

    if not data:
        return 0.0

    if block_size is None:
        return _shannon_entropy(data)
    else:
        results = []
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            ent = _shannon_entropy(block)
            results.append((i, ent))
        return results


def _shannon_entropy(data):
    """Calculate Shannon entropy of a byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0

    freq = [0] * 256
    for byte in data:
        freq[byte] += 1

    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return entropy


def get_entropy_verdict(entropy):
    """Return a human-readable verdict for an entropy value."""
    if entropy < 1.0:
        return "VERY LOW — likely empty/sparse data"
    elif entropy < 3.5:
        return "LOW — plaintext / structured data"
    elif entropy < 5.0:
        return "MODERATE — native code or mixed content"
    elif entropy < 6.5:
        return "ELEVATED — compiled binary or compressed regions"
    elif entropy < 7.0:
        return "HIGH — likely compressed data"
    elif entropy < 7.5:
        return "VERY HIGH — packed or compressed"
    else:
        return "CRITICAL — encrypted or heavily packed"


# ══════════════════════════════════════════════════════════════
#  LEGACY FUNCTIONS (backward compat)
# ══════════════════════════════════════════════════════════════

def repair_file(file_path, hex_sig):
    """Overwrite the first bytes with the correct signature."""
    with open(file_path, 'r+b') as f:
        f.seek(0)
        f.write(binascii.unhexlify(hex_sig))
    return "Repair complete."