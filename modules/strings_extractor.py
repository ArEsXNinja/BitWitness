#!/usr/bin/env python3
"""
strings_extractor.py — Extract and classify printable strings from any binary.
Flags suspicious patterns: URLs, IPs, registry keys, commands, file extensions.
"""

import re
import os


# ── Minimum string length to extract ────────────────────────
MIN_LENGTH = 4

# ── Suspicious pattern definitions ──────────────────────────
SUSPICIOUS_PATTERNS = {
    "URL": re.compile(
        r"https?://[^\s\"'<>]+", re.IGNORECASE
    ),
    "IP Address": re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ),
    "Email": re.compile(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    ),
    "Registry Key": re.compile(
        r"(HKEY_[A-Z_]+|HKLM|HKCU|HKCR)\\[^\s\"']+", re.IGNORECASE
    ),
    "Windows Path": re.compile(
        r"[A-Z]:\\[^\s\"']{3,}", re.IGNORECASE
    ),
    "UNC Path": re.compile(
        r"\\\\[^\s\"']{3,}"
    ),
    "Executable Reference": re.compile(
        r"\b\w+\.(exe|dll|bat|cmd|ps1|vbs|js|scr|com|pif|hta|cpl|msi|wsf)\b",
        re.IGNORECASE
    ),
    "Suspicious Command": re.compile(
        r"\b(cmd\.exe|powershell|wget|curl|certutil|bitsadmin|mshta|regsvr32|rundll32"
        r"|wscript|cscript|schtasks|net\s+user|net\s+localgroup|taskkill|attrib\s+\+h)\b",
        re.IGNORECASE
    ),
    "Crypto / Encoding": re.compile(
        r"\b(base64|AES|RSA|DES|RC4|XOR|encrypt|decrypt|cipher|hash|md5|sha1|sha256)\b",
        re.IGNORECASE
    ),
}


def extract_strings(file_path, min_length=MIN_LENGTH):
    """
    Extract ASCII and Unicode strings from a binary file.
    Returns a dict with all strings and classified suspicious strings.
    """
    if not os.path.isfile(file_path):
        return {"error": f"File not found: {file_path}"}

    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        return {"error": f"Cannot read file: {e}"}

    # Extract ASCII strings
    ascii_strings = _extract_ascii(data, min_length)

    # Extract Unicode (UTF-16LE) strings
    unicode_strings = _extract_unicode(data, min_length)

    # Combine and deduplicate, preserving order
    all_strings = list(dict.fromkeys(ascii_strings + unicode_strings))

    # Classify suspicious strings
    suspicious = _classify_strings(all_strings)

    return {
        "total_count":     len(all_strings),
        "ascii_count":     len(ascii_strings),
        "unicode_count":   len(unicode_strings),
        "all_strings":     all_strings,
        "suspicious":      suspicious,
        "suspicious_count": sum(len(v) for v in suspicious.values()),
    }


def _extract_ascii(data, min_length):
    """Extract printable ASCII strings."""
    pattern = re.compile(
        rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}"
    )
    matches = pattern.findall(data)
    return [m.decode("ascii", errors="replace") for m in matches]


def _extract_unicode(data, min_length):
    """Extract UTF-16LE encoded strings."""
    pattern = re.compile(
        rb"(?:[\x20-\x7E]\x00){" + str(min_length).encode() + rb",}"
    )
    matches = pattern.findall(data)
    results = []
    for m in matches:
        try:
            s = m.decode("utf-16-le", errors="replace").strip("\x00")
            if len(s) >= min_length:
                results.append(s)
        except Exception:
            pass
    return results


def _classify_strings(strings):
    """Classify strings into suspicious categories."""
    classified = {}

    for s in strings:
        for category, pattern in SUSPICIOUS_PATTERNS.items():
            matches = pattern.findall(s)
            if matches:
                if category not in classified:
                    classified[category] = []
                for m in matches:
                    val = m if isinstance(m, str) else m[0] if isinstance(m, tuple) else str(m)
                    if val not in classified[category]:
                        classified[category].append(val)

    return classified


def get_strings_summary(file_path, max_display=50):
    """
    Convenience function: extract strings and return a formatted summary.
    Returns the full result dict with a 'display_strings' key limited to max_display.
    """
    result = extract_strings(file_path)
    if "error" in result:
        return result

    # Trim the full list for display
    result["display_strings"] = result["all_strings"][:max_display]
    result["truncated"] = len(result["all_strings"]) > max_display

    return result
