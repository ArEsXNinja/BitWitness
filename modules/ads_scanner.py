#!/usr/bin/env python3
"""
ads_scanner.py — NTFS Alternate Data Streams (ADS) scanner.
Uses Windows API (kernel32.dll) via ctypes to detect hidden data streams
attached to files — a classic malware hiding technique on NTFS volumes.

No external dependencies required — uses only Python standard library.
"""

import os
import sys
import ctypes
import ctypes.wintypes

# ══════════════════════════════════════════════════════════════
#  PLATFORM CHECK
# ══════════════════════════════════════════════════════════════

ADS_AVAILABLE = sys.platform == "win32"


# ══════════════════════════════════════════════════════════════
#  WINDOWS API STRUCTURES & CONSTANTS
# ══════════════════════════════════════════════════════════════

if ADS_AVAILABLE:
    # Stream info level enum value
    FindStreamInfoStandard = 0

    # MAX_PATH for stream names
    MAX_PATH = 260

    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        """Structure returned by FindFirstStreamW / FindNextStreamW."""
        _fields_ = [
            ("StreamSize", ctypes.wintypes.LARGE_INTEGER),
            ("cStreamName", ctypes.wintypes.WCHAR * (MAX_PATH + 36)),
        ]

    # Load kernel32 functions
    _kernel32 = ctypes.windll.kernel32

    _FindFirstStreamW = _kernel32.FindFirstStreamW
    _FindFirstStreamW.argtypes = [
        ctypes.wintypes.LPCWSTR,        # lpFileName
        ctypes.c_int,                    # InfoLevel
        ctypes.POINTER(WIN32_FIND_STREAM_DATA),  # lpFindStreamData
        ctypes.wintypes.DWORD,           # dwFlags (reserved, must be 0)
    ]
    _FindFirstStreamW.restype = ctypes.wintypes.HANDLE

    _FindNextStreamW = _kernel32.FindNextStreamW
    _FindNextStreamW.argtypes = [
        ctypes.wintypes.HANDLE,          # hFindStream
        ctypes.POINTER(WIN32_FIND_STREAM_DATA),  # lpFindStreamData
    ]
    _FindNextStreamW.restype = ctypes.wintypes.BOOL

    _FindClose = _kernel32.FindClose
    _FindClose.argtypes = [ctypes.wintypes.HANDLE]
    _FindClose.restype = ctypes.wintypes.BOOL

    INVALID_HANDLE_VALUE = ctypes.wintypes.HANDLE(-1).value


# ══════════════════════════════════════════════════════════════
#  SUSPICIOUS STREAM INDICATORS
# ══════════════════════════════════════════════════════════════

# Stream names that may indicate hidden executable content
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".scr", ".com", ".pif", ".hta", ".cpl", ".msi", ".wsf",
    ".jar", ".py", ".rb", ".sh",
}

# Minimum hidden data size to flag as notable (bytes)
NOTABLE_SIZE_THRESHOLD = 1024  # 1 KB


# ══════════════════════════════════════════════════════════════
#  CORE SCANNING FUNCTIONS
# ══════════════════════════════════════════════════════════════

def scan_ads(file_path):
    """
    Scan a file for NTFS Alternate Data Streams.

    Args:
        file_path: Path to the file to scan.

    Returns:
        dict with keys:
            streams:        list of stream dicts (name, size, is_default, suspicious, reason)
            total_streams:  total number of streams (including default ::$DATA)
            hidden_streams: number of non-default streams
            hidden_size:    total bytes in hidden streams
            has_suspicious: bool — True if any stream is flagged suspicious
            error:          error string if something went wrong
    """
    if not ADS_AVAILABLE:
        return {"error": "ADS scanning is only available on Windows (NTFS volumes)."}

    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}

    abs_path = os.path.abspath(file_path)

    try:
        streams = _enumerate_streams(abs_path)
    except Exception as e:
        return {"error": f"Failed to enumerate streams: {e}"}

    # Classify streams
    hidden_streams = []
    default_stream = None
    total_hidden_size = 0
    has_suspicious = False

    for stream in streams:
        name = stream["name"]
        size = stream["size"]

        # The default data stream is "::$DATA"
        if name == "::$DATA" or name == ":$DATA":
            stream["is_default"] = True
            default_stream = stream
        else:
            stream["is_default"] = False
            total_hidden_size += size

            # Check for suspicious indicators
            reasons = []

            # Check stream name extension
            stream_name_lower = name.lower()
            for ext in SUSPICIOUS_EXTENSIONS:
                if ext in stream_name_lower:
                    reasons.append(f"Executable extension in stream name ({ext})")
                    break

            # Check for notable size
            if size > NOTABLE_SIZE_THRESHOLD:
                reasons.append(f"Large hidden data ({_human_size(size)})")

            # Check for MZ header (PE executable in stream)
            if size >= 2:
                try:
                    stream_path = abs_path + name.split(":$DATA")[0]
                    with open(stream_path, "rb") as f:
                        magic = f.read(2)
                    if magic == b"MZ":
                        reasons.append("Contains PE executable (MZ header)")
                    elif magic == b"PK":
                        reasons.append("Contains ZIP/archive data (PK header)")
                except Exception:
                    pass

            stream["suspicious"] = len(reasons) > 0
            stream["reasons"] = reasons
            if stream["suspicious"]:
                has_suspicious = True

            hidden_streams.append(stream)

    return {
        "streams":        streams,
        "total_streams":  len(streams),
        "hidden_streams": len(hidden_streams),
        "hidden_details": hidden_streams,
        "hidden_size":    total_hidden_size,
        "hidden_size_human": _human_size(total_hidden_size),
        "has_suspicious": has_suspicious,
        "default_stream": default_stream,
    }


def extract_ads(file_path, stream_name, output_path):
    """
    Extract/dump the content of a specific ADS to a file.

    Args:
        file_path:   Path to the file with the ADS
        stream_name: Name of the stream (e.g., ":hidden.txt:$DATA")
        output_path: Where to write the extracted content

    Returns:
        dict with keys: success, bytes_written, output_path, error
    """
    if not ADS_AVAILABLE:
        return {"error": "ADS extraction is only available on Windows."}

    abs_path = os.path.abspath(file_path)

    # Build the stream path: file.txt:stream_name
    # Strip :$DATA suffix if present for opening
    clean_name = stream_name.split(":$DATA")[0]
    if clean_name.startswith(":"):
        stream_path = abs_path + clean_name
    else:
        stream_path = abs_path + ":" + clean_name

    try:
        with open(stream_path, "rb") as src:
            data = src.read()

        with open(output_path, "wb") as dst:
            dst.write(data)

        return {
            "success":       True,
            "bytes_written": len(data),
            "output_path":   os.path.abspath(output_path),
        }
    except Exception as e:
        return {"error": f"Failed to extract ADS: {e}"}


def scan_directory_ads(dir_path, recursive=False):
    """
    Scan all files in a directory for ADS.

    Args:
        dir_path:   Path to directory
        recursive:  If True, scan subdirectories too

    Returns:
        dict with keys:
            files_scanned:   int
            files_with_ads:  int
            total_hidden:    int
            results:         list of (file_path, scan_result) tuples
    """
    if not ADS_AVAILABLE:
        return {"error": "ADS scanning is only available on Windows."}

    if not os.path.isdir(dir_path):
        return {"error": f"Directory not found: {dir_path}"}

    results = []
    files_scanned = 0
    files_with_ads = 0
    total_hidden = 0

    walker = os.walk(dir_path) if recursive else [(dir_path, [], os.listdir(dir_path))]

    for root, dirs, files in walker:
        for fname in files:
            fpath = os.path.join(root, fname)
            if not os.path.isfile(fpath):
                continue

            files_scanned += 1
            result = scan_ads(fpath)

            if "error" not in result and result["hidden_streams"] > 0:
                files_with_ads += 1
                total_hidden += result["hidden_streams"]
                results.append({"file": fpath, "scan": result})

    return {
        "files_scanned":  files_scanned,
        "files_with_ads": files_with_ads,
        "total_hidden":   total_hidden,
        "results":        results,
    }


# ══════════════════════════════════════════════════════════════
#  INTERNAL HELPERS
# ══════════════════════════════════════════════════════════════

def _enumerate_streams(file_path):
    """Use Windows API to enumerate all streams on a file."""
    streams = []
    find_data = WIN32_FIND_STREAM_DATA()

    handle = _FindFirstStreamW(
        file_path,
        FindStreamInfoStandard,
        ctypes.byref(find_data),
        0,
    )

    if handle == INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error() if hasattr(ctypes, 'get_last_error') else ctypes.GetLastError()
        # ERROR_HANDLE_EOF (38) means no streams — normal for non-NTFS
        if err == 38:
            return streams
        # ERROR_INVALID_PARAMETER (87) — file system doesn't support streams
        if err == 87:
            return streams
        return streams

    try:
        streams.append({
            "name": find_data.cStreamName,
            "size": find_data.StreamSize,
        })

        while _FindNextStreamW(handle, ctypes.byref(find_data)):
            streams.append({
                "name": find_data.cStreamName,
                "size": find_data.StreamSize,
            })
    finally:
        _FindClose(handle)

    return streams


def _human_size(size):
    """Convert bytes to human-readable size."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 ** 2:
        return f"{size / 1024:.2f} KB"
    elif size < 1024 ** 3:
        return f"{size / (1024 ** 2):.2f} MB"
    else:
        return f"{size / (1024 ** 3):.2f} GB"
