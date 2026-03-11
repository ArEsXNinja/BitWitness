#!/usr/bin/env python3
"""
vt_lookup.py — VirusTotal API v3 hash-based lookup module.
Only sends the file HASH to VirusTotal — the file itself is never uploaded.
Requires a free API key from https://www.virustotal.com
"""

import os
import sys
import hashlib

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


VT_API_URL = "https://www.virustotal.com/api/v3/files/{file_id}"


def _get_api_key():
    """
    Try to get the VT API key from:
      1. Environment variable VT_API_KEY
      2. A .vt_api_key file searched in multiple locations:
         - Project root (relative to modules/)
         - modules/ directory itself
         - Current working directory
         - Directory of the main script (sys.argv[0])
         - Directory of the exe (for PyInstaller builds)
    Returns None if not found.
    """
    # Check env variable
    key = os.environ.get("VT_API_KEY", "").strip()
    if key:
        return key

    # Build list of directories to search
    search_dirs = []

    # 1. Relative to this module file (original behavior)
    module_dir = os.path.dirname(os.path.abspath(__file__))
    search_dirs.append(os.path.join(module_dir, ".."))  # project root
    search_dirs.append(module_dir)                       # modules/ dir

    # 2. Current working directory
    search_dirs.append(os.getcwd())

    # 3. Directory of the main script (sys.argv[0])
    if sys.argv and sys.argv[0]:
        search_dirs.append(os.path.dirname(os.path.abspath(sys.argv[0])))

    # 4. PyInstaller exe directory (frozen builds)
    if getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(sys.executable)
        search_dirs.append(exe_dir)
        search_dirs.append(os.path.join(exe_dir, ".."))  # parent of exe dir (e.g. project root)

    # 5. User home directory
    search_dirs.append(os.path.expanduser("~"))

    # De-duplicate while preserving order
    seen = set()
    unique_dirs = []
    for d in search_dirs:
        d = os.path.abspath(d)
        if d not in seen:
            seen.add(d)
            unique_dirs.append(d)

    # Search each directory for .vt_api_key
    for directory in unique_dirs:
        key_path = os.path.join(directory, ".vt_api_key")
        try:
            with open(key_path, "r") as f:
                key = f.read().strip()
                if key:
                    return key
        except (FileNotFoundError, PermissionError):
            pass

    return None


def _compute_sha256(file_path):
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def lookup_hash(file_path, api_key=None):
    """
    Perform a VirusTotal hash lookup for the given file.
    Only the SHA-256 hash is sent — the file is NEVER uploaded.

    Returns a dict with results or error info.
    """
    if not REQUESTS_AVAILABLE:
        return {
            "error": "requests library not installed. Run: pip install requests",
            "status": "unavailable",
        }

    # Resolve API key
    if not api_key:
        api_key = _get_api_key()

    if not api_key:
        return {
            "error": "No VirusTotal API key provided. Set VT_API_KEY env variable or provide key at prompt.",
            "status": "no_key",
        }

    # Compute hash
    try:
        file_hash = _compute_sha256(file_path)
    except Exception as e:
        return {"error": f"Cannot hash file: {e}", "status": "hash_error"}

    # Query VT API v3
    url = VT_API_URL.format(file_id=file_hash)
    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(url, headers=headers, timeout=30)
    except requests.exceptions.ConnectionError:
        return {"error": "Cannot connect to VirusTotal. Check your internet.", "status": "connection_error"}
    except requests.exceptions.Timeout:
        return {"error": "VirusTotal request timed out.", "status": "timeout"}
    except Exception as e:
        return {"error": f"Request failed: {e}", "status": "request_error"}

    if resp.status_code == 404:
        return {
            "status":    "not_found",
            "file_hash": file_hash,
            "message":   "File hash not found in VirusTotal database.",
        }

    if resp.status_code == 401:
        return {
            "status":  "auth_error",
            "error":   "Invalid API key. Check your VirusTotal API key.",
        }

    if resp.status_code == 429:
        return {
            "status": "rate_limit",
            "error":  "API rate limit exceeded. Free tier allows 4 requests/minute.",
        }

    if resp.status_code != 200:
        return {
            "status": "api_error",
            "error":  f"VirusTotal API returned status {resp.status_code}",
        }

    # Parse response
    try:
        data = resp.json()
    except Exception:
        return {"error": "Cannot parse VT response.", "status": "parse_error"}

    return _parse_vt_response(data, file_hash)


def _parse_vt_response(data, file_hash):
    """Parse the VT API v3 JSON response into a clean result dict."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious   = stats.get("malicious", 0)
    suspicious  = stats.get("suspicious", 0)
    undetected  = stats.get("undetected", 0)
    harmless    = stats.get("harmless", 0)
    timeout     = stats.get("timeout", 0)
    unsupported = stats.get("type-unsupported", 0)
    total       = malicious + suspicious + undetected + harmless + timeout + unsupported

    # Get top engine detections
    detections = []
    analysis_results = attrs.get("last_analysis_results", {})
    for engine, detail in analysis_results.items():
        if detail.get("category") in ("malicious", "suspicious"):
            detections.append({
                "engine": engine,
                "result": detail.get("result", "N/A"),
                "category": detail.get("category"),
            })

    # Sort by engine name
    detections.sort(key=lambda d: d["engine"])

    # Threat labels
    popular_threat = attrs.get("popular_threat_classification", {})
    threat_label = popular_threat.get("suggested_threat_label", "N/A")

    result = {
        "status":       "found",
        "file_hash":    file_hash,
        "malicious":    malicious,
        "suspicious":   suspicious,
        "undetected":   undetected,
        "harmless":     harmless,
        "total":        total,
        "detection_ratio": f"{malicious + suspicious}/{total}",
        "threat_label": threat_label,
        "detections":   detections[:25],  # Limit to top 25
        "file_type":    attrs.get("type_description", "Unknown"),
        "file_name":    attrs.get("meaningful_name", "N/A"),
        "first_seen":   attrs.get("first_submission_date"),
        "last_seen":    attrs.get("last_analysis_date"),
        "reputation":   attrs.get("reputation", "N/A"),
        "tags":         attrs.get("tags", []),
    }

    # Verdict
    if malicious > 5:
        result["verdict"] = "MALICIOUS"
    elif malicious > 0 or suspicious > 0:
        result["verdict"] = "SUSPICIOUS"
    else:
        result["verdict"] = "CLEAN"

    return result
