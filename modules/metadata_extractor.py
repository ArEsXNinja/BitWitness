#!/usr/bin/env python3
"""
metadata_extractor.py — File metadata and EXIF data extraction for forensic analysis.
Extracts timestamps, file properties, EXIF image metadata, and PE version info.
"""

import os
import stat
import datetime

# Optional: Pillow for EXIF extraction
try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

# Optional: pefile for PE version info
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


# ══════════════════════════════════════════════════════════════
#  FILE METADATA
# ══════════════════════════════════════════════════════════════

def get_file_metadata(file_path):
    """
    Extract comprehensive file metadata.

    Returns dict with:
        file_name, full_path, extension, size_bytes, size_human,
        created, modified, accessed, permissions, is_hidden,
        is_readonly, is_symlink
    """
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}

    try:
        abs_path = os.path.abspath(file_path)
        st = os.stat(file_path)
        size = st.st_size

        # Human-readable size
        if size < 1024:
            size_human = f"{size} B"
        elif size < 1024 ** 2:
            size_human = f"{size / 1024:.2f} KB"
        elif size < 1024 ** 3:
            size_human = f"{size / (1024 ** 2):.2f} MB"
        else:
            size_human = f"{size / (1024 ** 3):.2f} GB"

        # Timestamps
        created  = datetime.datetime.fromtimestamp(st.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
        modified = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        accessed = datetime.datetime.fromtimestamp(st.st_atime).strftime("%Y-%m-%d %H:%M:%S")

        # Permissions
        mode = st.st_mode
        perms = stat.filemode(mode)

        # Attributes
        is_hidden = os.path.basename(file_path).startswith(".")
        is_readonly = not os.access(file_path, os.W_OK)
        is_symlink = os.path.islink(file_path)

        # Windows: check hidden attribute
        if os.name == "nt":
            try:
                import ctypes
                attrs = ctypes.windll.kernel32.GetFileAttributesW(abs_path)
                if attrs != -1:
                    is_hidden = bool(attrs & 0x02)
            except Exception:
                pass

        return {
            "file_name":    os.path.basename(file_path),
            "full_path":    abs_path,
            "extension":    os.path.splitext(file_path)[1] or "N/A",
            "size_bytes":   size,
            "size_human":   size_human,
            "created":      created,
            "modified":     modified,
            "accessed":     accessed,
            "permissions":  perms,
            "is_hidden":    is_hidden,
            "is_readonly":  is_readonly,
            "is_symlink":   is_symlink,
        }
    except Exception as e:
        return {"error": f"Cannot read metadata: {e}"}


# ══════════════════════════════════════════════════════════════
#  EXIF DATA (Images)
# ══════════════════════════════════════════════════════════════

def get_exif_data(file_path):
    """
    Extract EXIF metadata from an image file.

    Returns dict with EXIF tags, including GPS data if available.
    Returns {"available": False} if not an image or no EXIF data.
    """
    if not PILLOW_AVAILABLE:
        return {"available": False, "reason": "Pillow not installed (pip install Pillow)"}

    try:
        img = Image.open(file_path)
    except Exception:
        return {"available": False, "reason": "Not a valid image file"}

    exif_raw = img.getexif()
    if not exif_raw:
        return {"available": False, "reason": "No EXIF data found"}

    exif_data = {}
    gps_data = {}

    for tag_id, value in exif_raw.items():
        tag_name = TAGS.get(tag_id, f"Tag_{tag_id}")

        # Handle GPS separately
        if tag_name == "GPSInfo":
            if isinstance(value, dict):
                for gps_id, gps_val in value.items():
                    gps_name = GPSTAGS.get(gps_id, f"GPS_{gps_id}")
                    gps_data[gps_name] = _safe_str(gps_val)
            continue

        exif_data[tag_name] = _safe_str(value)

    result = {
        "available": True,
        "tags": exif_data,
        "tag_count": len(exif_data),
    }

    if gps_data:
        result["gps"] = gps_data

    # Extract key fields for quick summary
    summary = {}
    key_fields = ["Make", "Model", "Software", "DateTime",
                  "DateTimeOriginal", "ExposureTime", "FNumber",
                  "ISOSpeedRatings", "ImageWidth", "ImageLength"]
    for field in key_fields:
        if field in exif_data:
            summary[field] = exif_data[field]

    if summary:
        result["summary"] = summary

    return result


def _safe_str(val):
    """Convert EXIF value to a safe string representation."""
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8", errors="replace").strip("\x00")
        except Exception:
            return val.hex()
    elif isinstance(val, (list, tuple)):
        return ", ".join(str(v) for v in val)
    else:
        return str(val)


# ══════════════════════════════════════════════════════════════
#  PE VERSION INFO
# ══════════════════════════════════════════════════════════════

def get_pe_metadata(file_path):
    """
    Extract version info and metadata from PE files.

    Returns dict with company, product, description, version, etc.
    """
    if not PEFILE_AVAILABLE:
        return {"available": False, "reason": "pefile not installed"}

    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )
    except Exception:
        return {"available": False, "reason": "Not a valid PE file"}

    version_info = {}

    if hasattr(pe, "VS_VERSIONINFO"):
        for info in pe.VS_VERSIONINFO:
            if hasattr(info, "StringTable"):
                for st in info.StringTable:
                    for entry in st.entries.items():
                        key = entry[0].decode("utf-8", errors="replace")
                        val = entry[1].decode("utf-8", errors="replace")
                        version_info[key] = val

    if hasattr(pe, "FileInfo"):
        for fi_list in pe.FileInfo:
            for fi in fi_list:
                if hasattr(fi, "StringTable"):
                    for st in fi.StringTable:
                        for key, val in st.entries.items():
                            k = key.decode("utf-8", errors="replace")
                            v = val.decode("utf-8", errors="replace")
                            version_info[k] = v

    pe.close()

    if not version_info:
        return {"available": False, "reason": "No version info in PE"}

    return {
        "available": True,
        "version_info": version_info,
    }
