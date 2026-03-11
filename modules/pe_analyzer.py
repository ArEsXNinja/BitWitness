#!/usr/bin/env python3
"""
pe_analyzer.py — PEStudio-inspired static PE analysis module.
Uses the 'pefile' library to parse Windows PE files and flag
suspicious characteristics without executing the binary.
"""

import os
import math
import struct
import hashlib
import datetime

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


# ── Suspicious API functions commonly abused by malware ──────
SUSPICIOUS_APIS = {
    # Process injection
    "CreateRemoteThread", "CreateRemoteThreadEx",
    "NtCreateThreadEx", "RtlCreateUserThread",
    "VirtualAlloc", "VirtualAllocEx",
    "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory",
    "NtWriteVirtualMemory", "NtReadVirtualMemory",
    "OpenProcess",

    # Code execution
    "ShellExecuteA", "ShellExecuteW",
    "ShellExecuteExA", "ShellExecuteExW",
    "WinExec", "CreateProcessA", "CreateProcessW",
    "CreateProcessInternalW",

    # DLL injection / loading
    "LoadLibraryA", "LoadLibraryW",
    "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "LdrLoadDll",

    # Keylogging / hooking
    "SetWindowsHookExA", "SetWindowsHookExW",
    "GetAsyncKeyState", "GetKeyState",
    "SetWinEventHook",

    # Registry manipulation
    "RegSetValueExA", "RegSetValueExW",
    "RegCreateKeyExA", "RegCreateKeyExW",
    "RegOpenKeyExA", "RegOpenKeyExW",
    "RegDeleteKeyA", "RegDeleteKeyW",

    # File / resource access
    "CreateFileA", "CreateFileW",
    "DeleteFileA", "DeleteFileW",
    "MoveFileA", "MoveFileW",

    # Network activity
    "InternetOpenA", "InternetOpenW",
    "InternetOpenUrlA", "InternetOpenUrlW",
    "InternetConnectA", "InternetConnectW",
    "HttpOpenRequestA", "HttpOpenRequestW",
    "HttpSendRequestA", "HttpSendRequestW",
    "URLDownloadToFileA", "URLDownloadToFileW",
    "WSAStartup", "connect", "send", "recv",
    "socket", "bind", "listen", "accept",

    # Crypto
    "CryptEncrypt", "CryptDecrypt",
    "CryptCreateHash", "CryptHashData",
    "CryptAcquireContextA", "CryptAcquireContextW",

    # Anti-debug / evasion
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "GetTickCount", "QueryPerformanceCounter",
    "OutputDebugStringA", "OutputDebugStringW",

    # Privilege escalation
    "AdjustTokenPrivileges", "OpenProcessToken",
    "LookupPrivilegeValueA", "LookupPrivilegeValueW",

    # Service manipulation
    "CreateServiceA", "CreateServiceW",
    "StartServiceA", "StartServiceW",
    "OpenSCManagerA", "OpenSCManagerW",
}

# ── Known suspicious section names ───────────────────────────
SUSPICIOUS_SECTIONS = {
    "UPX0", "UPX1", "UPX2",         # UPX packer
    ".ndata",                         # NSIS installer
    ".aspack", ".adata",              # ASPack
    ".petite",                        # Petite packer
    ".pec1", ".pec2",                 # PECompact
    ".themida", ".winlice",           # Themida
    ".vmp0", ".vmp1", ".vmp2",        # VMProtect
}


def is_pe_file(file_path):
    """Quick check: does the file start with MZ magic bytes?"""
    try:
        with open(file_path, "rb") as f:
            return f.read(2) == b"MZ"
    except Exception:
        return False


def analyze_pe(file_path):
    """
    Perform full static PE analysis.
    Returns a dict with all analysis results.
    """
    if not PEFILE_AVAILABLE:
        return {"error": "pefile library not installed. Run: pip install pefile"}

    if not is_pe_file(file_path):
        return {"error": "Not a valid PE file (missing MZ header)."}

    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError as e:
        return {"error": f"PE parsing error: {e}"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}

    result = {}

    # ── 1. Basic info ────────────────────────────────────────
    result["basic"] = _get_basic_info(pe, file_path)

    # ── 2. Sections ──────────────────────────────────────────
    result["sections"] = _get_sections(pe)

    # ── 3. Imports ───────────────────────────────────────────
    imports_info = _get_imports(pe)
    result["imports"] = imports_info["imports"]
    result["suspicious_apis"] = imports_info["suspicious"]

    # ── 4. Exports ───────────────────────────────────────────
    result["exports"] = _get_exports(pe)

    # ── 5. Import Hash (Imphash) ─────────────────────────────
    result["imphash"] = _get_imphash(pe)

    # ── 6. Overlay detection ─────────────────────────────────
    result["overlay"] = _get_overlay(pe, file_path)

    # ── 7. Resources ─────────────────────────────────────────
    result["resources"] = _get_resources(pe)

    # ── 8. Digital signature ─────────────────────────────────
    result["digital_signature"] = _check_digital_signature(pe)

    # ── 9. TLS Callbacks ─────────────────────────────────────
    result["tls_callbacks"] = _get_tls_callbacks(pe)

    # ── 10. Debug info ───────────────────────────────────────
    result["debug_info"] = _get_debug_info(pe)

    # ── 11. Rich header ──────────────────────────────────────
    result["rich_header"] = _get_rich_header(pe)

    # ── 12. Threat indicators ────────────────────────────────
    result["indicators"] = _get_threat_indicators(result)

    pe.close()
    return result


def _get_basic_info(pe, file_path):
    """Extract PE header information."""
    info = {}

    # Machine type
    machine_map = {
        0x14c:  "x86 (i386)",
        0x8664: "x64 (AMD64)",
        0x1c0:  "ARM",
        0xaa64: "ARM64",
    }
    info["machine"] = machine_map.get(
        pe.FILE_HEADER.Machine,
        f"Unknown (0x{pe.FILE_HEADER.Machine:X})"
    )

    # Compile timestamp
    try:
        ts = pe.FILE_HEADER.TimeDateStamp
        info["compile_time"] = datetime.datetime.utcfromtimestamp(ts).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
        info["compile_raw"] = ts
    except Exception:
        info["compile_time"] = "Invalid"

    # Entry point & image base
    info["entry_point"] = f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}"
    info["image_base"] = f"0x{pe.OPTIONAL_HEADER.ImageBase:08X}"

    # Subsystem
    subsys_map = {
        1: "Native",
        2: "Windows GUI",
        3: "Windows Console (CUI)",
        5: "OS/2 Console",
        7: "POSIX Console",
        9: "Windows CE GUI",
        10: "EFI Application",
    }
    info["subsystem"] = subsys_map.get(
        pe.OPTIONAL_HEADER.Subsystem,
        f"Unknown ({pe.OPTIONAL_HEADER.Subsystem})"
    )

    # File characteristics
    chars = []
    if pe.FILE_HEADER.Characteristics & 0x0002:
        chars.append("EXECUTABLE")
    if pe.FILE_HEADER.Characteristics & 0x2000:
        chars.append("DLL")
    if pe.FILE_HEADER.Characteristics & 0x0100:
        chars.append("32-BIT")
    if pe.FILE_HEADER.Characteristics & 0x0020:
        chars.append("LARGE_ADDRESS_AWARE")
    info["characteristics"] = ", ".join(chars) if chars else "None"

    # Number of sections
    info["num_sections"] = pe.FILE_HEADER.NumberOfSections

    # File size
    info["file_size"] = os.path.getsize(file_path)

    # PE type (PE32 vs PE32+)
    magic = pe.OPTIONAL_HEADER.Magic
    if magic == 0x10b:
        info["pe_type"] = "PE32 (32-bit)"
    elif magic == 0x20b:
        info["pe_type"] = "PE32+ (64-bit)"
    else:
        info["pe_type"] = f"Unknown (0x{magic:X})"

    return info


def _get_sections(pe):
    """Analyze each PE section."""
    sections = []
    for section in pe.sections:
        try:
            name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
        except Exception:
            name = str(section.Name)

        entropy = section.get_entropy()

        sec_info = {
            "name":           name,
            "virtual_size":   section.Misc_VirtualSize,
            "raw_size":       section.SizeOfRawData,
            "entropy":        round(entropy, 4),
            "high_entropy":   entropy > 7.0,
            "suspicious_name": name.strip(".").upper() in SUSPICIOUS_SECTIONS
                               or name.upper() in SUSPICIOUS_SECTIONS,
        }

        # Section characteristics
        chars = []
        if section.Characteristics & 0x20:
            chars.append("CODE")
        if section.Characteristics & 0x40:
            chars.append("INITIALIZED_DATA")
        if section.Characteristics & 0x80:
            chars.append("UNINITIALIZED_DATA")
        if section.Characteristics & 0x20000000:
            chars.append("EXECUTE")
        if section.Characteristics & 0x40000000:
            chars.append("READ")
        if section.Characteristics & 0x80000000:
            chars.append("WRITE")
        sec_info["characteristics"] = ", ".join(chars)

        # Size ratio (anomaly detection)
        if section.SizeOfRawData > 0:
            sec_info["size_ratio"] = round(
                section.Misc_VirtualSize / section.SizeOfRawData, 2
            )
        else:
            sec_info["size_ratio"] = 0

        sections.append(sec_info)

    return sections


def _get_imports(pe):
    """Parse import table and flag suspicious APIs."""
    imports = {}
    suspicious = []

    try:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="replace")
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode("utf-8", errors="replace")
                        funcs.append(func_name)
                        if func_name in SUSPICIOUS_APIS:
                            suspicious.append({
                                "dll":  dll_name,
                                "func": func_name,
                            })
                    else:
                        funcs.append(f"Ordinal: {imp.ordinal}")
                imports[dll_name] = funcs
    except Exception:
        pass

    return {"imports": imports, "suspicious": suspicious}


def _get_exports(pe):
    """Parse export table."""
    exports = []
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode("utf-8", errors="replace") if exp.name else f"Ordinal: {exp.ordinal}"
                exports.append(name)
    except Exception:
        pass
    return exports


# ══════════════════════════════════════════════════════════════
#  NEW v3.0 ANALYSIS FUNCTIONS
# ══════════════════════════════════════════════════════════════

def _get_imphash(pe):
    """Compute import hash for malware family correlation."""
    try:
        return pe.get_imphash()
    except Exception:
        return None


def _get_overlay(pe, file_path):
    """
    Detect overlay data appended after the PE structure.
    Overlays are commonly used by droppers and packed malware.
    """
    try:
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset is None:
            return {"present": False}

        file_size = os.path.getsize(file_path)
        overlay_size = file_size - overlay_offset

        if overlay_size <= 0:
            return {"present": False}

        # Read first bytes of overlay for analysis
        with open(file_path, "rb") as f:
            f.seek(overlay_offset)
            overlay_head = f.read(min(256, overlay_size))

        # Compute entropy of overlay
        entropy = _calc_entropy(overlay_head)

        # Check if overlay starts with MZ (embedded PE)
        has_embedded_pe = overlay_head[:2] == b"MZ"

        return {
            "present": True,
            "offset": f"0x{overlay_offset:X}",
            "size": overlay_size,
            "size_human": _human_size(overlay_size),
            "entropy": round(entropy, 4),
            "high_entropy": entropy > 7.0,
            "has_embedded_pe": has_embedded_pe,
            "first_bytes": " ".join(f"{b:02X}" for b in overlay_head[:16]),
        }
    except Exception:
        return {"present": False}


def _get_resources(pe):
    """
    Extract embedded resources with type, size, and entropy.
    Flags resources that may contain embedded executables.
    """
    resources = []
    try:
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return resources

        # Resource type names
        RESOURCE_TYPE = {
            1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU",
            5: "DIALOG", 6: "STRING", 7: "FONTDIR", 8: "FONT",
            9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE",
            12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION",
            24: "MANIFEST",
        }

        for rsrc_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            type_name = RESOURCE_TYPE.get(
                rsrc_type.id, rsrc_type.name.string.decode("utf-8", errors="replace")
                if rsrc_type.name else f"TYPE_{rsrc_type.id}"
            )

            if not hasattr(rsrc_type, "directory"):
                continue

            for rsrc_id in rsrc_type.directory.entries:
                if not hasattr(rsrc_id, "directory"):
                    continue

                for rsrc_lang in rsrc_id.directory.entries:
                    try:
                        data_rva = rsrc_lang.data.struct.OffsetToData
                        size = rsrc_lang.data.struct.Size
                        data = pe.get_data(data_rva, min(size, 4096))

                        entropy = _calc_entropy(data)

                        # Check for embedded PE
                        has_pe = data[:2] == b"MZ" if len(data) >= 2 else False

                        res_name = ""
                        if rsrc_id.name:
                            res_name = rsrc_id.name.string.decode("utf-8", errors="replace")
                        else:
                            res_name = str(rsrc_id.id)

                        resources.append({
                            "type": type_name,
                            "name": res_name,
                            "size": size,
                            "size_human": _human_size(size),
                            "entropy": round(entropy, 4),
                            "high_entropy": entropy > 7.0,
                            "has_embedded_pe": has_pe,
                            "suspicious": has_pe or entropy > 7.0 or size > 500000,
                        })
                    except Exception:
                        pass

    except Exception:
        pass

    return resources


def _check_digital_signature(pe):
    """
    Check if the PE has a digital signature (Authenticode).
    """
    try:
        # Security directory (IMAGE_DIRECTORY_ENTRY_SECURITY = 4)
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        if sec_dir.VirtualAddress == 0 or sec_dir.Size == 0:
            return {"signed": False, "detail": "No digital signature present"}

        return {
            "signed": True,
            "detail": "Authenticode signature present",
            "cert_offset": f"0x{sec_dir.VirtualAddress:X}",
            "cert_size": sec_dir.Size,
        }
    except Exception:
        return {"signed": False, "detail": "Cannot check signature"}


def _get_tls_callbacks(pe):
    """
    Detect TLS (Thread Local Storage) callbacks.
    TLS callbacks execute before the main entry point — often used for anti-debug.
    """
    callbacks = []
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
            tls = pe.DIRECTORY_ENTRY_TLS.struct
            callback_rva = tls.AddressOfCallBacks

            if callback_rva:
                # Read callback addresses
                callback_offset = pe.get_offset_from_rva(
                    callback_rva - pe.OPTIONAL_HEADER.ImageBase
                )
                addr_size = 8 if pe.OPTIONAL_HEADER.Magic == 0x20b else 4
                fmt = "<Q" if addr_size == 8 else "<I"

                for i in range(10):  # Max 10 callbacks
                    try:
                        addr_bytes = pe.get_data(callback_rva - pe.OPTIONAL_HEADER.ImageBase + i * addr_size, addr_size)
                        addr = struct.unpack(fmt, addr_bytes)[0]
                        if addr == 0:
                            break
                        callbacks.append(f"0x{addr:X}")
                    except Exception:
                        break
    except Exception:
        pass

    return {
        "present": len(callbacks) > 0,
        "count": len(callbacks),
        "addresses": callbacks,
    }


def _get_debug_info(pe):
    """
    Extract debug directory info.
    PDB paths can reveal the attacker's build environment.
    """
    debug_entries = []
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            DEBUG_TYPE = {
                1: "COFF", 2: "CODEVIEW", 3: "FPO",
                4: "MISC", 5: "EXCEPTION", 6: "FIXUP",
                9: "BORLAND", 11: "CLSID",
                13: "ILTCG", 14: "MPX", 16: "REPRO",
                20: "POGO",
            }

            for entry in pe.DIRECTORY_ENTRY_DEBUG:
                debug_type = DEBUG_TYPE.get(entry.struct.Type, f"TYPE_{entry.struct.Type}")
                info = {"type": debug_type}

                # Try to extract PDB path (CodeView)
                if entry.struct.Type == 2:  # CODEVIEW
                    try:
                        if hasattr(entry, "entry") and hasattr(entry.entry, "PdbFileName"):
                            pdb = entry.entry.PdbFileName.decode("utf-8", errors="replace").rstrip("\x00")
                            info["pdb_path"] = pdb
                    except Exception:
                        pass

                debug_entries.append(info)
    except Exception:
        pass

    return {
        "present": len(debug_entries) > 0,
        "entries": debug_entries,
    }


def _get_rich_header(pe):
    """
    Parse the Rich header (compiler/linker build environment fingerprint).
    """
    try:
        rich = pe.parse_rich_header()
        if not rich:
            return {"present": False}

        # Compute Rich header hash (MD5 of decrypted data)
        raw = rich.get("clear_data", b"")
        rich_hash = hashlib.md5(raw).hexdigest() if raw else None

        entries = []
        values = rich.get("values", [])
        for i in range(0, len(values), 2):
            if i + 1 < len(values):
                comp_id = values[i]
                count = values[i + 1]
                # comp_id encodes build tool and version
                tool_id = comp_id >> 16
                build = comp_id & 0xFFFF
                entries.append({
                    "tool_id": tool_id,
                    "build": build,
                    "count": count,
                })

        return {
            "present": True,
            "hash": rich_hash,
            "entries": entries,
            "entry_count": len(entries),
        }
    except Exception:
        return {"present": False}


def _calc_entropy(data):
    """Compute Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for c in freq:
        if c > 0:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


def _human_size(size):
    """Convert bytes to human-readable size."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024**2:
        return f"{size/1024:.1f} KB"
    elif size < 1024**3:
        return f"{size/1024**2:.1f} MB"
    return f"{size/1024**3:.1f} GB"


def _get_threat_indicators(result):
    """Summarize threat indicators from the analysis."""
    indicators = []

    # High-entropy sections
    high_ent = [s for s in result["sections"] if s["high_entropy"]]
    if high_ent:
        names = ", ".join(s["name"] for s in high_ent)
        indicators.append({
            "severity": "HIGH",
            "type":     "Packed/Encrypted",
            "detail":   f"High entropy section(s): {names} (possible packing/encryption)"
        })

    # Suspicious section names
    sus_sect = [s for s in result["sections"] if s["suspicious_name"]]
    if sus_sect:
        names = ", ".join(s["name"] for s in sus_sect)
        indicators.append({
            "severity": "HIGH",
            "type":     "Known Packer",
            "detail":   f"Suspicious section name(s): {names}"
        })

    # Suspicious API count
    sus_count = len(result["suspicious_apis"])
    if sus_count > 10:
        indicators.append({
            "severity": "HIGH",
            "type":     "Suspicious Imports",
            "detail":   f"{sus_count} suspicious API imports detected"
        })
    elif sus_count > 3:
        indicators.append({
            "severity": "MEDIUM",
            "type":     "Suspicious Imports",
            "detail":   f"{sus_count} suspicious API imports detected"
        })
    elif sus_count > 0:
        indicators.append({
            "severity": "LOW",
            "type":     "Suspicious Imports",
            "detail":   f"{sus_count} suspicious API import(s) detected"
        })

    # Compile timestamp anomaly
    basic = result.get("basic", {})
    raw_ts = basic.get("compile_raw", 0)
    if raw_ts == 0 or raw_ts > 2000000000:
        indicators.append({
            "severity": "MEDIUM",
            "type":     "Timestamp Anomaly",
            "detail":   "Compile timestamp is invalid or set far in the future"
        })

    # Writable + Executable section (W^X violation)
    for s in result["sections"]:
        chars = s.get("characteristics", "")
        if "WRITE" in chars and "EXECUTE" in chars:
            indicators.append({
                "severity": "MEDIUM",
                "type":     "W^X Violation",
                "detail":   f"Section '{s['name']}' is both writable and executable"
            })

    if not indicators:
        indicators.append({
            "severity": "INFO",
            "type":     "Clean",
            "detail":   "No obvious threat indicators found"
        })

    return indicators
