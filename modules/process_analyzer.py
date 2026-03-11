#!/usr/bin/env python3
"""
process_analyzer.py — Running process enumeration and forensic analysis.
Uses Windows API (kernel32.dll, psapi.dll) via ctypes to enumerate all
running processes, flag suspicious ones, and provide forensic details.

No external dependencies required — uses only Python standard library.
"""

import os
import sys
import ctypes
import ctypes.wintypes

# ══════════════════════════════════════════════════════════════
#  PLATFORM CHECK
# ══════════════════════════════════════════════════════════════

PROCESS_ANALYZER_AVAILABLE = sys.platform == "win32"


# ══════════════════════════════════════════════════════════════
#  WINDOWS API STRUCTURES & CONSTANTS
# ══════════════════════════════════════════════════════════════

if PROCESS_ANALYZER_AVAILABLE:
    # Snapshot flags
    TH32CS_SNAPPROCESS = 0x00000002

    # Process access rights
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_VM_READ = 0x0010

    MAX_PATH = 260

    class PROCESSENTRY32W(ctypes.Structure):
        """Structure for Process32First/Next."""
        _fields_ = [
            ("dwSize",              ctypes.wintypes.DWORD),
            ("cntUsage",            ctypes.wintypes.DWORD),
            ("th32ProcessID",       ctypes.wintypes.DWORD),
            ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID",        ctypes.wintypes.DWORD),
            ("cntThreads",          ctypes.wintypes.DWORD),
            ("th32ParentProcessID", ctypes.wintypes.DWORD),
            ("pcPriClassBase",      ctypes.c_long),
            ("dwFlags",             ctypes.wintypes.DWORD),
            ("szExeFile",           ctypes.wintypes.WCHAR * MAX_PATH),
        ]

    # Load API functions
    _kernel32 = ctypes.windll.kernel32

    _CreateToolhelp32Snapshot = _kernel32.CreateToolhelp32Snapshot
    _CreateToolhelp32Snapshot.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.DWORD]
    _CreateToolhelp32Snapshot.restype = ctypes.wintypes.HANDLE

    _Process32FirstW = _kernel32.Process32FirstW
    _Process32FirstW.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    _Process32FirstW.restype = ctypes.wintypes.BOOL

    _Process32NextW = _kernel32.Process32NextW
    _Process32NextW.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    _Process32NextW.restype = ctypes.wintypes.BOOL

    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    _CloseHandle.restype = ctypes.wintypes.BOOL

    _OpenProcess = _kernel32.OpenProcess
    _OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
    _OpenProcess.restype = ctypes.wintypes.HANDLE

    _QueryFullProcessImageNameW = _kernel32.QueryFullProcessImageNameW
    _QueryFullProcessImageNameW.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.LPWSTR,
        ctypes.POINTER(ctypes.wintypes.DWORD),
    ]
    _QueryFullProcessImageNameW.restype = ctypes.wintypes.BOOL

    INVALID_HANDLE_VALUE = ctypes.wintypes.HANDLE(-1).value


# ══════════════════════════════════════════════════════════════
#  SUSPICIOUS PROCESS INDICATORS
# ══════════════════════════════════════════════════════════════

# Well-known suspicious process names (commonly used by malware/tools)
SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz.exe", "mimi.exe", "mimi32.exe", "mimi64.exe",
    "procdump.exe", "procdump64.exe",
    "psexec.exe", "psexec64.exe",
    "cobalt.exe", "beacon.exe",
    "nc.exe", "ncat.exe", "netcat.exe",
    "lazagne.exe",
    "sharphound.exe", "bloodhound.exe",
    "rubeus.exe", "seatbelt.exe",
    "certutil.exe",  # often abused
    "bitsadmin.exe",  # often abused
    "mshta.exe",
    "wmic.exe",
    "cmstp.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "msiexec.exe",
    "powershell_ise.exe",
}

# Suspicious path fragments — processes running from these locations are flagged
SUSPICIOUS_PATH_FRAGMENTS = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\downloads\\",
    "\\public\\",
    "\\recycler\\",
    "\\$recycle.bin\\",
    "\\perflogs\\",
    "\\programdata\\",  # unusual for executables
]

# Known system process names (these are expected and safe)
KNOWN_SYSTEM_PROCESSES = {
    "system", "system idle process", "registry", "smss.exe",
    "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "svchost.exe", "dwm.exe", "explorer.exe",
    "taskhostw.exe", "sihost.exe", "fontdrvhost.exe",
    "runtimebroker.exe", "searchhost.exe", "startmenuexperiencehost.exe",
    "textinputhost.exe", "shellexperiencehost.exe", "ctfmon.exe",
    "conhost.exe", "dllhost.exe", "thoughtput.exe",
    "securityhealthservice.exe", "securityhealthsystray.exe",
    "msmpeng.exe", "nissrv.exe",  # Windows Defender
    "spoolsv.exe", "wudfhost.exe",
}


# ══════════════════════════════════════════════════════════════
#  CORE ANALYSIS FUNCTIONS
# ══════════════════════════════════════════════════════════════

def enumerate_processes():
    """
    Enumerate all running processes on the system.

    Returns:
        dict with keys:
            processes:         list of process dicts
            total_count:       total number of processes
            suspicious_count:  number of flagged processes
            suspicious_procs:  list of suspicious process dicts
            error:             error string if something went wrong
    """
    if not PROCESS_ANALYZER_AVAILABLE:
        return {"error": "Process analysis is only available on Windows."}

    try:
        procs = _get_all_processes()
    except Exception as e:
        return {"error": f"Failed to enumerate processes: {e}"}

    suspicious = []
    for proc in procs:
        reasons = _check_suspicious(proc)
        proc["suspicious"] = len(reasons) > 0
        proc["reasons"] = reasons
        if proc["suspicious"]:
            suspicious.append(proc)

    return {
        "processes":        procs,
        "total_count":      len(procs),
        "suspicious_count": len(suspicious),
        "suspicious_procs": suspicious,
    }


def get_process_details(pid):
    """
    Get detailed information about a specific process by PID.

    Returns:
        dict with process details.
    """
    if not PROCESS_ANALYZER_AVAILABLE:
        return {"error": "Process analysis is only available on Windows."}

    procs = _get_all_processes()
    for proc in procs:
        if proc["pid"] == pid:
            reasons = _check_suspicious(proc)
            proc["suspicious"] = len(reasons) > 0
            proc["reasons"] = reasons
            return proc

    return {"error": f"Process with PID {pid} not found."}


def find_process_by_name(name):
    """
    Find all processes matching a given name (case-insensitive).

    Returns:
        list of matching process dicts.
    """
    if not PROCESS_ANALYZER_AVAILABLE:
        return {"error": "Process analysis is only available on Windows."}

    procs = _get_all_processes()
    matches = []
    name_lower = name.lower()

    for proc in procs:
        if name_lower in proc["name"].lower():
            reasons = _check_suspicious(proc)
            proc["suspicious"] = len(reasons) > 0
            proc["reasons"] = reasons
            matches.append(proc)

    return matches


# ══════════════════════════════════════════════════════════════
#  INTERNAL HELPERS
# ══════════════════════════════════════════════════════════════

def _get_all_processes():
    """Use CreateToolhelp32Snapshot to enumerate all processes."""
    processes = []

    # Take snapshot
    snapshot = _CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        return processes

    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

        if not _Process32FirstW(snapshot, ctypes.byref(entry)):
            return processes

        while True:
            exe_name = entry.szExeFile
            pid = entry.th32ProcessID
            ppid = entry.th32ParentProcessID
            threads = entry.cntThreads

            # Try to get the full executable path
            full_path = _get_process_path(pid)

            processes.append({
                "pid":         pid,
                "ppid":        ppid,
                "name":        exe_name,
                "full_path":   full_path,
                "threads":     threads,
            })

            if not _Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        _CloseHandle(snapshot)

    return processes


def _get_process_path(pid):
    """Get the full executable path for a process by PID."""
    if pid == 0 or pid == 4:  # System Idle Process / System
        return "N/A"

    # Try PROCESS_QUERY_LIMITED_INFORMATION first (works for more processes)
    for access in [PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_QUERY_INFORMATION]:
        handle = _OpenProcess(access, False, pid)
        if not handle:
            continue

        try:
            buf = ctypes.create_unicode_buffer(1024)
            size = ctypes.wintypes.DWORD(1024)
            if _QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                return buf.value
        finally:
            _CloseHandle(handle)

    return "Access Denied"


def _check_suspicious(proc):
    """Check a process for suspicious indicators."""
    reasons = []
    name_lower = proc["name"].lower()
    path_lower = (proc.get("full_path") or "").lower()

    # Check against known suspicious names
    if name_lower in SUSPICIOUS_PROCESS_NAMES:
        reasons.append(f"Known suspicious tool: {proc['name']}")

    # Check for suspicious path locations
    if path_lower and path_lower != "n/a" and path_lower != "access denied":
        for frag in SUSPICIOUS_PATH_FRAGMENTS:
            if frag in path_lower:
                reasons.append(f"Running from suspicious location: {frag.strip(chr(92))}")
                break

        # Check for processes with no file extension (unusual)
        if "." not in os.path.basename(path_lower):
            reasons.append("Executable has no file extension")

    # Check for common LOLBin abuse patterns
    # (Living Off the Land Binaries)
    lolbins = {
        "mshta.exe":     "LOLBin: Can execute HTA/VBScript",
        "regsvr32.exe":  "LOLBin: Can download and execute code",
        "rundll32.exe":  "LOLBin: Can execute arbitrary DLLs",
        "certutil.exe":  "LOLBin: Can download files and decode",
        "bitsadmin.exe": "LOLBin: Can download files",
        "cmstp.exe":     "LOLBin: Can bypass UAC/AppLocker",
        "msiexec.exe":   "LOLBin: Can execute remote MSI packages",
        "wmic.exe":      "LOLBin: Can execute commands remotely",
    }
    if name_lower in lolbins:
        reasons.append(lolbins[name_lower])

    return reasons


def get_process_summary():
    """
    Get a high-level summary of the process landscape.

    Returns:
        dict with summary stats.
    """
    result = enumerate_processes()
    if "error" in result:
        return result

    procs = result["processes"]

    # Count unique executable names
    unique_names = set(p["name"].lower() for p in procs)

    # Count processes by path status
    accessible = sum(1 for p in procs if p.get("full_path") not in ("N/A", "Access Denied", None))
    denied = sum(1 for p in procs if p.get("full_path") == "Access Denied")

    return {
        "total_processes":    len(procs),
        "unique_executables": len(unique_names),
        "path_accessible":    accessible,
        "path_denied":        denied,
        "suspicious_count":   result["suspicious_count"],
        "suspicious_procs":   result["suspicious_procs"],
    }
