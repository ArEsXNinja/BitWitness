#!/usr/bin/env python3
"""
eventlog_reader.py — Windows Event Log reader for forensic analysis.
Uses Windows API (advapi32.dll) via ctypes to read Security, System,
and Application event logs for forensic-relevant events.

No external dependencies required — uses only Python standard library.
"""

import os
import sys
import ctypes
import ctypes.wintypes
import struct
import datetime

# ══════════════════════════════════════════════════════════════
#  PLATFORM CHECK
# ══════════════════════════════════════════════════════════════

EVENTLOG_AVAILABLE = sys.platform == "win32"


# ══════════════════════════════════════════════════════════════
#  WINDOWS API CONSTANTS
# ══════════════════════════════════════════════════════════════

if EVENTLOG_AVAILABLE:
    # Read flags
    EVENTLOG_SEQUENTIAL_READ = 0x0001
    EVENTLOG_BACKWARDS_READ = 0x0008

    # Event types
    EVENTLOG_SUCCESS          = 0x0000
    EVENTLOG_ERROR_TYPE       = 0x0001
    EVENTLOG_WARNING_TYPE     = 0x0002
    EVENTLOG_INFORMATION_TYPE = 0x0004
    EVENTLOG_AUDIT_SUCCESS    = 0x0008
    EVENTLOG_AUDIT_FAILURE    = 0x0010

    EVENT_TYPE_NAMES = {
        EVENTLOG_SUCCESS:          "Success",
        EVENTLOG_ERROR_TYPE:       "Error",
        EVENTLOG_WARNING_TYPE:     "Warning",
        EVENTLOG_INFORMATION_TYPE: "Information",
        EVENTLOG_AUDIT_SUCCESS:    "Audit Success",
        EVENTLOG_AUDIT_FAILURE:    "Audit Failure",
    }

    # EVENTLOGRECORD structure offsets (fixed header is 56 bytes)
    # We parse manually since the structure has variable-length fields

    # Load advapi32
    _advapi32 = ctypes.windll.advapi32

    _OpenEventLogW = _advapi32.OpenEventLogW
    _OpenEventLogW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR]
    _OpenEventLogW.restype = ctypes.wintypes.HANDLE

    _ReadEventLogW = _advapi32.ReadEventLogW
    _ReadEventLogW.argtypes = [
        ctypes.wintypes.HANDLE,     # hEventLog
        ctypes.wintypes.DWORD,      # dwReadFlags
        ctypes.wintypes.DWORD,      # dwRecordOffset
        ctypes.c_void_p,            # lpBuffer
        ctypes.wintypes.DWORD,      # nNumberOfBytesToRead
        ctypes.POINTER(ctypes.wintypes.DWORD),  # pnBytesRead
        ctypes.POINTER(ctypes.wintypes.DWORD),  # pnMinNumberOfBytesNeeded
    ]
    _ReadEventLogW.restype = ctypes.wintypes.BOOL

    _CloseEventLog = _advapi32.CloseEventLog
    _CloseEventLog.argtypes = [ctypes.wintypes.HANDLE]
    _CloseEventLog.restype = ctypes.wintypes.BOOL

    _GetNumberOfEventLogRecords = _advapi32.GetNumberOfEventLogRecords
    _GetNumberOfEventLogRecords.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.POINTER(ctypes.wintypes.DWORD),
    ]
    _GetNumberOfEventLogRecords.restype = ctypes.wintypes.BOOL


# ══════════════════════════════════════════════════════════════
#  FORENSIC EVENT IDS
# ══════════════════════════════════════════════════════════════

# Well-known forensic event IDs and their descriptions
FORENSIC_EVENT_IDS = {
    # Security log
    4624:  {"desc": "Successful logon",                "severity": "info",     "log": "Security"},
    4625:  {"desc": "Failed logon",                    "severity": "warning",  "log": "Security"},
    4634:  {"desc": "User logoff",                     "severity": "info",     "log": "Security"},
    4648:  {"desc": "Logon using explicit credentials", "severity": "warning", "log": "Security"},
    4672:  {"desc": "Special privileges assigned",     "severity": "info",     "log": "Security"},
    4688:  {"desc": "New process created",             "severity": "info",     "log": "Security"},
    4689:  {"desc": "Process terminated",              "severity": "info",     "log": "Security"},
    4697:  {"desc": "Service installed on system",     "severity": "high",     "log": "Security"},
    4698:  {"desc": "Scheduled task created",          "severity": "high",     "log": "Security"},
    4699:  {"desc": "Scheduled task deleted",          "severity": "warning",  "log": "Security"},
    4720:  {"desc": "User account created",            "severity": "high",     "log": "Security"},
    4722:  {"desc": "User account enabled",            "severity": "warning",  "log": "Security"},
    4723:  {"desc": "Password change attempt",         "severity": "info",     "log": "Security"},
    4724:  {"desc": "Password reset attempt",          "severity": "warning",  "log": "Security"},
    4732:  {"desc": "Member added to local group",     "severity": "high",     "log": "Security"},
    4738:  {"desc": "User account changed",            "severity": "warning",  "log": "Security"},
    4756:  {"desc": "Member added to universal group", "severity": "high",     "log": "Security"},
    1102:  {"desc": "Audit log cleared",               "severity": "critical", "log": "Security"},
    4616:  {"desc": "System time changed",             "severity": "high",     "log": "Security"},
    4657:  {"desc": "Registry value modified",         "severity": "warning",  "log": "Security"},

    # System log
    7034:  {"desc": "Service crashed unexpectedly",    "severity": "warning",  "log": "System"},
    7035:  {"desc": "Service control manager",         "severity": "info",     "log": "System"},
    7036:  {"desc": "Service state changed",           "severity": "info",     "log": "System"},
    7040:  {"desc": "Service start type changed",      "severity": "warning",  "log": "System"},
    7045:  {"desc": "New service installed",           "severity": "high",     "log": "System"},
    1074:  {"desc": "System shutdown/restart",         "severity": "info",     "log": "System"},
    6005:  {"desc": "Event log service started",       "severity": "info",     "log": "System"},
    6006:  {"desc": "Event log service stopped",       "severity": "info",     "log": "System"},
    6008:  {"desc": "Unexpected system shutdown",      "severity": "warning",  "log": "System"},
    104:   {"desc": "Event log cleared",               "severity": "critical", "log": "System"},
}


# ══════════════════════════════════════════════════════════════
#  CORE READING FUNCTIONS
# ══════════════════════════════════════════════════════════════

def read_event_log(log_name="Security", max_events=100, filter_event_ids=None):
    """
    Read events from a Windows Event Log.

    Args:
        log_name:          Name of the log ("Security", "System", "Application")
        max_events:        Maximum number of events to read
        filter_event_ids:  Optional set of event IDs to filter for

    Returns:
        dict with keys:
            events:        list of event dicts
            total_read:    number of events read
            total_records: total records in the log
            log_name:      name of the log read
            error:         error string if something went wrong
    """
    if not EVENTLOG_AVAILABLE:
        return {"error": "Event log reading is only available on Windows."}

    # Open the event log
    handle = _OpenEventLogW(None, log_name)
    if not handle:
        err = ctypes.GetLastError()
        if err == 5:  # ACCESS_DENIED
            return {"error": f"Access denied to {log_name} log. Run as Administrator."}
        return {"error": f"Cannot open {log_name} log (error {err})."}

    try:
        # Get total record count
        total = ctypes.wintypes.DWORD(0)
        _GetNumberOfEventLogRecords(handle, ctypes.byref(total))

        events = []
        buf_size = 65536  # 64 KB buffer
        buf = (ctypes.c_byte * buf_size)()
        bytes_read = ctypes.wintypes.DWORD(0)
        min_bytes = ctypes.wintypes.DWORD(0)

        read_flags = EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ

        while len(events) < max_events:
            success = _ReadEventLogW(
                handle,
                read_flags,
                0,
                ctypes.byref(buf),
                buf_size,
                ctypes.byref(bytes_read),
                ctypes.byref(min_bytes),
            )

            if not success:
                break

            # Parse the buffer
            offset = 0
            raw_bytes = bytes(buf[:bytes_read.value])

            while offset < bytes_read.value and len(events) < max_events:
                try:
                    event = _parse_event_record(raw_bytes, offset)
                    if event is None:
                        break

                    # Apply filter
                    if filter_event_ids is None or event["event_id"] in filter_event_ids:
                        # Add forensic context if known
                        forensic = FORENSIC_EVENT_IDS.get(event["event_id"])
                        if forensic:
                            event["forensic_desc"] = forensic["desc"]
                            event["forensic_severity"] = forensic["severity"]
                        else:
                            event["forensic_desc"] = None
                            event["forensic_severity"] = None

                        events.append(event)

                    offset += event["_record_length"]
                except Exception:
                    break

        return {
            "events":        events,
            "total_read":    len(events),
            "total_records": total.value,
            "log_name":      log_name,
        }

    finally:
        _CloseEventLog(handle)


def read_forensic_events(max_events=50):
    """
    Read only forensic-relevant events across Security and System logs.

    Returns:
        dict with events from both logs, filtered to forensic IDs.
    """
    forensic_ids = set(FORENSIC_EVENT_IDS.keys())

    security = read_event_log("Security", max_events=max_events, filter_event_ids=forensic_ids)
    system = read_event_log("System", max_events=max_events, filter_event_ids=forensic_ids)

    all_events = []
    if "error" not in security:
        all_events.extend(security.get("events", []))
    if "error" not in system:
        all_events.extend(system.get("events", []))

    # Sort by timestamp descending
    all_events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)

    # Severity counts
    severity_counts = {"critical": 0, "high": 0, "warning": 0, "info": 0}
    for ev in all_events:
        sev = ev.get("forensic_severity")
        if sev and sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "events":            all_events[:max_events],
        "total_forensic":    len(all_events),
        "severity_counts":   severity_counts,
        "security_status":   security.get("error", "OK"),
        "system_status":     system.get("error", "OK"),
        "security_total":    security.get("total_records", 0) if "error" not in security else 0,
        "system_total":      system.get("total_records", 0) if "error" not in system else 0,
    }


def get_log_summary():
    """
    Get a high-level summary of event log status.

    Returns:
        dict with record counts for each major log.
    """
    if not EVENTLOG_AVAILABLE:
        return {"error": "Event log reading is only available on Windows."}

    logs = {}
    for log_name in ["Security", "System", "Application"]:
        handle = _OpenEventLogW(None, log_name)
        if handle:
            total = ctypes.wintypes.DWORD(0)
            _GetNumberOfEventLogRecords(handle, ctypes.byref(total))
            logs[log_name] = total.value
            _CloseEventLog(handle)
        else:
            err = ctypes.GetLastError()
            if err == 5:
                logs[log_name] = "Access Denied"
            else:
                logs[log_name] = f"Error ({err})"

    return logs


# ══════════════════════════════════════════════════════════════
#  INTERNAL HELPERS
# ══════════════════════════════════════════════════════════════

def _parse_event_record(data, offset):
    """
    Parse an EVENTLOGRECORD from raw bytes.

    EVENTLOGRECORD fixed header (56 bytes):
        DWORD  Length
        DWORD  Reserved
        DWORD  RecordNumber
        DWORD  TimeGenerated
        DWORD  TimeWritten
        DWORD  EventID
        WORD   EventType
        WORD   NumStrings
        WORD   EventCategory
        WORD   ReservedFlags
        DWORD  ClosingRecordNumber
        DWORD  StringOffset
        DWORD  UserSidLength
        DWORD  UserSidOffset
        DWORD  DataLength
        DWORD  DataOffset
    """
    if offset + 56 > len(data):
        return None

    header = struct.unpack_from("<IIIIIIHHHHI I I I I I", data, offset)
    record_length      = header[0]
    record_number      = header[2]
    time_generated     = header[3]
    time_written       = header[4]
    event_id           = header[5] & 0xFFFF  # Lower 16 bits
    event_type         = header[6]
    num_strings        = header[7]
    event_category     = header[8]
    string_offset      = header[11]
    user_sid_length    = header[12]
    user_sid_offset    = header[13]

    if record_length == 0 or offset + record_length > len(data):
        return None

    # Parse timestamp
    try:
        timestamp = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=time_generated)
        ts_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        ts_str = "N/A"

    # Parse source name (null-terminated wchar string after fixed header)
    source_offset = offset + 56
    source_name = _read_wchar_string(data, source_offset)

    # Parse computer name (after source name + null)
    computer_offset = source_offset + (len(source_name) + 1) * 2
    computer_name = _read_wchar_string(data, computer_offset)

    # Parse event strings
    strings = []
    if num_strings > 0 and string_offset > 0:
        str_pos = offset + string_offset
        for _ in range(min(num_strings, 10)):  # Limit to 10 strings
            if str_pos >= offset + record_length:
                break
            s = _read_wchar_string(data, str_pos)
            strings.append(s)
            str_pos += (len(s) + 1) * 2

    return {
        "_record_length":  record_length,
        "record_number":   record_number,
        "timestamp":       ts_str,
        "event_id":        event_id,
        "event_type":      EVENT_TYPE_NAMES.get(event_type, f"Unknown({event_type})"),
        "event_type_id":   event_type,
        "category":        event_category,
        "source":          source_name,
        "computer":        computer_name,
        "strings":         strings,
    }


def _read_wchar_string(data, offset):
    """Read a null-terminated wide character string from raw bytes."""
    chars = []
    pos = offset
    while pos + 1 < len(data):
        wchar = struct.unpack_from("<H", data, pos)[0]
        if wchar == 0:
            break
        chars.append(chr(wchar))
        pos += 2
    return "".join(chars)
