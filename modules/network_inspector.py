#!/usr/bin/env python3
"""
network_inspector.py — Active network connection inspector.
Uses Windows API (iphlpapi.dll) via ctypes to enumerate TCP/UDP
connections with owning process information — a forensic netstat.

No external dependencies required — uses only Python standard library.
"""

import os
import sys
import ctypes
import ctypes.wintypes
import socket
import struct

# ══════════════════════════════════════════════════════════════
#  PLATFORM CHECK
# ══════════════════════════════════════════════════════════════

NETWORK_INSPECTOR_AVAILABLE = sys.platform == "win32"


# ══════════════════════════════════════════════════════════════
#  WINDOWS API STRUCTURES & CONSTANTS
# ══════════════════════════════════════════════════════════════

if NETWORK_INSPECTOR_AVAILABLE:
    # Address family
    AF_INET = 2

    # TCP table class — include PID
    TCP_TABLE_OWNER_PID_ALL = 5
    UDP_TABLE_OWNER_PID = 1

    # TCP states
    TCP_STATES = {
        1:  "CLOSED",
        2:  "LISTEN",
        3:  "SYN_SENT",
        4:  "SYN_RCVD",
        5:  "ESTABLISHED",
        6:  "FIN_WAIT1",
        7:  "FIN_WAIT2",
        8:  "CLOSE_WAIT",
        9:  "CLOSING",
        10: "LAST_ACK",
        11: "TIME_WAIT",
        12: "DELETE_TCB",
    }

    class MIB_TCPROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("dwState",      ctypes.wintypes.DWORD),
            ("dwLocalAddr",  ctypes.wintypes.DWORD),
            ("dwLocalPort",  ctypes.wintypes.DWORD),
            ("dwRemoteAddr", ctypes.wintypes.DWORD),
            ("dwRemotePort", ctypes.wintypes.DWORD),
            ("dwOwningPid",  ctypes.wintypes.DWORD),
        ]

    class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("dwNumEntries", ctypes.wintypes.DWORD),
            ("table",        MIB_TCPROW_OWNER_PID * 512),
        ]

    class MIB_UDPROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("dwLocalAddr",  ctypes.wintypes.DWORD),
            ("dwLocalPort",  ctypes.wintypes.DWORD),
            ("dwOwningPid",  ctypes.wintypes.DWORD),
        ]

    class MIB_UDPTABLE_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("dwNumEntries", ctypes.wintypes.DWORD),
            ("table",        MIB_UDPROW_OWNER_PID * 512),
        ]

    # Load iphlpapi
    _iphlpapi = ctypes.windll.iphlpapi

    _GetExtendedTcpTable = _iphlpapi.GetExtendedTcpTable
    _GetExtendedTcpTable.argtypes = [
        ctypes.c_void_p,                  # pTcpTable
        ctypes.POINTER(ctypes.wintypes.DWORD),  # pdwSize
        ctypes.wintypes.BOOL,             # bOrder
        ctypes.wintypes.ULONG,            # ulAf
        ctypes.c_int,                     # TableClass
        ctypes.wintypes.ULONG,            # Reserved
    ]
    _GetExtendedTcpTable.restype = ctypes.wintypes.DWORD

    _GetExtendedUdpTable = _iphlpapi.GetExtendedUdpTable
    _GetExtendedUdpTable.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.wintypes.DWORD),
        ctypes.wintypes.BOOL,
        ctypes.wintypes.ULONG,
        ctypes.c_int,
        ctypes.wintypes.ULONG,
    ]
    _GetExtendedUdpTable.restype = ctypes.wintypes.DWORD

    # For process name lookup
    _kernel32 = ctypes.windll.kernel32

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

    _OpenProcess = _kernel32.OpenProcess
    _OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
    _OpenProcess.restype = ctypes.wintypes.HANDLE

    _QueryFullProcessImageNameW = _kernel32.QueryFullProcessImageNameW
    _QueryFullProcessImageNameW.argtypes = [
        ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD,
        ctypes.wintypes.LPWSTR, ctypes.POINTER(ctypes.wintypes.DWORD),
    ]
    _QueryFullProcessImageNameW.restype = ctypes.wintypes.BOOL

    _CloseHandle = _kernel32.CloseHandle


# ══════════════════════════════════════════════════════════════
#  SUSPICIOUS PORT / CONNECTION INDICATORS
# ══════════════════════════════════════════════════════════════

# Ports commonly associated with malware / C2 communication
SUSPICIOUS_PORTS = {
    4444:  "Metasploit default",
    5555:  "Common backdoor",
    1234:  "Common backdoor",
    1337:  "Common backdoor (leet)",
    31337: "Back Orifice",
    6666:  "IRC / trojan",
    6667:  "IRC C2",
    6668:  "IRC C2",
    6669:  "IRC C2",
    8080:  "HTTP proxy / C2",
    8443:  "HTTPS alt / C2",
    9090:  "Common C2",
    3389:  "RDP (verify if expected)",
    5900:  "VNC",
    5901:  "VNC",
    4443:  "Common C2",
    8888:  "Common C2",
    12345: "NetBus trojan",
    54321: "Back Orifice 2000",
    65535: "Suspicious high port",
}


# ══════════════════════════════════════════════════════════════
#  CORE INSPECTION FUNCTIONS
# ══════════════════════════════════════════════════════════════

def get_tcp_connections():
    """
    Get all active TCP connections with owning process info.

    Returns:
        dict with keys:
            connections:       list of connection dicts
            total:             total connections
            established:       count of ESTABLISHED connections
            listening:         count of LISTEN connections
            suspicious:        list of flagged connections
            suspicious_count:  count of flagged connections
    """
    if not NETWORK_INSPECTOR_AVAILABLE:
        return {"error": "Network inspection is only available on Windows."}

    try:
        connections = _enum_tcp_connections()
    except Exception as e:
        return {"error": f"Failed to enumerate TCP connections: {e}"}

    # Process name cache
    pid_name_cache = {}

    suspicious = []
    established_count = 0
    listening_count = 0

    for conn in connections:
        pid = conn["pid"]
        if pid not in pid_name_cache:
            pid_name_cache[pid] = _get_process_name(pid)
        conn["process_name"] = pid_name_cache[pid]

        if conn["state"] == "ESTABLISHED":
            established_count += 1
        elif conn["state"] == "LISTEN":
            listening_count += 1

        # Check for suspicious indicators
        reasons = _check_connection_suspicious(conn)
        conn["suspicious"] = len(reasons) > 0
        conn["reasons"] = reasons
        if conn["suspicious"]:
            suspicious.append(conn)

    return {
        "connections":      connections,
        "total":            len(connections),
        "established":      established_count,
        "listening":        listening_count,
        "suspicious":       suspicious,
        "suspicious_count": len(suspicious),
    }


def get_udp_endpoints():
    """
    Get all active UDP endpoints with owning process info.

    Returns:
        dict with keys:
            endpoints:         list of endpoint dicts
            total:             total endpoints
            suspicious:        list of flagged endpoints
            suspicious_count:  count of flagged
    """
    if not NETWORK_INSPECTOR_AVAILABLE:
        return {"error": "Network inspection is only available on Windows."}

    try:
        endpoints = _enum_udp_endpoints()
    except Exception as e:
        return {"error": f"Failed to enumerate UDP endpoints: {e}"}

    pid_name_cache = {}
    suspicious = []

    for ep in endpoints:
        pid = ep["pid"]
        if pid not in pid_name_cache:
            pid_name_cache[pid] = _get_process_name(pid)
        ep["process_name"] = pid_name_cache[pid]

        # Check suspicious
        reasons = []
        local_port = ep.get("local_port", 0)
        if local_port in SUSPICIOUS_PORTS:
            reasons.append(f"Suspicious port {local_port}: {SUSPICIOUS_PORTS[local_port]}")
        ep["suspicious"] = len(reasons) > 0
        ep["reasons"] = reasons
        if ep["suspicious"]:
            suspicious.append(ep)

    return {
        "endpoints":       endpoints,
        "total":           len(endpoints),
        "suspicious":      suspicious,
        "suspicious_count": len(suspicious),
    }


def get_full_network_snapshot():
    """
    Get a complete snapshot of all TCP and UDP connections.

    Returns:
        dict combining TCP and UDP results.
    """
    tcp = get_tcp_connections()
    udp = get_udp_endpoints()

    if "error" in tcp:
        return tcp
    if "error" in udp:
        return udp

    all_suspicious = tcp.get("suspicious", []) + udp.get("suspicious", [])

    return {
        "tcp": tcp,
        "udp": udp,
        "total_connections":   tcp["total"] + udp["total"],
        "total_suspicious":    len(all_suspicious),
        "all_suspicious":      all_suspicious,
    }


# ══════════════════════════════════════════════════════════════
#  INTERNAL HELPERS
# ══════════════════════════════════════════════════════════════

def _enum_tcp_connections():
    """Enumerate TCP connections using GetExtendedTcpTable."""
    connections = []

    # First call to get required buffer size
    size = ctypes.wintypes.DWORD(0)
    _GetExtendedTcpTable(None, ctypes.byref(size), True, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)

    # Allocate buffer
    buf = (ctypes.c_byte * size.value)()
    ret = _GetExtendedTcpTable(ctypes.byref(buf), ctypes.byref(size), True, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)

    if ret != 0:
        return connections

    # Parse the table
    table = ctypes.cast(buf, ctypes.POINTER(MIB_TCPTABLE_OWNER_PID)).contents
    num_entries = table.dwNumEntries

    for i in range(min(num_entries, 512)):
        row = table.table[i]
        connections.append({
            "local_addr":   _ip_to_str(row.dwLocalAddr),
            "local_port":   socket.ntohs(row.dwLocalPort & 0xFFFF),
            "remote_addr":  _ip_to_str(row.dwRemoteAddr),
            "remote_port":  socket.ntohs(row.dwRemotePort & 0xFFFF),
            "state":        TCP_STATES.get(row.dwState, f"UNKNOWN({row.dwState})"),
            "pid":          row.dwOwningPid,
            "protocol":     "TCP",
        })

    return connections


def _enum_udp_endpoints():
    """Enumerate UDP endpoints using GetExtendedUdpTable."""
    endpoints = []

    size = ctypes.wintypes.DWORD(0)
    _GetExtendedUdpTable(None, ctypes.byref(size), True, AF_INET, UDP_TABLE_OWNER_PID, 0)

    buf = (ctypes.c_byte * size.value)()
    ret = _GetExtendedUdpTable(ctypes.byref(buf), ctypes.byref(size), True, AF_INET, UDP_TABLE_OWNER_PID, 0)

    if ret != 0:
        return endpoints

    table = ctypes.cast(buf, ctypes.POINTER(MIB_UDPTABLE_OWNER_PID)).contents
    num_entries = table.dwNumEntries

    for i in range(min(num_entries, 512)):
        row = table.table[i]
        endpoints.append({
            "local_addr":  _ip_to_str(row.dwLocalAddr),
            "local_port":  socket.ntohs(row.dwLocalPort & 0xFFFF),
            "pid":         row.dwOwningPid,
            "protocol":    "UDP",
        })

    return endpoints


def _ip_to_str(addr):
    """Convert a DWORD IP address to dotted string."""
    return socket.inet_ntoa(struct.pack("<I", addr))


def _get_process_name(pid):
    """Get process name from PID."""
    if pid == 0:
        return "System Idle Process"
    if pid == 4:
        return "System"

    handle = _OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return f"PID:{pid}"

    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = ctypes.wintypes.DWORD(1024)
        if _QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return os.path.basename(buf.value)
    finally:
        _CloseHandle(handle)

    return f"PID:{pid}"


def _check_connection_suspicious(conn):
    """Check if a TCP connection has suspicious indicators."""
    reasons = []

    remote_port = conn.get("remote_port", 0)
    local_port = conn.get("local_port", 0)
    remote_addr = conn.get("remote_addr", "")
    state = conn.get("state", "")

    # Check suspicious ports
    if remote_port in SUSPICIOUS_PORTS:
        reasons.append(f"Suspicious remote port {remote_port}: {SUSPICIOUS_PORTS[remote_port]}")
    if local_port in SUSPICIOUS_PORTS:
        reasons.append(f"Suspicious local port {local_port}: {SUSPICIOUS_PORTS[local_port]}")

    # Established connections to external IPs are notable
    if state == "ESTABLISHED" and remote_addr not in ("0.0.0.0", "127.0.0.1"):
        # Check if private or public
        if not _is_private_ip(remote_addr):
            reasons.append(f"ESTABLISHED to external IP: {remote_addr}")

    return reasons


def _is_private_ip(ip):
    """Check if an IP address is private/reserved."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False

    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return True
    if a == 0:
        return True
    return False
