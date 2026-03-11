#!/usr/bin/env python3
"""
yara_scanner.py — YARA rule scanning with built-in malware detection rules.
Scans files against predefined or custom YARA rules to detect malware patterns.
"""

import os

# Optional: yara-python
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


# ══════════════════════════════════════════════════════════════
#  BUILT-IN YARA RULES
# ══════════════════════════════════════════════════════════════

BUILTIN_RULES_SOURCE = r"""
rule UPX_Packed {
    meta:
        description = "Detects UPX packed executables"
        category = "packer"
        severity = "medium"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
        $upx_sig = { 55 50 58 21 }
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule MPRESS_Packed {
    meta:
        description = "Detects MPRESS packed executables"
        category = "packer"
        severity = "medium"
    strings:
        $mpress1 = ".MPRESS1" ascii
        $mpress2 = ".MPRESS2" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule VMProtect_Packed {
    meta:
        description = "Detects VMProtect protected executables"
        category = "packer"
        severity = "high"
    strings:
        $vmp0 = ".vmp0" ascii
        $vmp1 = ".vmp1" ascii
        $vmprotect = "VMProtect" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Themida_Packed {
    meta:
        description = "Detects Themida/WinLicense protected executables"
        category = "packer"
        severity = "high"
    strings:
        $themida = ".themida" ascii
        $winlice = ".winlice" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Suspicious_PowerShell {
    meta:
        description = "Contains PowerShell execution strings"
        category = "suspicious_command"
        severity = "high"
    strings:
        $ps1 = "powershell" ascii nocase
        $ps2 = "powershell.exe" ascii nocase
        $ps3 = "-EncodedCommand" ascii nocase
        $ps4 = "-ExecutionPolicy Bypass" ascii nocase
        $ps5 = "Invoke-Expression" ascii nocase
        $ps6 = "IEX(" ascii nocase
        $ps7 = "New-Object System.Net.WebClient" ascii nocase
        $ps8 = "DownloadString" ascii nocase
        $ps9 = "DownloadFile" ascii nocase
    condition:
        3 of them
}

rule Suspicious_Shell_Commands {
    meta:
        description = "Contains suspicious shell/system commands"
        category = "suspicious_command"
        severity = "medium"
    strings:
        $cmd1 = "cmd.exe /c" ascii nocase
        $cmd2 = "cmd /c" ascii nocase
        $reg1 = "reg add" ascii nocase
        $reg2 = "reg delete" ascii nocase
        $schtask = "schtasks /create" ascii nocase
        $wmic = "wmic process" ascii nocase
        $certutil = "certutil -decode" ascii nocase
        $bitsadmin = "bitsadmin /transfer" ascii nocase
        $attrib = "attrib +h +s" ascii nocase
    condition:
        2 of them
}

rule Shellcode_Patterns {
    meta:
        description = "Contains common shellcode byte patterns"
        category = "shellcode"
        severity = "critical"
    strings:
        $nop_sled = { 90 90 90 90 90 90 90 90 }
        $int3_sled = { CC CC CC CC CC CC CC CC }
        $shell_x86 = { 31 C0 50 68 }
        $shell_x86_2 = { 68 63 6D 64 00 }
        $shell_x64 = { 48 31 C0 48 89 }
    condition:
        any of them
}

rule Suspicious_Network_Activity {
    meta:
        description = "Contains indicators of network communication"
        category = "network"
        severity = "medium"
    strings:
        $http = "http://" ascii nocase
        $https = "https://" ascii nocase
        $ftp = "ftp://" ascii nocase
        $user_agent = "User-Agent:" ascii nocase
        $wget = "wget " ascii nocase
        $curl = "curl " ascii nocase
        $socket = "WSAStartup" ascii
        $connect = "InternetOpenA" ascii
        $download = "URLDownloadToFile" ascii
    condition:
        3 of them
}

rule Ransomware_Indicators {
    meta:
        description = "Contains potential ransomware indicators"
        category = "ransomware"
        severity = "critical"
    strings:
        $ransom1 = "your files have been encrypted" ascii nocase
        $ransom2 = "bitcoin" ascii nocase
        $ransom3 = "decrypt" ascii nocase
        $ransom4 = ".onion" ascii nocase
        $ransom5 = "pay" ascii nocase
        $ransom6 = "wallet" ascii nocase
        $ext1 = ".encrypted" ascii nocase
        $ext2 = ".locked" ascii nocase
        $ext3 = ".crypto" ascii nocase
        $vss = "vssadmin delete shadows" ascii nocase
        $bcdedit = "bcdedit /set" ascii nocase
        $wbadmin = "wbadmin delete" ascii nocase
    condition:
        ($vss or $bcdedit or $wbadmin) or (4 of ($ransom*)) or (2 of ($ext*) and 2 of ($ransom*))
}

rule Mimikatz_Indicators {
    meta:
        description = "Contains Mimikatz credential theft tool indicators"
        category = "credential_theft"
        severity = "critical"
    strings:
        $mimi1 = "mimikatz" ascii nocase
        $mimi2 = "sekurlsa" ascii nocase
        $mimi3 = "kerberos::list" ascii nocase
        $mimi4 = "privilege::debug" ascii nocase
        $mimi5 = "lsadump" ascii nocase
        $mimi6 = "gentilkiwi" ascii nocase
    condition:
        2 of them
}

rule CobaltStrike_Beacon {
    meta:
        description = "Detects potential Cobalt Strike beacon indicators"
        category = "c2_framework"
        severity = "critical"
    strings:
        $cs1 = "beacon.dll" ascii nocase
        $cs2 = "beacon.x64.dll" ascii nocase
        $cs3 = "%s as %s\\%s: %d" ascii
        $cs4 = "ReflectiveLoader" ascii
        $cs5 = "S-1-5-18" ascii
        $pipe = { 5C 5C 2E 5C 70 69 70 65 5C }
    condition:
        2 of them
}

rule Process_Injection_APIs {
    meta:
        description = "Contains process injection API import pattern"
        category = "injection"
        severity = "high"
    strings:
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "NtCreateThreadEx" ascii
        $api5 = "RtlCreateUserThread" ascii
        $api6 = "QueueUserAPC" ascii
        $api7 = "NtUnmapViewOfSection" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Anti_Debug_Techniques {
    meta:
        description = "Contains anti-debugging technique indicators"
        category = "evasion"
        severity = "high"
    strings:
        $ad1 = "IsDebuggerPresent" ascii
        $ad2 = "CheckRemoteDebuggerPresent" ascii
        $ad3 = "NtQueryInformationProcess" ascii
        $ad4 = "OutputDebugStringA" ascii
        $ad5 = "GetTickCount" ascii
        $ad6 = "QueryPerformanceCounter" ascii
        $ad7 = "FindWindowA" ascii
        $vm1 = "VMware" ascii nocase
        $vm2 = "VirtualBox" ascii nocase
        $vm3 = "QEMU" ascii nocase
        $vm4 = "Sandboxie" ascii nocase
    condition:
        3 of ($ad*) or 2 of ($vm*)
}

rule Persistence_Registry {
    meta:
        description = "Contains Windows registry persistence mechanisms"
        category = "persistence"
        severity = "high"
    strings:
        $run1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        $run2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii nocase
        $srv1 = "SYSTEM\\CurrentControlSet\\Services" ascii nocase
        $task = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule" ascii nocase
        $winlogon = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii nocase
    condition:
        any of them
}

rule Base64_Encoded_PE {
    meta:
        description = "Contains base64-encoded PE file"
        category = "encoded_payload"
        severity = "high"
    strings:
        $b64_mz1 = "TVqQAAMAAAA" ascii
        $b64_mz2 = "TVpQAAIAAAA" ascii
        $b64_mz3 = "TVroAAAAAAA" ascii
        $b64_mz4 = "TVpBRUAAAAA" ascii
    condition:
        any of them
}

rule Suspicious_Strings_Collection {
    meta:
        description = "Contains a collection of suspicious string patterns"
        category = "suspicious_strings"
        severity = "medium"
    strings:
        $s1 = "keylog" ascii nocase
        $s2 = "screenshot" ascii nocase
        $s3 = "webcam" ascii nocase
        $s4 = "clipboard" ascii nocase
        $s5 = "password" ascii nocase
        $s6 = "credential" ascii nocase
        $s7 = "backdoor" ascii nocase
        $s8 = "reverse_shell" ascii nocase
        $s9 = "bind_shell" ascii nocase
    condition:
        3 of them
}

rule Crypto_Mining {
    meta:
        description = "Contains cryptocurrency mining indicators"
        category = "cryptominer"
        severity = "high"
    strings:
        $pool1 = "stratum+tcp://" ascii nocase
        $pool2 = "stratum+ssl://" ascii nocase
        $miner1 = "xmrig" ascii nocase
        $miner2 = "cpuminer" ascii nocase
        $miner3 = "cgminer" ascii nocase
        $miner4 = "ethminer" ascii nocase
        $algo1 = "cryptonight" ascii nocase
        $algo2 = "randomx" ascii nocase
        $wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
    condition:
        2 of them
}
"""


# ══════════════════════════════════════════════════════════════
#  SCANNING FUNCTIONS
# ══════════════════════════════════════════════════════════════

def get_builtin_rules():
    """
    Compile the built-in YARA rules.

    Returns:
        Compiled yara.Rules object, or None if yara-python is not available.
    """
    if not YARA_AVAILABLE:
        return None

    try:
        return yara.compile(source=BUILTIN_RULES_SOURCE)
    except yara.SyntaxError as e:
        return None


def scan_file(file_path, rules_path=None):
    """
    Scan a file with YARA rules.

    Args:
        file_path:  Path to file to scan
        rules_path: Optional path to custom .yar/.yara rules file.
                    If None, uses built-in rules.

    Returns:
        dict with:
            matches: list of match dicts (rule, meta, strings, tags)
            total_matches: int
            severity_summary: dict of severity counts
    """
    if not YARA_AVAILABLE:
        return {
            "error": "yara-python not installed. Run: pip install yara-python",
            "available": False,
        }

    if not os.path.isfile(file_path):
        return {"error": f"File not found: {file_path}"}

    # Compile rules
    try:
        if rules_path and os.path.isfile(rules_path):
            rules = yara.compile(filepath=rules_path)
        else:
            rules = get_builtin_rules()
            if rules is None:
                return {"error": "Failed to compile built-in YARA rules."}
    except Exception as e:
        return {"error": f"YARA compilation error: {e}"}

    # Scan
    try:
        matches = rules.match(file_path, timeout=60)
    except yara.TimeoutError:
        return {"error": "YARA scan timed out (60s limit)."}
    except Exception as e:
        return {"error": f"YARA scan error: {e}"}

    # Parse results
    results = []
    severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for match in matches:
        meta = dict(match.meta) if match.meta else {}
        severity = meta.get("severity", "medium").lower()

        if severity in severity_summary:
            severity_summary[severity] += 1
        else:
            severity_summary["info"] += 1

        # Extract matched strings (limit to avoid huge output)
        # yara-python 4.x uses StringMatch objects with .identifier/.instances
        matched_strings = []
        for string_match in match.strings:
            if len(matched_strings) >= 10:
                break
            identifier = string_match.identifier
            for instance in string_match.instances:
                if len(matched_strings) >= 10:
                    break
                try:
                    data = instance.matched_data
                    display = data.decode("ascii", errors="replace")
                    if len(display) > 60:
                        display = display[:60] + "..."
                except Exception:
                    try:
                        display = instance.matched_data.hex()[:60]
                    except Exception:
                        display = str(instance)[:60]

                matched_strings.append({
                    "offset": f"0x{instance.offset:X}",
                    "identifier": identifier,
                    "data": display,
                })

        results.append({
            "rule": match.rule,
            "description": meta.get("description", "No description"),
            "category": meta.get("category", "unknown"),
            "severity": severity,
            "tags": list(match.tags) if match.tags else [],
            "matched_strings": matched_strings,
        })

    # Sort by severity (critical first)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    results.sort(key=lambda r: severity_order.get(r["severity"], 5))

    return {
        "matches": results,
        "total_matches": len(results),
        "severity_summary": severity_summary,
        "rules_used": "custom" if rules_path else "built-in",
        "available": True,
    }


def get_rule_count():
    """Return the number of built-in YARA rules."""
    # Count 'rule ' definitions in the source
    return BUILTIN_RULES_SOURCE.count("\nrule ")
