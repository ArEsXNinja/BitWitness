"""Run full malware analysis on tushar.exe — one-shot script."""
import os, sys

# Ensure we're in the project root
os.chdir(os.path.dirname(os.path.abspath(__file__)))
os.chdir("..")

sys.path.insert(0, "modules")

from hex_engine import check_header, SIGNATURES
from integrity import get_file_hash
from pe_analyzer import analyze_pe, is_pe_file
from strings_extractor import get_strings_summary
from vt_lookup import lookup_hash

file_path = "tushar.exe"
print("=" * 64)
print("  BitWitness v2.0 — Full Static Malware Analysis")
print(f"  Target : {os.path.abspath(file_path)}")
print(f"  Size   : {os.path.getsize(file_path):,} bytes")
print("=" * 64)

# 1. Integrity
print("\n" + "-" * 64)
print("  [MODULE 01] FILE INTEGRITY  —  SHA-256")
print("-" * 64)
h = get_file_hash(file_path)
print(f"  Hash: {h}")

# 2. Header
print("\n" + "-" * 64)
print("  [MODULE 02] HEADER / SIGNATURE ANALYSIS")
print("-" * 64)
hdr = check_header(file_path)
print(f"  Result: {hdr}")
with open(file_path, "rb") as f:
    raw = f.read(16)
print(f"  Raw header: {' '.join(f'{b:02X}' for b in raw)}")

# 3. PE Analysis
print("\n" + "-" * 64)
print("  [MODULE 04] PE STATIC ANALYSIS  —  PESTUDIO-STYLE")
print("-" * 64)
result = analyze_pe(file_path)
if "error" in result:
    print(f"  Error: {result['error']}")
else:
    basic = result["basic"]
    for k, v in basic.items():
        print(f"  {k:>20}: {v}")

    print("\n  -- SECTIONS --")
    print(f"  {'Name':<10} {'VirtSize':>10} {'RawSize':>10} {'Entropy':>8} Flags")
    print(f"  {'-'*10} {'-'*10} {'-'*10} {'-'*8} {'-'*20}")
    for s in result.get("sections", []):
        flags = []
        if s["high_entropy"]:
            flags.append("PACKED?")
        if s["suspicious_name"]:
            flags.append("SUS_NAME")
        print(
            f"  {s['name']:<10} {s['virtual_size']:>10,} "
            f"{s['raw_size']:>10,} {s['entropy']:>8.4f} {' '.join(flags)}"
        )

    imports = result.get("imports", {})
    total_funcs = sum(len(v) for v in imports.values())
    print(f"\n  -- IMPORTS ({len(imports)} DLLs, {total_funcs} functions) --")
    for dll, funcs in imports.items():
        print(f"  {dll} ({len(funcs)} functions)")

    sus = result.get("suspicious_apis", [])
    print(f"\n  -- SUSPICIOUS APIs ({len(sus)}) --")
    if sus:
        for api in sus:
            print(f"  [!] {api['dll']} -> {api['func']}")
    else:
        print("  None detected.")

    print("\n  -- THREAT INDICATORS --")
    for ind in result.get("indicators", []):
        print(f"  [{ind['severity']}] {ind['type']}: {ind['detail']}")

# 4. Strings
print("\n" + "-" * 64)
print("  [MODULE 05] STRINGS EXTRACTION  —  ASCII / UNICODE")
print("-" * 64)
sr = get_strings_summary(file_path, 80)
if "error" not in sr:
    print(f"  Total: {sr['total_count']:,} | ASCII: {sr['ascii_count']:,} | Unicode: {sr['unicode_count']:,}")
    suspicious = sr.get("suspicious", {})
    if suspicious:
        sus_total = sum(len(v) for v in suspicious.values())
        print(f"\n  -- SUSPICIOUS STRINGS ({sus_total}) --")
        for cat, items in suspicious.items():
            print(f"  {cat} ({len(items)} found):")
            for item in items[:8]:
                print(f"    > {item}")
            if len(items) > 8:
                print(f"    ... and {len(items) - 8} more")
    else:
        print("  No suspicious patterns detected.")

# 5. VT Lookup
print("\n" + "-" * 64)
print("  [MODULE 06] VIRUSTOTAL LOOKUP  —  HASH-BASED")
print("-" * 64)
print("  (Only the hash is sent — file is NEVER uploaded)")
vt = lookup_hash(file_path)
status = vt.get("status", "")
if status == "found":
    print(f"  VERDICT      : {vt['verdict']}")
    print(f"  Detection    : {vt['detection_ratio']}")
    print(f"  Threat Label : {vt.get('threat_label', 'N/A')}")
    print(f"  File Type    : {vt.get('file_type', 'N/A')}")
    print(f"  Reputation   : {vt.get('reputation', 'N/A')}")
    dets = vt.get("detections", [])
    if dets:
        print(f"\n  -- ENGINE DETECTIONS ({len(dets)}) --")
        for d in dets[:15]:
            print(f"  {d['engine']:<24} {d['result']}")
        if len(dets) > 15:
            print(f"  ... and {len(dets) - 15} more")
elif status == "not_found":
    print(f"  Hash: {vt.get('file_hash', 'N/A')}")
    print("  File hash not found in VirusTotal database.")
else:
    print(f"  Status: {status}")
    print(f"  {vt.get('error', 'Unknown error')}")

print("\n" + "=" * 64)
print("  Analysis Complete.")
print("=" * 64)
