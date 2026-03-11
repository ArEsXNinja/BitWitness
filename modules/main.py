#!/usr/bin/env python3
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  BitWitness  —  Digital Forensics & Evidence Analysis Framework
#  Author : Rohit
#  Version: 4.0.0
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import os
import sys
import time
import random
import datetime
import itertools
import threading

from hex_engine import (check_header, identify_file_type, SIGNATURES,
                        hex_dump, hex_dump_string, get_file_entropy,
                        get_entropy_verdict)
from imaging import create_image
from integrity import get_file_hash, get_all_hashes, get_fuzzy_hash, SSDEEP_AVAILABLE
from pe_analyzer import analyze_pe, is_pe_file, PEFILE_AVAILABLE
from strings_extractor import get_strings_summary
from vt_lookup import lookup_hash
from metadata_extractor import get_file_metadata, get_exif_data, get_pe_metadata
from yara_scanner import scan_file as yara_scan_file, get_rule_count, YARA_AVAILABLE
from report_generator import (generate_html_report, generate_json_report,
                               generate_pdf_report, generate_summary,
                               calculate_risk_score, get_risk_verdict)
from ads_scanner import scan_ads, extract_ads, scan_directory_ads, ADS_AVAILABLE
from process_analyzer import (enumerate_processes, get_process_summary,
                              PROCESS_ANALYZER_AVAILABLE)
from network_inspector import (get_tcp_connections, get_udp_endpoints,
                               get_full_network_snapshot,
                               NETWORK_INSPECTOR_AVAILABLE)
from sig_verifier import verify_signature, SIG_VERIFIER_AVAILABLE
from eventlog_reader import (read_event_log, read_forensic_events,
                             get_log_summary, EVENTLOG_AVAILABLE,
                             FORENSIC_EVENT_IDS)


# ══════════════════════════════════════════════════════════════
#  ANSI COLOUR PALETTE
# ══════════════════════════════════════════════════════════════
class C:
    # ── base ──
    RST   = "\033[0m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"
    ITAL  = "\033[3m"
    ULINE = "\033[4m"
    BLINK = "\033[5m"

    # ── foreground ──
    BLK = "\033[30m";  RED   = "\033[91m";  GRN  = "\033[92m"
    YEL = "\033[93m";  BLU   = "\033[94m";  MAG  = "\033[95m"
    CYN = "\033[96m";  WHT   = "\033[97m";  GRY  = "\033[90m"

    # ── custom 256-colour ──
    ORANGE = "\033[38;5;208m"
    LIME   = "\033[38;5;118m"
    PINK   = "\033[38;5;205m"
    SKY    = "\033[38;5;117m"
    GOLD   = "\033[38;5;220m"
    VIOLET = "\033[38;5;135m"


# ══════════════════════════════════════════════════════════════
#  ASCII ART BANNERS  (randomised per launch)
# ══════════════════════════════════════════════════════════════
BANNERS = [
    # ── Banner 1: Classic block letters ──
    C.RED + C.BOLD + r"""
     ______  _ _   _    _  _ _
     | ___ \(_) | | |  | |(_) |
     | |_/ / _| |_| |  | | _| |_ _ __   ___  ___ ___
     | ___ \| | __| |/\| || | __| '_ \ / _ \/ __/ __|
     | |_/ /| | |_\  /\  /| | |_| | | |  __/\__ \__ \
     \____/ |_|\__|/  \/ |_|\__|_| |_|\___||___/___/""" + C.RST,

    # ── Banner 2: Slant ──
    C.CYN + C.BOLD + r"""
       ____  _ __  _       __ _ __
      / __ )(_) /_| |     / /(_) /_____  ___  __________
     / __  / / __/ | /| / / / / __/ __ \/ _ \/ ___/ ___/
    / /_/ / / /_ |  |/ |/ / / / /_/ / / /  __(__  |__  )
   /_____/_/\__/ |__/|_/_/_/\__/_/ /_/\___/____/____/
""" + C.RST,

    # ── Banner 3: Sharp angular ──
    C.GRN + C.BOLD + r"""
     ___  ___ _____ _ _ _ ___ _____ _  _ ___ ___ ___
    | _ )|_ _|_   _| | | |_ _|_   _| \| | __/ __/ __|
    | _ \ | |  | | | | | || |  | | | .` | _|\__ \__ \
    |___/___|  |_| |_____|___| |_| |_|\_|___|___/___/""" + C.RST,

    # ── Banner 4: Big ASCII ──
    C.GOLD + C.BOLD + r"""
     ____  _ _    __        _____ _____ _   _ _____ ____ ____
    | __ )(_) |_  \ \      / /_ _|_   _| \ | | ____/ ___/ ___|
    |  _ \| | __| \ \ /\ / / | |  | | |  \| |  _| \___ \___ \
    | |_) | | |_  |\ V  V /  | |  | | | |\  | |___ ___) ___) |
    |____/|_|\__| | \_/\_/  |___| |_| |_| \_|_____|____/____/
""" + C.RST,
]

QUOTES = [
    "Every contact leaves a trace.  — Locard's Exchange Principle",
    "The best evidence is digital evidence — if you know where to look.",
    "In forensics, we trust the hash.",
    "A byte saved is a byte earned.",
    "Truth is found in the bits and bytes.",
    "Data doesn't lie. People do.",
    "Evidence speaks louder than alibis.",
]

# ══════════════════════════════════════════════════════════════
#  UI HELPERS
# ══════════════════════════════════════════════════════════════

def enable_ansi():
    """Enable VT100 escape sequences on Windows."""
    os.system("")
    if sys.platform == "win32":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            pass


def typewriter(text, speed=0.012):
    """Print text with a typing animation."""
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(speed)
    print()


def spinner_task(message, func, *args, **kwargs):
    """Run *func* in a thread while showing a spinner."""
    result = [None]
    error  = [None]
    done   = threading.Event()

    def worker():
        try:
            result[0] = func(*args, **kwargs)
        except Exception as e:
            error[0] = e
        finally:
            done.set()

    t = threading.Thread(target=worker, daemon=True)
    t.start()

    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    idx = 0
    while not done.is_set():
        frame = f"{C.CYN}{frames[idx % len(frames)]}{C.RST}"
        sys.stdout.write(f"\r  {frame} {C.DIM}{message}{C.RST}  ")
        sys.stdout.flush()
        idx += 1
        time.sleep(0.08)

    sys.stdout.write("\r" + " " * (len(message) + 12) + "\r")
    sys.stdout.flush()

    if error[0]:
        raise error[0]
    return result[0]


def progress_bar(current, total, width=40, label=""):
    """Print an inline progress bar."""
    pct   = current / total if total else 0
    filled = int(width * pct)
    bar   = f"{C.GRN}{'█' * filled}{C.DIM}{'░' * (width - filled)}{C.RST}"
    sys.stdout.write(f"\r  {bar} {C.WHT}{pct*100:5.1f}%{C.RST}  {C.DIM}{label}{C.RST}")
    sys.stdout.flush()
    if current == total:
        print()


# ── Styled output ────────────────────────────────────────────

def line(char="─", width=64):
    print(f"  {C.DIM}{char * width}{C.RST}")

def info(msg):
    print(f"  {C.DIM}[{C.RST}{C.BLU}ℹ{C.RST}{C.DIM}]{C.RST}  {msg}")

def success(msg):
    print(f"  {C.DIM}[{C.RST}{C.GRN}✓{C.RST}{C.DIM}]{C.RST}  {msg}")

def warn(msg):
    print(f"  {C.DIM}[{C.RST}{C.YEL}⚠{C.RST}{C.DIM}]{C.RST}  {msg}")

def fail(msg):
    print(f"  {C.DIM}[{C.RST}{C.RED}✗{C.RST}{C.DIM}]{C.RST}  {msg}")

def bullet(key, val):
    print(f"  {C.DIM}│{C.RST}  {C.GOLD}{key:>16}{C.RST}  {C.DIM}:{C.RST}  {C.WHT}{val}{C.RST}")

def prompt(text):
    try:
        return input(f"\n  {C.BOLD}{C.CYN}BitWitness{C.RST}{C.DIM}({C.RST}{C.RED}forensics{C.RST}{C.DIM}){C.RST}{C.YEL} ❯ {C.RST}{text}").strip().strip('"').strip("'")
    except (KeyboardInterrupt, EOFError):
        print(f"\n\n  {C.DIM}[{C.RST}{C.YEL}!{C.RST}{C.DIM}]{C.RST}  Session terminated by user.\n")
        sys.exit(0)


def section_header(number, title, icon=""):
    print(f"\n  {C.BOLD}{C.WHT}{'━' * 64}{C.RST}")
    print(f"  {C.BOLD}{C.ORANGE}  {icon}  MODULE {number}  │  {title}{C.RST}")
    print(f"  {C.BOLD}{C.WHT}{'━' * 64}{C.RST}")


def table_row(label, value, color=C.WHT):
    print(f"  {C.DIM}│{C.RST}  {C.GRY}{label:<22}{C.RST} {color}{value}{C.RST}")


# ══════════════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════════════

def print_banner():
    enable_ansi()
    print()
    art = random.choice(BANNERS)
    print(art)
    print()
    line("━")
    print(f"  {C.BOLD}{C.WHT}  ◉  Digital Forensics & Evidence Analysis Framework{C.RST}")
    line("━")
    print()

    bullet("Version",  "4.0.0")
    bullet("Build",    datetime.datetime.now().strftime("%Y-%m-%d"))
    bullet("Platform", f"{sys.platform} / Python {sys.version.split()[0]}")

    # Module status
    mod_parts = [
        f"{C.GRN}hex_engine{C.RST}",
        f"{C.CYN}imaging{C.RST}",
        f"{C.YEL}integrity{C.RST}",
        f"{C.RED}pe_analyzer{C.RST}",
        f"{C.MAG}strings{C.RST}",
        f"{C.ORANGE}vt_lookup{C.RST}",
        f"{C.SKY}metadata{C.RST}",
        f"{C.VIOLET}yara{C.RST}",
        f"{C.PINK}reports{C.RST}",
        f"{C.LIME}ads_scan{C.RST}",
        f"{C.GOLD}proc_analyzer{C.RST}",
        f"{C.CYN}net_inspector{C.RST}",
        f"{C.RED}sig_verify{C.RST}",
        f"{C.SKY}eventlog{C.RST}",
    ]
    bullet("Modules",  f" {C.DIM}|{C.RST} ".join(mod_parts))

    # Feature flags
    flags = []
    flags.append(f"{C.GRN}pefile ✓{C.RST}" if PEFILE_AVAILABLE else f"{C.RED}pefile ✗{C.RST}")
    flags.append(f"{C.GRN}yara ✓{C.RST}" if YARA_AVAILABLE else f"{C.YEL}yara ✗{C.RST}")
    flags.append(f"{C.GRN}ssdeep ✓{C.RST}" if SSDEEP_AVAILABLE else f"{C.YEL}ssdeep ✗{C.RST}")
    flags.append(f"{C.GRN}WinAPI ✓{C.RST}" if ADS_AVAILABLE else f"{C.YEL}WinAPI ✗{C.RST}")
    bullet("Libraries", "  ".join(flags))
    bullet("Author",   "Rohit")

    print()
    line("─")
    quote = random.choice(QUOTES)
    print(f"  {C.DIM}{C.ITAL}  \"{quote}\"{C.RST}")
    line("─")
    print(f"  {C.RED}{C.BOLD}  ⚠  Authorized forensic investigations only.{C.RST}")
    line("─")
    print()


# ══════════════════════════════════════════════════════════════
#  INTERACTIVE MENU
# ══════════════════════════════════════════════════════════════

def show_menu():
    print(f"""
  {C.BOLD}{C.WHT}+──────────────────────────────────────────────────────────────+{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}  {C.ORANGE}{C.BOLD}SELECT OPERATION MODE{C.RST}                                       {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}+──────────────────────────────────────────────────────────────+{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}                                                              {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}  {C.DIM}─── FORENSIC ANALYSIS ───{C.RST}                                   {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}   {C.GRN}[1]{C.RST}   {C.WHT}Full Forensic Analysis{C.RST}    {C.DIM}hash+header+meta+imaging{C.RST}   {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}   {C.CYN}[2]{C.RST}   {C.WHT}Integrity Check{C.RST}          {C.DIM}MD5/SHA-1/SHA-256/SHA-512{C.RST}  {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}   {C.YEL}[3]{C.RST}   {C.WHT}Header + Hex Dump{C.RST}        {C.DIM}magic bytes + hex viewer{C.RST}   {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}   {C.MAG}[4]{C.RST}   {C.WHT}Forensic Imaging{C.RST}         {C.DIM}bit-for-bit copy{C.RST}          {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}   {C.SKY}[5]{C.RST}   {C.WHT}Metadata Extraction{C.RST}      {C.DIM}timestamps+EXIF+properties{C.RST}{C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}                                                              {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}  {C.DIM}─── MALWARE ANALYSIS ───{C.RST}                                    {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}   {C.RED}[6]{C.RST}   {C.WHT}Full Malware Analysis{C.RST}     {C.DIM}PE+strings+YARA+VT{C.RST}        {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}   {C.ORANGE}[7]{C.RST}   {C.WHT}PE Static Analysis{C.RST}       {C.DIM}headers+imports+overlay+res{C.RST}{C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}   {C.VIOLET}[8]{C.RST}   {C.WHT}Strings Extraction{C.RST}       {C.DIM}ASCII/Unicode strings{C.RST}      {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}   {C.PINK}[9]{C.RST}   {C.WHT}YARA Scan{C.RST}                {C.DIM}rule-based malware detect{C.RST}  {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}   {C.LIME}[10]{C.RST}  {C.WHT}VirusTotal Lookup{C.RST}        {C.DIM}hash-based VT check{C.RST}        {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}                                                              {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}  {C.DIM}─── REPORTING ───{C.RST}                                           {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}   {C.GOLD}[11]{C.RST}  {C.WHT}Generate Report{C.RST}          {C.DIM}HTML/JSON/PDF export{C.RST}       {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}                                                              {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}  {C.DIM}─── WINDOWS FORENSICS ───{C.RST}                                  {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}   {C.LIME}[12]{C.RST}  {C.WHT}ADS Scanner{C.RST}              {C.DIM}hidden NTFS streams{C.RST}        {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}   {C.GOLD}[13]{C.RST}  {C.WHT}Process Analyzer{C.RST}         {C.DIM}running process audit{C.RST}      {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}   {C.CYN}[14]{C.RST}  {C.WHT}Network Inspector{C.RST}        {C.DIM}active connections+PIDs{C.RST}    {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}   {C.RED}[15]{C.RST}  {C.WHT}Signature Verifier{C.RST}       {C.DIM}Authenticode check{C.RST}        {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}   {C.SKY}[16]{C.RST}  {C.WHT}Event Log Reader{C.RST}         {C.DIM}security/system events{C.RST}    {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}                                                              {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}   {C.GRY}[0]{C.RST}   {C.WHT}Exit{C.RST}                                                   {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}│{C.RST}                                                              {C.BOLD}{C.WHT}│{C.RST}
  {C.BOLD}{C.WHT}+──────────────────────────────────────────────────────────────+{C.RST}""")


# ══════════════════════════════════════════════════════════════
#  CORE ANALYSIS ROUTINES
# ══════════════════════════════════════════════════════════════

def get_target_file():
    file_path = prompt("Target file path: ")
    if not os.path.isfile(file_path):
        fail(f"File not found → {C.RED}{file_path}{C.RST}")
        return None
    return file_path


def show_file_info(file_path):
    abs_path = os.path.abspath(file_path)
    size     = os.path.getsize(file_path)
    mod_time = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))

    print(f"\n  {C.BOLD}{C.WHT}{'━' * 64}{C.RST}")
    print(f"  {C.BOLD}{C.ORANGE}  🎯  TARGET ACQUIRED{C.RST}")
    print(f"  {C.BOLD}{C.WHT}{'━' * 64}{C.RST}")
    table_row("File",          os.path.basename(file_path))
    table_row("Full Path",     abs_path)
    table_row("Size",          f"{size:,} bytes  ({size/1024:.2f} KB)")
    table_row("Last Modified", mod_time.strftime("%Y-%m-%d %H:%M:%S"))
    table_row("Extension",     os.path.splitext(file_path)[1] or "N/A")
    print(f"  {C.DIM}│{C.RST}")


# ── Module 01: Integrity ─────────────────────────────────────

def run_integrity(file_path):
    section_header("01", "FILE INTEGRITY  ·  MULTI-HASH", "🔒")

    hashes = spinner_task("Computing file hashes…", get_all_hashes, file_path)

    if "error" in hashes:
        fail(hashes["error"])
        return None

    for algo in ["md5", "sha1", "sha256", "sha512"]:
        color = C.LIME if algo == "sha256" else C.WHT
        success(f"{algo.upper():<8} : {color}{hashes[algo]}{C.RST}")

    # Fuzzy hash
    fuzzy = get_fuzzy_hash(file_path)
    if fuzzy:
        success(f"{'ssdeep':<8} : {C.SKY}{fuzzy}{C.RST}")
    elif not SSDEEP_AVAILABLE:
        info(f"{'ssdeep':<8} : {C.DIM}not installed (pip install ssdeep){C.RST}")

    return hashes


# ── Module 02: Header Analysis + Hex Dump ────────────────────

def run_header_analysis(file_path, show_hex=True):
    section_header("02", "HEADER / SIGNATURE ANALYSIS  ·  MAGIC BYTES", "🔎")
    result = spinner_task("Reading file header…", check_header, file_path)

    # Show raw hex of first 16 bytes
    try:
        with open(file_path, "rb") as f:
            raw = f.read(16)
        hex_dump_str = " ".join(f"{b:02X}" for b in raw)
        info(f"Raw header : {C.DIM}{hex_dump_str}{C.RST}")
    except Exception:
        pass

    # File type identification (enhanced)
    types = identify_file_type(file_path)
    for t in types:
        confidence_color = C.GRN if t["confidence"] == "HIGH" else C.YEL if t["confidence"] == "MEDIUM" else C.RED
        info(f"Detected   : {C.WHT}{t['type']}{C.RST}  {C.DIM}[{C.RST}{confidence_color}{t['confidence']}{C.RST}{C.DIM}]{C.RST}")

    # File entropy
    entropy = spinner_task("Computing file entropy…", get_file_entropy, file_path)
    if isinstance(entropy, float) and entropy >= 0:
        verdict = get_entropy_verdict(entropy)
        ent_color = C.RED if entropy > 7.0 else C.YEL if entropy > 6.0 else C.GRN
        info(f"Entropy    : {ent_color}{entropy:.4f}{C.RST}  {C.DIM}— {verdict}{C.RST}")

    # Signature count
    info(f"Known sigs : {C.WHT}{len(SIGNATURES)}{C.RST} file signatures in database")

    if "UNKNOWN" in result or "CORRUPT" in result:
        warn(f"Verdict    : {C.YEL}{result}{C.RST}")
    else:
        success(f"Verdict    : {C.GRN}{result}{C.RST}")

    # Hex dump viewer
    if show_hex:
        print(f"\n  {C.BOLD}{C.WHT}  ── HEX DUMP (first 256 bytes) ──{C.RST}")
        print(f"  {C.DIM}  Offset    │ Hex{'':49s} │ ASCII{C.RST}")
        print(f"  {C.DIM}  {'─'*10}┼{'─'*52}┼{'─'*17}{C.RST}")
        dump = hex_dump(file_path, 0, 256)
        for dl in dump:
            print(f"  {C.CYN}  {dl['offset']}{C.RST}  │ {C.WHT}{dl['hex']}{C.RST}  │ {C.GRN}{dl['ascii']}{C.RST}")

    return result


# ── Module 03: Forensic Imaging ──────────────────────────────

def run_forensic_imaging(file_path, original_hash=None):
    section_header("03", "FORENSIC IMAGING  ·  BIT-FOR-BIT COPY", "💾")

    dest = prompt("Destination path for forensic copy: ")
    if not dest:
        info("Imaging skipped — no destination provided.")
        return

    if os.path.isdir(dest):
        base = os.path.basename(file_path)
        name, ext = os.path.splitext(base)
        dest = os.path.join(dest, f"{name}_forensic_copy{ext}")
        info(f"Auto-named → {C.WHT}{dest}{C.RST}")

    info("Creating forensic image…")

    src_size = os.path.getsize(file_path)
    chunk    = 4096
    copied   = 0
    try:
        with open(file_path, "rb") as fsrc, open(dest, "wb") as fdst:
            while True:
                buf = fsrc.read(chunk)
                if not buf:
                    break
                fdst.write(buf)
                copied += len(buf)
                progress_bar(copied, src_size, label="copying…")
    except Exception as e:
        fail(f"Imaging failed → {e}")
        return

    success(f"Image saved → {C.WHT}{os.path.abspath(dest)}{C.RST}")
    success(f"Bytes copied → {C.WHT}{copied:,}{C.RST}")

    # Verify integrity
    info("Verifying copy integrity…")
    copy_hash = spinner_task("Hashing forensic copy…", get_file_hash, dest)

    if original_hash is None:
        original_hash = spinner_task("Hashing original…", get_file_hash, file_path)

    table_row("Original hash", original_hash, C.LIME)
    table_row("Copy hash",     copy_hash, C.LIME)

    if copy_hash == original_hash:
        print()
        print(f"  {C.BOLD}{C.GRN}  ██████████████████████████████████████████████████████{C.RST}")
        print(f"  {C.BOLD}{C.GRN}  ██  ✓  INTEGRITY VERIFIED  —  HASHES MATCH          ██{C.RST}")
        print(f"  {C.BOLD}{C.GRN}  ██████████████████████████████████████████████████████{C.RST}")
    else:
        print()
        print(f"  {C.BOLD}{C.RED}  ██████████████████████████████████████████████████████{C.RST}")
        print(f"  {C.BOLD}{C.RED}  ██  ✗  ALERT — HASHES DO NOT MATCH!                 ██{C.RST}")
        print(f"  {C.BOLD}{C.RED}  ██████████████████████████████████████████████████████{C.RST}")


# ── Module 04: Metadata Extraction ───────────────────────────

def run_metadata(file_path):
    section_header("04", "METADATA EXTRACTION  ·  FILE PROPERTIES", "📋")

    # File system metadata
    meta = spinner_task("Extracting file metadata…", get_file_metadata, file_path)
    if "error" in meta:
        fail(meta["error"])
        return meta

    print(f"\n  {C.BOLD}{C.WHT}  ── FILE SYSTEM PROPERTIES ──{C.RST}")
    table_row("Created",       meta.get("created", "N/A"))
    table_row("Modified",      meta.get("modified", "N/A"))
    table_row("Accessed",      meta.get("accessed", "N/A"))
    table_row("Permissions",   meta.get("permissions", "N/A"))
    table_row("Hidden",        str(meta.get("is_hidden", False)))
    table_row("Read-only",     str(meta.get("is_readonly", False)))
    table_row("Symlink",       str(meta.get("is_symlink", False)))

    # EXIF data (for images)
    exif = get_exif_data(file_path)
    if exif.get("available"):
        print(f"\n  {C.BOLD}{C.WHT}  ── EXIF DATA ({exif.get('tag_count', 0)} tags) ──{C.RST}")
        summary = exif.get("summary", {})
        for key, val in summary.items():
            table_row(key, str(val)[:60])

        gps = exif.get("gps", {})
        if gps:
            print(f"\n  {C.BOLD}{C.RED}  ⚠ GPS LOCATION DATA FOUND{C.RST}")
            for key, val in gps.items():
                table_row(f"GPS.{key}", str(val)[:60])

    # PE version info
    pe_meta = get_pe_metadata(file_path)
    if pe_meta.get("available"):
        print(f"\n  {C.BOLD}{C.WHT}  ── PE VERSION INFO ──{C.RST}")
        for key, val in pe_meta["version_info"].items():
            table_row(key, str(val)[:60])

    return meta


# ══════════════════════════════════════════════════════════════
#  MALWARE ANALYSIS DISPLAY ROUTINES
# ══════════════════════════════════════════════════════════════

def run_pe_analysis(file_path):
    """Run PE static analysis and display results."""
    section_header("05", "PE STATIC ANALYSIS  ·  PESTUDIO-STYLE", "⚙️")

    if not PEFILE_AVAILABLE:
        fail(f"pefile library not installed. Run: {C.WHT}pip install pefile{C.RST}")
        return None

    if not is_pe_file(file_path):
        warn("Not a PE (Portable Executable) file. Skipping PE analysis.")
        return None

    result = spinner_task("Parsing PE structure...", analyze_pe, file_path)

    if "error" in result:
        fail(result["error"])
        return None

    # ── Basic info ──
    basic = result["basic"]
    print(f"\n  {C.BOLD}{C.WHT}  ── PE HEADER INFO ──{C.RST}")
    table_row("PE Type",        basic.get("pe_type", "N/A"))
    table_row("Machine",        basic.get("machine", "N/A"))
    table_row("Compile Time",   basic.get("compile_time", "N/A"))
    table_row("Entry Point",    basic.get("entry_point", "N/A"))
    table_row("Image Base",     basic.get("image_base", "N/A"))
    table_row("Subsystem",      basic.get("subsystem", "N/A"))
    table_row("Characteristics",basic.get("characteristics", "N/A"))
    table_row("Sections",       str(basic.get("num_sections", "N/A")))

    # Imphash
    imphash = result.get("imphash")
    if imphash:
        table_row("Imphash",   f"{C.VIOLET}{imphash}{C.RST}")

    # Digital signature
    sig = result.get("digital_signature", {})
    sig_color = C.GRN if sig.get("signed") else C.YEL
    table_row("Digital Sig",    f"{sig_color}{sig.get('detail', 'N/A')}{C.RST}")

    # ── Sections ──
    sections = result.get("sections", [])
    if sections:
        print(f"\n  {C.BOLD}{C.WHT}  ── SECTIONS ──{C.RST}")
        print(f"  {C.DIM}|{C.RST}  {C.GRY}{'Name':<10} {'VirtSize':>10} {'RawSize':>10} {'Entropy':>8} {'Flags'}{C.RST}")
        print(f"  {C.DIM}|{C.RST}  {C.DIM}{'-'*10} {'-'*10} {'-'*10} {'-'*8} {'-'*20}{C.RST}")
        for s in sections:
            ent_color = C.RED if s["high_entropy"] else C.GRN
            name_color = C.RED if s["suspicious_name"] else C.WHT
            flags = []
            if s["high_entropy"]:
                flags.append(f"{C.RED}PACKED?{C.RST}")
            if s["suspicious_name"]:
                flags.append(f"{C.RED}SUS_NAME{C.RST}")
            flag_str = " ".join(flags)
            print(
                f"  {C.DIM}|{C.RST}  {name_color}{s['name']:<10}{C.RST} "
                f"{C.WHT}{s['virtual_size']:>10,}{C.RST} "
                f"{C.WHT}{s['raw_size']:>10,}{C.RST} "
                f"{ent_color}{s['entropy']:>8.4f}{C.RST} "
                f"{flag_str}"
            )

    # ── Imports summary ──
    imports = result.get("imports", {})
    if imports:
        total_funcs = sum(len(v) for v in imports.values())
        print(f"\n  {C.BOLD}{C.WHT}  ── IMPORTS ──{C.RST}")
        info(f"DLLs loaded: {C.WHT}{len(imports)}{C.RST}  |  Functions imported: {C.WHT}{total_funcs}{C.RST}")
        for dll, funcs in imports.items():
            print(f"  {C.DIM}|{C.RST}  {C.CYN}{dll}{C.RST} {C.DIM}({len(funcs)} functions){C.RST}")

    # ── Suspicious APIs ──
    sus_apis = result.get("suspicious_apis", [])
    if sus_apis:
        print(f"\n  {C.BOLD}{C.RED}  ── SUSPICIOUS API IMPORTS ({len(sus_apis)}) ──{C.RST}")
        for api in sus_apis:
            print(f"  {C.DIM}|{C.RST}  {C.RED}(!){C.RST} {C.YEL}{api['dll']}{C.RST} -> {C.RED}{C.BOLD}{api['func']}{C.RST}")
    else:
        print(f"\n  {C.BOLD}{C.WHT}  ── SUSPICIOUS APIs ──{C.RST}")
        success("No suspicious API imports detected.")

    # ── Overlay ──
    overlay = result.get("overlay", {})
    if overlay.get("present"):
        print(f"\n  {C.BOLD}{C.YEL}  ── OVERLAY DATA DETECTED ──{C.RST}")
        table_row("Offset",        overlay.get("offset", "N/A"))
        table_row("Size",          f"{overlay.get('size_human', 'N/A')} ({overlay.get('size', 0):,} bytes)")
        table_row("Entropy",       f"{overlay.get('entropy', 0):.4f}")
        table_row("First Bytes",   overlay.get("first_bytes", "N/A"))
        if overlay.get("has_embedded_pe"):
            warn(f"Overlay starts with MZ — {C.RED}possible embedded PE executable!{C.RST}")

    # ── Resources ──
    resources = result.get("resources", [])
    if resources:
        suspicious_resources = [r for r in resources if r.get("suspicious")]
        print(f"\n  {C.BOLD}{C.WHT}  ── RESOURCES ({len(resources)} total) ──{C.RST}")
        if suspicious_resources:
            print(f"  {C.BOLD}{C.RED}  ⚠ {len(suspicious_resources)} suspicious resource(s)!{C.RST}")
        for r in resources[:15]:
            flag = f" {C.RED}⚠ SUSPICIOUS{C.RST}" if r.get("suspicious") else ""
            print(f"  {C.DIM}|{C.RST}  {C.WHT}{r['type']:<16}{C.RST} {r['name']:<12} {r['size_human']:>10}  ent={r['entropy']:.2f}{flag}")

    # ── TLS Callbacks ──
    tls = result.get("tls_callbacks", {})
    if tls.get("present"):
        print(f"\n  {C.BOLD}{C.RED}  ── TLS CALLBACKS ({tls['count']}) — Pre-entry point execution ──{C.RST}")
        for addr in tls["addresses"]:
            print(f"  {C.DIM}|{C.RST}  {C.RED}(!){C.RST} Callback at {C.WHT}{addr}{C.RST}")

    # ── Debug Info ──
    debug = result.get("debug_info", {})
    if debug.get("present"):
        print(f"\n  {C.BOLD}{C.WHT}  ── DEBUG INFO ──{C.RST}")
        for entry in debug["entries"]:
            pdb = entry.get("pdb_path", "")
            if pdb:
                print(f"  {C.DIM}|{C.RST}  {C.WHT}{entry['type']}{C.RST}  PDB: {C.YEL}{pdb}{C.RST}")
            else:
                print(f"  {C.DIM}|{C.RST}  {C.WHT}{entry['type']}{C.RST}")

    # ── Rich Header ──
    rich = result.get("rich_header", {})
    if rich.get("present"):
        print(f"\n  {C.BOLD}{C.WHT}  ── RICH HEADER (Build Environment) ──{C.RST}")
        table_row("Rich Hash",     rich.get("hash", "N/A"))
        table_row("Build Entries", str(rich.get("entry_count", 0)))

    # ── Threat indicators ──
    indicators = result.get("indicators", [])
    print(f"\n  {C.BOLD}{C.WHT}  ── THREAT INDICATORS ──{C.RST}")
    for ind in indicators:
        sev = ind["severity"]
        if sev == "HIGH":
            color = C.RED
            icon = "[!!!]"
        elif sev == "MEDIUM":
            color = C.YEL
            icon = "[!!] "
        elif sev == "LOW":
            color = C.ORANGE
            icon = "[!]  "
        else:
            color = C.GRN
            icon = "[OK] "
        print(f"  {C.DIM}|{C.RST}  {color}{icon} {ind['type']}: {ind['detail']}{C.RST}")

    return result


def run_strings_extraction(file_path):
    """Run strings extraction and display results."""
    section_header("06", "STRINGS EXTRACTION  ·  ASCII / UNICODE", "📝")

    result = spinner_task("Extracting strings...", get_strings_summary, file_path, 80)

    if "error" in result:
        fail(result["error"])
        return None

    info(f"Total strings found : {C.WHT}{result['total_count']:,}{C.RST}")
    info(f"ASCII strings       : {C.WHT}{result['ascii_count']:,}{C.RST}")
    info(f"Unicode strings     : {C.WHT}{result['unicode_count']:,}{C.RST}")

    # Show suspicious strings
    suspicious = result.get("suspicious", {})
    if suspicious:
        sus_total = result.get("suspicious_count", 0)
        print(f"\n  {C.BOLD}{C.RED}  ── SUSPICIOUS STRINGS ({sus_total}) ──{C.RST}")
        for category, items in suspicious.items():
            print(f"\n  {C.DIM}|{C.RST}  {C.YEL}{category}{C.RST} {C.DIM}({len(items)} found){C.RST}")
            for item in items[:10]:
                print(f"  {C.DIM}|{C.RST}    {C.RED}>{C.RST} {C.WHT}{item}{C.RST}")
            if len(items) > 10:
                print(f"  {C.DIM}|{C.RST}    {C.DIM}... and {len(items) - 10} more{C.RST}")
    else:
        success("No suspicious string patterns detected.")

    # Show sample strings
    display = result.get("display_strings", [])
    if display:
        print(f"\n  {C.BOLD}{C.WHT}  ── SAMPLE STRINGS (first {len(display)}) ──{C.RST}")
        for i, s in enumerate(display[:30], 1):
            truncated = s[:80] + ("..." if len(s) > 80 else "")
            print(f"  {C.DIM}|{C.RST}  {C.GRY}{i:>4}.{C.RST} {C.WHT}{truncated}{C.RST}")
        if result.get("truncated"):
            print(f"  {C.DIM}|{C.RST}  {C.DIM}... {result['total_count'] - len(display)} more strings not shown{C.RST}")

    return result


def run_yara_scan(file_path):
    """Run YARA rule scanning and display results."""
    section_header("07", "YARA SCAN  ·  RULE-BASED DETECTION", "🛡️")

    if not YARA_AVAILABLE:
        warn(f"yara-python not installed. Run: {C.WHT}pip install yara-python{C.RST}")
        info("YARA scanning provides pattern-based malware detection using 17+ built-in rules.")
        return None

    rule_count = get_rule_count()
    info(f"Scanning with {C.WHT}{rule_count}{C.RST} built-in YARA rules...")

    result = spinner_task("Running YARA scan...", yara_scan_file, file_path)

    if "error" in result:
        fail(result["error"])
        return None

    total = result.get("total_matches", 0)
    severity = result.get("severity_summary", {})

    if total == 0:
        success("No YARA rules matched — file appears clean by rule-based analysis.")
        return result

    # Severity summary
    print(f"\n  {C.BOLD}{C.RED}  ── YARA MATCHES ({total}) ──{C.RST}")
    sev_parts = []
    for sev_name, sev_color in [("critical", C.RED), ("high", C.ORANGE),
                                 ("medium", C.YEL), ("low", C.GRN)]:
        count = severity.get(sev_name, 0)
        if count > 0:
            sev_parts.append(f"{sev_color}{sev_name.upper()}: {count}{C.RST}")
    if sev_parts:
        info("Severity: " + "  ".join(sev_parts))

    # Display each match
    for match in result.get("matches", []):
        sev = match["severity"]
        if sev == "critical":
            color, icon = C.RED, "🔴"
        elif sev == "high":
            color, icon = C.ORANGE, "🟠"
        elif sev == "medium":
            color, icon = C.YEL, "🟡"
        else:
            color, icon = C.GRN, "🟢"

        print(f"\n  {C.DIM}|{C.RST}  {icon} {color}{C.BOLD}{match['rule']}{C.RST}")
        print(f"  {C.DIM}|{C.RST}    {C.DIM}Desc: {match.get('description', 'N/A')}{C.RST}")
        print(f"  {C.DIM}|{C.RST}    {C.DIM}Category: {match.get('category', 'N/A')}  |  Severity: {color}{sev.upper()}{C.RST}")

        # Show matched strings
        for ms in match.get("matched_strings", [])[:5]:
            print(f"  {C.DIM}|{C.RST}    {C.GRY}@ {ms['offset']} {ms['identifier']}: {C.WHT}{ms['data']}{C.RST}")

    return result


def run_vt_lookup(file_path):
    """Run VirusTotal hash lookup and display results."""
    section_header("08", "VIRUSTOTAL LOOKUP  ·  HASH-BASED", "🦠")

    info("Only the file HASH is sent to VT — the file is NEVER uploaded.")

    from vt_lookup import _get_api_key
    api_key = _get_api_key()
    if not api_key:
        api_key = prompt("Enter VirusTotal API key (or press Enter to skip): ")
        if not api_key:
            info("No API key provided. Skipping VirusTotal lookup.")
            return None

    result = spinner_task("Querying VirusTotal...", lookup_hash, file_path, api_key)

    status = result.get("status", "")

    if status == "found":
        ratio = result["detection_ratio"]
        malicious = result["malicious"]
        verdict = result["verdict"]

        if verdict == "MALICIOUS":
            verdict_color = C.RED
        elif verdict == "SUSPICIOUS":
            verdict_color = C.YEL
        else:
            verdict_color = C.GRN

        print(f"\n  {C.BOLD}{verdict_color}  ── VERDICT: {verdict} ──{C.RST}")
        table_row("Detection Ratio", f"{verdict_color}{ratio}{C.RST}")
        table_row("Threat Label",    result.get("threat_label", "N/A"))
        table_row("File Type",       result.get("file_type", "N/A"))
        table_row("Reputation",      str(result.get("reputation", "N/A")))
        table_row("SHA-256",         result.get("file_hash", "N/A"))

        tags = result.get("tags", [])
        if tags:
            table_row("Tags", ", ".join(tags[:10]))

        detections = result.get("detections", [])
        if detections:
            print(f"\n  {C.BOLD}{C.RED}  ── ENGINE DETECTIONS ({len(detections)}) ──{C.RST}")
            for d in detections[:15]:
                cat_color = C.RED if d["category"] == "malicious" else C.YEL
                print(f"  {C.DIM}|{C.RST}  {cat_color}{d['engine']:<24}{C.RST} {C.WHT}{d['result']}{C.RST}")
            if len(detections) > 15:
                print(f"  {C.DIM}|{C.RST}  {C.DIM}... and {len(detections) - 15} more detections{C.RST}")

    elif status == "not_found":
        info(f"Hash: {C.WHT}{result.get('file_hash', 'N/A')}{C.RST}")
        warn("File hash not found in VirusTotal database.")
        info("This means the file has never been submitted to VT.")

    elif status == "no_key":
        warn(result.get("error", "No API key."))

    else:
        fail(result.get("error", f"VT lookup failed (status: {status})"))

    return result


# ── Reporting ─────────────────────────────────────────────────

def run_report_generation(analysis_data, file_path):
    """Generate PDF, HTML, and/or JSON reports."""
    section_header("09", "REPORT GENERATION  ·  EXPORT", "📊")

    print(f"\n  {C.WHT}Select report format:{C.RST}")
    print(f"  {C.RED}[1]{C.RST} {C.BOLD}PDF Report{C.RST}  {C.DIM}(recommended — forensic PDF){C.RST}")
    print(f"  {C.GRN}[2]{C.RST} HTML Report (visual, browser)")
    print(f"  {C.CYN}[3]{C.RST} JSON Report (data, automation)")
    print(f"  {C.YEL}[4]{C.RST} All formats (PDF + HTML + JSON)")

    choice = prompt("Format [1/2/3/4]: ")

    base = os.path.splitext(os.path.basename(file_path))[0]
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = os.path.join(os.path.dirname(os.path.abspath(file_path)))

    if choice in ("1", "4"):
        pdf_path = os.path.join(report_dir, f"{base}_report_{timestamp}.pdf")
        result = generate_pdf_report(analysis_data, pdf_path)
        if not result.startswith("Error"):
            success(f"PDF report  → {C.WHT}{result}{C.RST}")
        else:
            fail(result)

    if choice in ("2", "4"):
        html_path = os.path.join(report_dir, f"{base}_report_{timestamp}.html")
        result = generate_html_report(analysis_data, html_path)
        if not result.startswith("Error"):
            success(f"HTML report → {C.WHT}{result}{C.RST}")
        else:
            fail(result)

    if choice in ("3", "4"):
        json_path = os.path.join(report_dir, f"{base}_report_{timestamp}.json")
        result = generate_json_report(analysis_data, json_path)
        if not result.startswith("Error"):
            success(f"JSON report → {C.WHT}{result}{C.RST}")
        else:
            fail(result)

    if choice not in ("1", "2", "3", "4"):
        warn("Invalid selection. Report generation skipped.")


# ── Risk Score Dashboard ──────────────────────────────────────

def show_risk_dashboard(analysis_data):
    """Display the overall risk score dashboard."""
    risk_score = calculate_risk_score(analysis_data)
    verdict, verdict_class = get_risk_verdict(risk_score)

    print()
    print(f"  {C.BOLD}{C.WHT}{'━' * 64}{C.RST}")
    print(f"  {C.BOLD}{C.WHT}  ◆  RISK ASSESSMENT DASHBOARD{C.RST}")
    print(f"  {C.BOLD}{C.WHT}{'━' * 64}{C.RST}")

    # Color based on score
    if risk_score >= 75:
        sc = C.RED
    elif risk_score >= 50:
        sc = C.ORANGE
    elif risk_score >= 25:
        sc = C.YEL
    else:
        sc = C.GRN

    # Score bar
    filled = risk_score // 2
    bar = f"{sc}{'█' * filled}{C.DIM}{'░' * (50 - filled)}{C.RST}"
    print(f"\n  {bar}  {sc}{C.BOLD}{risk_score}/100{C.RST}")
    print(f"\n  {C.BOLD}  Verdict: {sc}{verdict}{C.RST}")

    # Breakdown
    pe = analysis_data.get("pe_analysis", {})
    vt = analysis_data.get("vt_lookup", {})
    yara_data = analysis_data.get("yara_scan", {})

    print(f"\n  {C.DIM}  Factors:{C.RST}")
    if vt and vt.get("status") == "found":
        print(f"  {C.DIM}  ├─{C.RST} VirusTotal: {C.WHT}{vt.get('detection_ratio', 'N/A')}{C.RST} detections")
    if pe and pe.get("suspicious_apis"):
        print(f"  {C.DIM}  ├─{C.RST} Suspicious APIs: {C.WHT}{len(pe['suspicious_apis'])}{C.RST}")
    if yara_data and yara_data.get("matches"):
        print(f"  {C.DIM}  ├─{C.RST} YARA rules matched: {C.WHT}{len(yara_data['matches'])}{C.RST}")
    sections = pe.get("sections", [])
    high_ent = sum(1 for s in sections if s.get("high_entropy"))
    if high_ent:
        print(f"  {C.DIM}  ├─{C.RST} High-entropy sections: {C.WHT}{high_ent}{C.RST}")
    if pe and pe.get("digital_signature", {}).get("signed") is False:
        print(f"  {C.DIM}  └─{C.RST} Digital signature: {C.YEL}Not signed{C.RST}")

    print(f"  {C.BOLD}{C.WHT}{'━' * 64}{C.RST}")


# ══════════════════════════════════════════════════════════════
#  WINDOWS API MODULE DISPLAY ROUTINES
# ══════════════════════════════════════════════════════════════

def run_ads_scan(file_path):
    """Run NTFS Alternate Data Streams scan and display results."""
    section_header("10", "NTFS ADS SCANNER  ·  HIDDEN STREAMS", "🔍")

    if not ADS_AVAILABLE:
        fail("ADS scanning is only available on Windows (NTFS volumes).")
        return None

    result = spinner_task("Scanning for alternate data streams...", scan_ads, file_path)

    if "error" in result:
        fail(result["error"])
        return None

    total = result["total_streams"]
    hidden = result["hidden_streams"]

    info(f"Total streams    : {C.WHT}{total}{C.RST}")
    info(f"Hidden streams   : {C.WHT}{hidden}{C.RST}")
    info(f"Hidden data size : {C.WHT}{result['hidden_size_human']}{C.RST}")

    if hidden == 0:
        success("No hidden alternate data streams found — file is clean.")
        return result

    # Display hidden streams
    print(f"\n  {C.BOLD}{C.YEL}  ── HIDDEN DATA STREAMS ({hidden}) ──{C.RST}")
    for stream in result.get("hidden_details", []):
        name = stream["name"]
        size = stream["size"]
        suspicious = stream.get("suspicious", False)

        icon = f"{C.RED}⚠{C.RST}" if suspicious else f"{C.GRN}•{C.RST}"
        color = C.RED if suspicious else C.WHT
        print(f"  {C.DIM}|{C.RST}  {icon} {color}{name}{C.RST}  {C.DIM}({size:,} bytes){C.RST}")

        for reason in stream.get("reasons", []):
            print(f"  {C.DIM}|{C.RST}    {C.RED}→ {reason}{C.RST}")

    if result["has_suspicious"]:
        print(f"\n  {C.BOLD}{C.RED}  ⚠ SUSPICIOUS HIDDEN DATA DETECTED!{C.RST}")
        info(f"Use the extract option to examine hidden stream content.")

    # Offer extraction
    if hidden > 0:
        extract = prompt(f"Extract a hidden stream? [y/N]: ")
        if extract.lower() == "y":
            details = result.get("hidden_details", [])
            print(f"\n  {C.WHT}Available streams:{C.RST}")
            for idx, s in enumerate(details, 1):
                print(f"    {C.CYN}[{idx}]{C.RST} {s['name']}  ({s['size']:,} bytes)")
            sel = prompt(f"Stream number [1-{len(details)}]: ")
            try:
                sel_idx = int(sel) - 1
                if 0 <= sel_idx < len(details):
                    out_path = prompt("Output path for extracted data: ")
                    if out_path:
                        ext_result = extract_ads(file_path, details[sel_idx]["name"], out_path)
                        if "error" in ext_result:
                            fail(ext_result["error"])
                        else:
                            success(f"Stream extracted → {C.WHT}{ext_result['output_path']}{C.RST}")
                            success(f"Bytes written   → {C.WHT}{ext_result['bytes_written']:,}{C.RST}")
            except (ValueError, IndexError):
                warn("Invalid selection.")

    return result


def run_process_analysis():
    """Run process enumeration and display results."""
    section_header("11", "RUNNING PROCESS AUDIT  ·  SYSTEM-WIDE", "⚙️")

    if not PROCESS_ANALYZER_AVAILABLE:
        fail("Process analysis is only available on Windows.")
        return None

    result = spinner_task("Enumerating running processes...", get_process_summary)

    if "error" in result:
        fail(result["error"])
        return None

    info(f"Total processes      : {C.WHT}{result['total_processes']}{C.RST}")
    info(f"Unique executables   : {C.WHT}{result['unique_executables']}{C.RST}")
    info(f"Path accessible      : {C.WHT}{result['path_accessible']}{C.RST}")
    info(f"Path denied          : {C.DIM}{result['path_denied']}{C.RST}")

    suspicious = result.get("suspicious_procs", [])
    if suspicious:
        print(f"\n  {C.BOLD}{C.RED}  ── SUSPICIOUS PROCESSES ({len(suspicious)}) ──{C.RST}")
        for proc in suspicious:
            pid = proc["pid"]
            name = proc["name"]
            path = proc.get("full_path", "N/A")
            print(f"\n  {C.DIM}|{C.RST}  {C.RED}⚠{C.RST} {C.BOLD}{C.YEL}{name}{C.RST}  {C.DIM}(PID: {pid}){C.RST}")
            if path and path != "N/A":
                print(f"  {C.DIM}|{C.RST}    Path: {C.WHT}{path}{C.RST}")
            for reason in proc.get("reasons", []):
                print(f"  {C.DIM}|{C.RST}    {C.RED}→ {reason}{C.RST}")
    else:
        success("No suspicious processes detected.")

    # Show top processes
    all_procs = enumerate_processes()
    procs = all_procs.get("processes", [])[:20]
    if procs:
        print(f"\n  {C.BOLD}{C.WHT}  ── PROCESS LIST (top 20) ──{C.RST}")
        print(f"  {C.DIM}|{C.RST}  {C.GRY}{'PID':<8} {'Name':<28} {'Path'}{C.RST}")
        print(f"  {C.DIM}|{C.RST}  {C.DIM}{'-'*8} {'-'*28} {'-'*30}{C.RST}")
        for p in procs:
            name_color = C.RED if p.get("suspicious") else C.WHT
            path = p.get("full_path", "N/A")
            if len(path) > 40:
                path = "..." + path[-37:]
            print(f"  {C.DIM}|{C.RST}  {C.CYN}{p['pid']:<8}{C.RST} {name_color}{p['name']:<28}{C.RST} {C.DIM}{path}{C.RST}")

    return result


def run_network_inspection():
    """Run network connection inspection and display results."""
    section_header("12", "NETWORK INSPECTOR  ·  ACTIVE CONNECTIONS", "🌐")

    if not NETWORK_INSPECTOR_AVAILABLE:
        fail("Network inspection is only available on Windows.")
        return None

    result = spinner_task("Scanning active network connections...", get_full_network_snapshot)

    if "error" in result:
        fail(result["error"])
        return None

    tcp = result.get("tcp", {})
    udp = result.get("udp", {})

    info(f"Total connections     : {C.WHT}{result['total_connections']}{C.RST}")
    info(f"TCP connections       : {C.WHT}{tcp.get('total', 0)}{C.RST}  "
         f"{C.DIM}({tcp.get('established', 0)} established, {tcp.get('listening', 0)} listening){C.RST}")
    info(f"UDP endpoints         : {C.WHT}{udp.get('total', 0)}{C.RST}")

    # TCP connections table
    tcp_conns = tcp.get("connections", [])
    if tcp_conns:
        print(f"\n  {C.BOLD}{C.WHT}  ── TCP CONNECTIONS ({len(tcp_conns)}) ──{C.RST}")
        print(f"  {C.DIM}|{C.RST}  {C.GRY}{'Local Address':<22} {'Remote Address':<22} {'State':<14} {'PID':<7} {'Process'}{C.RST}")
        print(f"  {C.DIM}|{C.RST}  {C.DIM}{'-'*22} {'-'*22} {'-'*14} {'-'*7} {'-'*18}{C.RST}")
        for conn in tcp_conns[:40]:
            local = f"{conn['local_addr']}:{conn['local_port']}"
            remote = f"{conn['remote_addr']}:{conn['remote_port']}"
            state = conn["state"]

            state_color = C.GRN if state == "ESTABLISHED" else C.CYN if state == "LISTEN" else C.DIM
            sus_flag = f" {C.RED}⚠{C.RST}" if conn.get("suspicious") else ""

            print(f"  {C.DIM}|{C.RST}  {C.WHT}{local:<22}{C.RST} {C.WHT}{remote:<22}{C.RST} "
                  f"{state_color}{state:<14}{C.RST} {C.CYN}{conn['pid']:<7}{C.RST} "
                  f"{C.DIM}{conn.get('process_name', 'N/A')}{C.RST}{sus_flag}")
        if len(tcp_conns) > 40:
            print(f"  {C.DIM}|{C.RST}  {C.DIM}... and {len(tcp_conns) - 40} more{C.RST}")

    # Suspicious connections
    all_sus = result.get("all_suspicious", [])
    if all_sus:
        print(f"\n  {C.BOLD}{C.RED}  ── SUSPICIOUS CONNECTIONS ({len(all_sus)}) ──{C.RST}")
        for s in all_sus:
            proto = s.get("protocol", "TCP")
            proc = s.get("process_name", "N/A")
            print(f"  {C.DIM}|{C.RST}  {C.RED}⚠{C.RST} [{proto}] {C.YEL}{proc}{C.RST} (PID:{s['pid']})")
            for reason in s.get("reasons", []):
                print(f"  {C.DIM}|{C.RST}    {C.RED}→ {reason}{C.RST}")
    else:
        success("No suspicious network connections detected.")

    return result


def run_signature_verification(file_path):
    """Run Authenticode signature verification and display results."""
    section_header("13", "AUTHENTICODE SIGNATURE  ·  TRUST VERIFICATION", "🔏")

    if not SIG_VERIFIER_AVAILABLE:
        fail("Signature verification is only available on Windows.")
        return None

    result = spinner_task("Verifying digital signature...", verify_signature, file_path)

    if "error" in result:
        fail(result["error"])
        return None

    status = result.get("status", "unknown")
    signed = result.get("signed", False)

    if status == "valid":
        print(f"\n  {C.BOLD}{C.GRN}  ── ✓ VALID DIGITAL SIGNATURE ──{C.RST}")
        table_row("Status",   f"{C.GRN}Signed and trusted{C.RST}")
    elif status == "unsigned":
        print(f"\n  {C.BOLD}{C.YEL}  ── ⚠ FILE IS NOT SIGNED ──{C.RST}")
        table_row("Status",   f"{C.YEL}No digital signature{C.RST}")
    elif status == "untrusted":
        print(f"\n  {C.BOLD}{C.RED}  ── ⚠ UNTRUSTED SIGNATURE ──{C.RST}")
        table_row("Status",   f"{C.RED}Signed but NOT trusted{C.RST}")
    elif status == "distrusted":
        print(f"\n  {C.BOLD}{C.RED}  ── ✗ EXPLICITLY DISTRUSTED ──{C.RST}")
        table_row("Status",   f"{C.RED}Explicitly distrusted{C.RST}")
    else:
        print(f"\n  {C.BOLD}{C.RED}  ── ✗ SIGNATURE INVALID ──{C.RST}")
        table_row("Status",   f"{C.RED}{status}{C.RST}")

    table_row("Detail",   result.get("detail", "N/A"))
    table_row("Signer",   result.get("signer", "N/A"))
    table_row("Issuer",   result.get("issuer", "N/A"))

    return result


def run_eventlog_reader():
    """Run Windows Event Log reader and display forensic events."""
    section_header("14", "WINDOWS EVENT LOG  ·  FORENSIC EVENTS", "📜")

    if not EVENTLOG_AVAILABLE:
        fail("Event log reading is only available on Windows.")
        return None

    # Show log summary first
    summary = spinner_task("Querying event log status...", get_log_summary)
    if "error" in summary:
        fail(summary["error"])
        return None

    print(f"\n  {C.BOLD}{C.WHT}  ── EVENT LOG STATUS ──{C.RST}")
    for log_name, count in summary.items():
        table_row(f"{log_name} Log", f"{count:,}" if isinstance(count, int) else str(count))

    # Read forensic events
    info("Reading forensic-relevant events (may require Administrator)...")
    result = spinner_task("Reading event logs...", read_forensic_events, 50)

    if "error" in result:
        fail(result["error"])
        return None

    # Show status for each log
    sec_status = result.get("security_status", "OK")
    sys_status = result.get("system_status", "OK")
    if sec_status != "OK":
        warn(f"Security log: {C.YEL}{sec_status}{C.RST}")
    if sys_status != "OK":
        warn(f"System log: {C.YEL}{sys_status}{C.RST}")

    events = result.get("events", [])
    sev_counts = result.get("severity_counts", {})

    info(f"Forensic events found : {C.WHT}{len(events)}{C.RST}")

    # Severity summary
    sev_parts = []
    for sev, color in [("critical", C.RED), ("high", C.ORANGE), ("warning", C.YEL), ("info", C.GRN)]:
        count = sev_counts.get(sev, 0)
        if count > 0:
            sev_parts.append(f"{color}{sev.upper()}: {count}{C.RST}")
    if sev_parts:
        info("Severity: " + "  ".join(sev_parts))

    if not events:
        success("No forensic-relevant events found (or access denied).")
        return result

    # Display events
    print(f"\n  {C.BOLD}{C.WHT}  ── FORENSIC EVENTS ──{C.RST}")
    for ev in events[:30]:
        eid = ev["event_id"]
        etype = ev.get("event_type", "")
        ts = ev.get("timestamp", "N/A")
        source = ev.get("source", "N/A")
        forensic_desc = ev.get("forensic_desc", "")
        severity = ev.get("forensic_severity", "info")

        if severity == "critical":
            color, icon = C.RED, "🔴"
        elif severity == "high":
            color, icon = C.ORANGE, "🟠"
        elif severity == "warning":
            color, icon = C.YEL, "🟡"
        else:
            color, icon = C.GRN, "🟢"

        print(f"  {C.DIM}|{C.RST}  {icon} {C.DIM}{ts}{C.RST}  {color}ID:{eid}{C.RST}  {C.WHT}{forensic_desc or etype}{C.RST}")
        print(f"  {C.DIM}|{C.RST}    {C.DIM}Source: {source}  |  Type: {etype}{C.RST}")

        # Show first event string if available
        strings = ev.get("strings", [])
        if strings and strings[0]:
            detail = strings[0][:80]
            print(f"  {C.DIM}|{C.RST}    {C.GRY}Detail: {detail}{C.RST}")

    if len(events) > 30:
        print(f"  {C.DIM}|{C.RST}  {C.DIM}... and {len(events) - 30} more events{C.RST}")

    return result


# ══════════════════════════════════════════════════════════════
#  SESSION FOOTER
# ══════════════════════════════════════════════════════════════

def print_footer(start_time):
    elapsed = time.time() - start_time
    print()
    line("=")
    print(f"  {C.BOLD}{C.GRN}  [OK]  Analysis complete in {elapsed:.2f}s{C.RST}")
    print(f"  {C.DIM}        Session ended at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RST}")
    line("=")
    print()


# ══════════════════════════════════════════════════════════════
#  MAIN LOOP
# ══════════════════════════════════════════════════════════════

# Store last analysis data for report generation
_last_analysis = {}

def main():
    global _last_analysis
    print_banner()

    while True:
        show_menu()
        choice = prompt("Select option [0-16]: ")

        if choice == "0":
            print()
            typewriter(f"  {C.DIM}Shutting down BitWitness...  Stay forensic.{C.RST}", speed=0.02)
            print()
            break

        valid_choices = [str(i) for i in range(1, 17)]
        if choice not in valid_choices:
            warn("Invalid option. Please select 1-16 or 0 to exit.")
            continue

        # Report generation uses stored data
        if choice == "11":
            if not _last_analysis:
                warn("No analysis data available. Run an analysis first (options 1-10).")
                continue
            run_report_generation(_last_analysis, _last_analysis.get("_file_path", "report"))
            continue

        # System-wide modules — no file needed
        if choice == "13":   # Process analyzer
            start = time.time()
            result = run_process_analysis()
            if result:
                _last_analysis = {"process_analysis": result}
            print_footer(start)
            continue

        if choice == "14":   # Network inspector
            start = time.time()
            result = run_network_inspection()
            if result:
                _last_analysis = {"network_inspection": result}
            print_footer(start)
            continue

        if choice == "16":   # Event log reader
            start = time.time()
            result = run_eventlog_reader()
            if result:
                _last_analysis = {"eventlog": result}
            print_footer(start)
            continue

        file_path = get_target_file()
        if not file_path:
            continue

        start = time.time()
        show_file_info(file_path)

        # Init analysis data collector
        analysis_data = {"_file_path": file_path}
        file_hash = None

        # Get basic file info for reports
        analysis_data["file_info"] = get_file_metadata(file_path)

        if choice == "1":      # Full forensic analysis
            hashes = run_integrity(file_path)
            if hashes:
                analysis_data["hashes"] = hashes
                file_hash = hashes.get("sha256")
            header = run_header_analysis(file_path, show_hex=False)
            analysis_data["header_analysis"] = header
            meta = run_metadata(file_path)
            analysis_data["metadata"] = meta
            run_forensic_imaging(file_path, original_hash=file_hash)

        elif choice == "2":    # Integrity only
            hashes = run_integrity(file_path)
            if hashes:
                analysis_data["hashes"] = hashes

        elif choice == "3":    # Header + hex dump
            header = run_header_analysis(file_path, show_hex=True)
            analysis_data["header_analysis"] = header

        elif choice == "4":    # Imaging only
            run_forensic_imaging(file_path)

        elif choice == "5":    # Metadata only
            meta = run_metadata(file_path)
            analysis_data["metadata"] = meta

        elif choice == "6":    # Full malware analysis
            hashes = run_integrity(file_path)
            if hashes:
                analysis_data["hashes"] = hashes
            header = run_header_analysis(file_path, show_hex=False)
            analysis_data["header_analysis"] = header
            pe_result = run_pe_analysis(file_path)
            if pe_result:
                analysis_data["pe_analysis"] = pe_result
            strings = run_strings_extraction(file_path)
            if strings:
                analysis_data["strings"] = strings
            yara_result = run_yara_scan(file_path)
            if yara_result:
                analysis_data["yara_scan"] = yara_result
            vt_result = run_vt_lookup(file_path)
            if vt_result:
                analysis_data["vt_lookup"] = vt_result

            # Show risk dashboard for full analysis
            show_risk_dashboard(analysis_data)

        elif choice == "7":    # PE analysis only
            pe_result = run_pe_analysis(file_path)
            if pe_result:
                analysis_data["pe_analysis"] = pe_result

        elif choice == "8":    # Strings only
            strings = run_strings_extraction(file_path)
            if strings:
                analysis_data["strings"] = strings

        elif choice == "9":    # YARA scan only
            yara_result = run_yara_scan(file_path)
            if yara_result:
                analysis_data["yara_scan"] = yara_result

        elif choice == "10":   # VT lookup only
            vt_result = run_vt_lookup(file_path)
            if vt_result:
                analysis_data["vt_lookup"] = vt_result

        elif choice == "12":   # ADS Scanner
            ads_result = run_ads_scan(file_path)
            if ads_result:
                analysis_data["ads_scan"] = ads_result

        elif choice == "15":   # Signature verifier
            sig_result = run_signature_verification(file_path)
            if sig_result:
                analysis_data["signature"] = sig_result

        # Store for report generation
        _last_analysis = analysis_data

        print_footer(start)


if __name__ == "__main__":
    main()