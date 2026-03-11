# BitWitness

**Digital Forensics & Static Malware Analysis Framework — v4.0**

BitWitness is a Python-based command-line forensic tool designed for professional file integrity verification, binary header analysis, forensic imaging, static malware analysis, Windows system forensics, and threat detection. Inspired by tools like **PEStudio**, **Autopsy**, **YARA**, **Process Explorer**, and **CFF Explorer**, it provides a premium CLI interface with animated output, color-coded results, risk scoring, and report generation.

---

## Features

### Forensic Analysis
| Module | Description |
|--------|-------------|
| **Multi-Hash Integrity** | MD5, SHA-1, SHA-256, SHA-512 + ssdeep fuzzy hashing |
| **Header Analysis** | 50+ file signature detection (images, docs, executables, archives, audio, video, forensic formats) |
| **Hex Dump Viewer** | xxd-style hex dump with ASCII sidebar and offset navigation |
| **File Entropy** | Shannon entropy scoring with verdicts (packed/encrypted detection) |
| **Forensic Imaging** | Bit-for-bit file copy with progress bar and integrity verification |
| **Metadata Extraction** | File timestamps, permissions, EXIF data (GPS, camera), PE version info |

### Static Malware Analysis
| Module | Description |
|--------|-------------|
| **PE Static Analysis** | PEStudio-inspired PE parsing — headers, sections, entropy, imports, exports |
| **Import Hash (Imphash)** | Malware family correlation via import table fingerprinting |
| **Overlay Detection** | Detects data appended after PE structure (common in droppers) |
| **Resource Extraction** | Embedded resources with type, size, entropy — flags embedded PEs |
| **Digital Signature** | Authenticode signature presence check |
| **TLS Callbacks** | Pre-entry-point execution detection (anti-debug evasion) |
| **Debug Info / PDB** | Build environment fingerprinting via PDB paths |
| **Rich Header** | Compiler/linker build tool identification |
| **Suspicious API Detection** | Flags 80+ dangerous Windows API imports |
| **Threat Indicators** | Weighted red flags: packing, W^X violations, timestamp anomalies |
| **YARA Scanning** | 17 built-in rules: packers, shellcode, ransomware, C2, injection, crypto mining |
| **Strings Extraction** | ASCII & Unicode string extraction with suspicious pattern classification |
| **VirusTotal Lookup** | Hash-based VT API v3 lookup — file is never uploaded |

### Reporting & Risk Assessment
| Module | Description |
|--------|-------------|
| **Risk Score Dashboard** | 0-100 weighted risk score with color-coded verdict |
| **PDF Report** | Professional forensic PDF report (recommended) |
| **HTML Report** | Professional dark-themed self-contained HTML report |
| **JSON Report** | Structured JSON export for automation / SIEM ingestion |

### Windows Forensics (Windows API — zero extra dependencies)
| Module | Description |
|--------|-------------|
| **ADS Scanner** | Detects hidden NTFS Alternate Data Streams — a classic malware hiding technique. Uses `kernel32.FindFirstStreamW`/`FindNextStreamW`. Supports extraction of hidden stream content. |
| **Process Analyzer** | Enumerates all running processes with PID, executable path, and thread count. Flags suspicious process names, LOLBins (Living Off the Land Binaries), and processes in suspicious locations (Temp, AppData, Downloads). Uses `kernel32.CreateToolhelp32Snapshot`. |
| **Network Inspector** | Lists all active TCP/UDP connections with owning process info — a forensic netstat. Flags suspicious ports (4444, 5555, 6667, etc.) and external ESTABLISHED connections. Uses `iphlpapi.GetExtendedTcpTable`/`GetExtendedUdpTable`. |
| **Authenticode Verifier** | Verifies digital signatures on PE files using the Windows trust chain. Extracts signer name and certificate issuer. Reports valid/unsigned/untrusted/distrusted status. Uses `wintrust.WinVerifyTrust`/`crypt32.CryptQueryObject`. |
| **Event Log Reader** | Reads Windows Security, System, and Application event logs for 30+ forensic-relevant event IDs (logon success/failure, process creation, service install, audit log cleared, etc.). Color-coded severity. Uses `advapi32.OpenEventLogW`/`ReadEventLogW`. |

### CLI Features
- Randomized ASCII art banners (4 styles)
- Animated spinners during computation
- Real-time progress bars for file operations
- Color-coded output with ANSI escape sequences
- Interactive menu with 16 operation modes
- Library status indicators (pefile ✓, yara ✓, ssdeep ✓, WinAPI ✓)
- Forensic quote of the day

---

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/BitWitness.git
cd BitWitness

# Create and activate virtual environment
python -m venv venv

# Windows
.\venv\Scripts\Activate.ps1

# Linux/Mac
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Optional Dependencies

| Package | Purpose | Required? |
|---------|---------|-----------|
| `pefile` | PE file parsing | **Yes** — core malware analysis |
| `requests` | VirusTotal HTTP API | **Yes** — VT lookups |
| `yara-python` | YARA rule scanning | Optional — pattern-based detection |
| `Pillow` | EXIF metadata extraction | Optional — image forensics |
| `fpdf2` | PDF report generation | Optional — forensic PDF reports |
| `ssdeep` | Fuzzy hashing | Optional — similarity matching |

> **Note:** The 5 Windows Forensics modules (ADS Scanner, Process Analyzer, Network Inspector, Signature Verifier, Event Log Reader) use only `ctypes` from the Python standard library — **no additional pip packages needed**.

---

## Usage

```bash
cd modules
python main.py
```

### Menu Options

```
+──────────────────────────────────────────────────────────────+
│  SELECT OPERATION MODE                                       │
+──────────────────────────────────────────────────────────────+
│                                                              │
│  ─── FORENSIC ANALYSIS ───                                   │
│   [1]   Full Forensic Analysis    hash+header+meta+imaging   │
│   [2]   Integrity Check           MD5/SHA-1/SHA-256/SHA-512  │
│   [3]   Header + Hex Dump         magic bytes + hex viewer   │
│   [4]   Forensic Imaging          bit-for-bit copy           │
│   [5]   Metadata Extraction       timestamps+EXIF+properties │
│                                                              │
│  ─── MALWARE ANALYSIS ───                                    │
│   [6]   Full Malware Analysis     PE+strings+YARA+VT         │
│   [7]   PE Static Analysis        headers+imports+overlay    │
│   [8]   Strings Extraction        ASCII/Unicode strings      │
│   [9]   YARA Scan                 rule-based malware detect  │
│   [10]  VirusTotal Lookup         hash-based VT check        │
│                                                              │
│  ─── REPORTING ───                                           │
│   [11]  Generate Report           HTML/JSON/PDF export       │
│                                                              │
│  ─── WINDOWS FORENSICS ───                                   │
│   [12]  ADS Scanner               hidden NTFS streams        │
│   [13]  Process Analyzer          running process audit      │
│   [14]  Network Inspector         active connections+PIDs    │
│   [15]  Signature Verifier        Authenticode check         │
│   [16]  Event Log Reader          security/system events     │
│                                                              │
│   [0]   Exit                                                 │
+──────────────────────────────────────────────────────────────+
```

---

## VirusTotal API Setup

The VirusTotal module requires a free API key. Get one at [virustotal.com](https://www.virustotal.com).

**Option 1** — Create a `.vt_api_key` file in the project root:
```
echo YOUR_API_KEY > .vt_api_key
```

**Option 2** — Set an environment variable:
```bash
# Windows PowerShell
$env:VT_API_KEY = "YOUR_API_KEY"

# Linux/Mac
export VT_API_KEY="YOUR_API_KEY"
```

**Option 3** — Paste it at runtime when prompted.

> **Note:** Only the file's SHA-256 hash is sent to VirusTotal. The file itself is **never uploaded**.

---

## Project Structure

```
BitWitness/
├── modules/
│   ├── main.py               # Main CLI interface & menu system (16 modes)
│   ├── hex_engine.py          # 50+ file signatures + hex dump + entropy
│   ├── imaging.py             # Forensic bit-for-bit file copy
│   ├── integrity.py           # Multi-hash (MD5/SHA-1/SHA-256/SHA-512) + ssdeep
│   ├── metadata_extractor.py  # File metadata, EXIF, PE version info
│   ├── pe_analyzer.py         # PE static analysis (imphash, overlay, resources, TLS, etc.)
│   ├── strings_extractor.py   # ASCII/Unicode string extraction
│   ├── vt_lookup.py           # VirusTotal API v3 hash lookup
│   ├── yara_scanner.py        # YARA rule scanning (17 built-in rules)
│   ├── report_generator.py    # PDF/HTML/JSON report generation + risk scoring
│   ├── ads_scanner.py         # NTFS Alternate Data Streams scanner (WinAPI)
│   ├── process_analyzer.py    # Running process audit (WinAPI)
│   ├── network_inspector.py   # Active network connections inspector (WinAPI)
│   ├── sig_verifier.py        # Authenticode digital signature verifier (WinAPI)
│   ├── eventlog_reader.py     # Windows Event Log forensic reader (WinAPI)
│   └── run_analysis.py        # One-shot analysis script
├── requirements.txt           # Python dependencies
├── .vt_api_key                # VirusTotal API key (user-created)
└── README.md                  # This file
```

---

## YARA Rules

BitWitness includes **17 built-in YARA rules** covering:

| Category | Rules |
|----------|-------|
| **Packers** | UPX, MPRESS, VMProtect, Themida |
| **Execution** | PowerShell invocation, suspicious shell commands |
| **Shellcode** | NOP sleds, common shellcode patterns |
| **Network** | HTTP/FTP indicators, download functions |
| **Ransomware** | Encryption keywords, shadow deletion, bitcoin references |
| **Credential Theft** | Mimikatz signatures |
| **C2 Frameworks** | Cobalt Strike beacon indicators |
| **Injection** | Process injection API patterns |
| **Evasion** | Anti-debug techniques, VM detection |
| **Persistence** | Registry run key modifications |
| **Encoded Payloads** | Base64-encoded PE files |
| **Crypto Mining** | Stratum pool connections, miner signatures |

Custom YARA rules can also be loaded by specifying a path.

---

## Example Output

```
================================================================
  BitWitness v3.0 — Full Static Malware Analysis
  Target : tushar.exe
  Size   : 1,331,584 bytes
================================================================

[MODULE 01] FILE INTEGRITY — MULTI-HASH
  MD5      : a1b2c3d4e5f6...
  SHA-1    : f1e2d3c4b5a6...
  SHA-256  : da8c83eae113475945a9ab217acf0a375f690e3...
  SHA-512  : 7a8b9c0d1e2f...

[MODULE 05] PE STATIC ANALYSIS
  Machine      : x64 (AMD64)
  Compile Time : 2026-02-05 13:03:02 UTC
  Imphash      : e4d9cd9a67be...
  Digital Sig  : No digital signature present

  -- SUSPICIOUS APIs (8) --
  [!] KERNEL32.dll -> WriteProcessMemory
  [!] KERNEL32.dll -> IsDebuggerPresent

  -- THREAT INDICATORS --
  [!!!] Packed/Encrypted: High entropy section .rdata (7.9974)
  [!!]  Suspicious Imports: 8 suspicious API imports detected

[MODULE 07] YARA SCAN — 17 rules
  🔴 Process_Injection_APIs — Contains process injection API pattern
  🟠 Anti_Debug_Techniques — Contains anti-debugging indicators

  ═══════════════════════════════════════════════════════════════
  ◆  RISK ASSESSMENT: 72/100 — HIGH
  ═══════════════════════════════════════════════════════════════
================================================================
```

---

## Disclaimer

> **This tool is intended for authorized forensic investigations and educational purposes only.**
> Unauthorized use of this tool against systems you do not own or have explicit permission to analyze is illegal. The authors are not responsible for any misuse.

---

## Author

**Rohit**

## License

This project is for educational and authorized forensic use only.
