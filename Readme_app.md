# 🛡️ BitWitness GUI — Desktop Application

**Native Python GUI for Digital Forensics & Static Malware Analysis**

Built with **CustomTkinter** · Dark cybersecurity theme · Author: Rohit · v4.0.0

---

## 📦 Requirements

| Package | Purpose | Install |
|---------|---------|---------|
| **Python 3.8+** | Runtime | [python.org](https://python.org) |
| **customtkinter** | GUI framework | `pip install customtkinter` |
| **pefile** | PE analysis | `pip install pefile` |
| **yara-python** | YARA scanning (optional) | `pip install yara-python` |
| **Pillow** | EXIF metadata (optional) | `pip install Pillow` |
| **fpdf2** | PDF reports (optional) | `pip install fpdf2` |
| **requests** | VirusTotal lookup | `pip install requests` |

### Quick Install (all at once)

```bash
pip install customtkinter pefile requests Pillow fpdf2
```

> **Note:** `yara-python` and `ssdeep` require C build tools. Install only if available on your system.

---

## 🚀 How to Start

### Option 1: Using Virtual Environment (Recommended)

```bash
cd c:\Users\ROHIT\OneDrive\Desktop\BiyWitness
venv\Scripts\python.exe gui_app.py
```

### Option 2: Using System Python

```bash
cd c:\Users\ROHIT\OneDrive\Desktop\BiyWitness
python gui_app.py
```

The application window will open immediately — no browser or server needed.

---

## 🖥️ How the App Works

### Application Layout

```
┌──────────────┬──────────────────────────────────────────┐
│              │  TOP BAR                                 │
│              │  [📂] File path input  [Browse] [Analyze]│
│              ├──────────────────────────────────────────┤
│   SIDEBAR    │                                          │
│              │  CONTENT AREA                            │
│  Dashboard   │  (changes based on selected module)      │
│  ──────────  │                                          │
│  File Anal.  │  Shows cards with analysis results,     │
│  ──────────  │  tables, progress bars, and gauges       │
│  Malware     │                                          │
│  ──────────  │                                          │
│  Win Forensic│                                          │
│  ──────────  │                                          │
│  Reports     │                                          │
└──────────────┴──────────────────────────────────────────┘
```

### Step-by-Step Usage

#### 1️⃣ Select a Target File
- Type a file path in the top bar **OR**
- Click **Browse** to open a native file picker dialog

#### 2️⃣ Run Analysis
**Full Analysis (recommended):**
Click the red **🔍 Analyze** button → runs all modules sequentially with a live progress bar showing each step:

```
Step 1/7: Computing file hashes (MD5, SHA-256...)
Step 2/7: Analyzing file header & entropy...
Step 3/7: Extracting metadata...
Step 4/7: PE static analysis...
Step 5/7: Extracting strings...
Step 6/7: Running YARA rules...
Step 7/7: Querying VirusTotal...
```

After completion, the **Dashboard** displays the full risk assessment.

**Individual Modules:**
Click any sidebar item to run a single analysis module on the selected file.

#### 3️⃣ Review Results
- **Dashboard** — Risk score gauge (0-100), file info, stat cards, threat indicators
- **Sidebar panels** — Detailed results for each module

#### 4️⃣ Export Reports
Navigate to **Reports** → choose PDF, HTML, or JSON → select a save location.

---

## 📋 Available Modules

### File Analysis
| Module | What It Does |
|--------|-------------|
| **Integrity Check** | MD5, SHA-1, SHA-256, SHA-512, ssdeep hashes with copy buttons |
| **Header Analysis** | File type detection (50+ signatures), entropy calculation |
| **Hex Viewer** | Formatted hex dump with offset, hex bytes, and ASCII columns |
| **Forensic Imaging** | Bit-for-bit file copy with integrity verification |
| **Metadata / EXIF** | File properties, timestamps, EXIF tags, PE version info |

### Malware Analysis
| Module | What It Does |
|--------|-------------|
| **PE Analysis** | Tabbed view: Headers, Sections (entropy bars), Imports, Suspicious APIs, Threats |
| **Strings** | ASCII/Unicode extraction with suspicious pattern classification |
| **YARA Scan** | 17 built-in rules for packers, shellcode, ransomware, C2, etc. |
| **VirusTotal** | Hash-based lookup via API v3 (file is never uploaded) |

### Windows Forensics
| Module | What It Does |
|--------|-------------|
| **ADS Scanner** | NTFS Alternate Data Stream detection |
| **Process Analyzer** | Running process enumeration with suspicious flags |
| **Network Inspector** | Active TCP/UDP connections with owning process info |
| **Signature Verifier** | Authenticode digital signature verification |
| **Event Log Reader** | Security, System, Application log forensic events |

---

## ⚙️ Configuration

### VirusTotal API Key
Set your API key via any of these methods (checked in order):
1. Environment variable: `set VT_API_KEY=your_key_here`
2. File: Create `.vt_api_key` in the project root with just the key
3. The app will prompt you at runtime if neither is set

---

## ❓ Troubleshooting

| Issue | Solution |
|-------|----------|
| **App won't start** | Ensure `customtkinter` is installed: `pip install customtkinter` |
| **Module shows ❌** | Install the missing package (shown on Dashboard) |
| **VT says "No key"** | Set the `VT_API_KEY` environment variable |
| **Windows modules unavailable** | These use `ctypes` and only work on Windows |
| **YARA not available** | `pip install yara-python` (requires C build tools) |
