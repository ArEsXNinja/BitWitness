#!/usr/bin/env python3
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  BitWitness GUI — Native Python Desktop Application
#  Author : Rohit
#  Version: 4.0.0
#  Framework: CustomTkinter
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import os
import sys
import math
import time
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

# ── Ensure modules/ is on the path ──
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODULES_DIR = os.path.join(SCRIPT_DIR, "modules")
if MODULES_DIR not in sys.path:
    sys.path.insert(0, MODULES_DIR)

# ── Import analysis modules ──
from integrity import get_all_hashes, get_fuzzy_hash, SSDEEP_AVAILABLE
from hex_engine import (check_header, identify_file_type, hex_dump,
                        get_file_entropy, get_entropy_verdict, SIGNATURES)
from imaging import create_image
from metadata_extractor import get_file_metadata, get_exif_data, get_pe_metadata
from pe_analyzer import analyze_pe, is_pe_file, PEFILE_AVAILABLE
from strings_extractor import get_strings_summary
from yara_scanner import scan_file as yara_scan_file, get_rule_count, YARA_AVAILABLE
from vt_lookup import lookup_hash
from report_generator import (generate_html_report, generate_json_report,
                               generate_pdf_report, calculate_risk_score,
                               get_risk_verdict)
from ads_scanner import scan_ads, ADS_AVAILABLE
from process_analyzer import enumerate_processes, PROCESS_ANALYZER_AVAILABLE
from network_inspector import (get_tcp_connections, get_udp_endpoints,
                                NETWORK_INSPECTOR_AVAILABLE)
from sig_verifier import verify_signature, SIG_VERIFIER_AVAILABLE
from eventlog_reader import (read_forensic_events, get_log_summary,
                              EVENTLOG_AVAILABLE)


# ══════════════════════════════════════════════════════════════
#  THEME CONFIGURATION
# ══════════════════════════════════════════════════════════════
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# Colors
BG_DEEP      = "#080810"
BG_SURFACE   = "#0f0f1c"
BG_ELEVATED  = "#161628"
BG_CARD      = "#1a1a2e"
BG_HOVER     = "#22223a"
ACCENT_RED   = "#dc143c"
ACCENT_GREEN = "#00e676"
ACCENT_ORANGE= "#ff8c00"
ACCENT_CYAN  = "#00bcd4"
ACCENT_GOLD  = "#ffd700"
ACCENT_VIOLET= "#9c27b0"
TEXT_PRIMARY  = "#e4e4f0"
TEXT_SECOND   = "#9a9ab8"
TEXT_MUTED    = "#5a5a78"

FONT_UI      = ("Segoe UI", 13)
FONT_UI_BOLD = ("Segoe UI", 13, "bold")
FONT_UI_SM   = ("Segoe UI", 11)
FONT_MONO    = ("Consolas", 12)
FONT_MONO_SM = ("Consolas", 11)
FONT_TITLE   = ("Segoe UI", 18, "bold")
FONT_HEADING = ("Segoe UI", 15, "bold")


# ══════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ══════════════════════════════════════════════════════════════
class BitWitnessApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("BitWitness — Digital Forensics & Evidence Analysis")
        self.geometry("1300x800")
        self.minsize(1000, 600)
        self.configure(fg_color=BG_DEEP)

        self.file_path = None
        self._analysis_data = {}
        self._current_panel = None

        self._build_layout()
        self._show_panel("dashboard")

    # ── Layout ─────────────────────────────────────────────────
    def _build_layout(self):
        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=240, fg_color=BG_ELEVATED,
                                     corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        self._build_sidebar()

        # Right side
        right = ctk.CTkFrame(self, fg_color=BG_DEEP, corner_radius=0)
        right.pack(side="right", fill="both", expand=True)

        # Top bar
        self._build_topbar(right)

        # Content area
        self.content_frame = ctk.CTkFrame(right, fg_color=BG_DEEP, corner_radius=0)
        self.content_frame.pack(fill="both", expand=True, padx=16, pady=(8, 16))

    # ── Sidebar ────────────────────────────────────────────────
    def _build_sidebar(self):
        # Brand
        brand = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=16, pady=(16, 8))

        ctk.CTkLabel(brand, text="🛡️  BitWitness",
                     font=("Segoe UI", 17, "bold"),
                     text_color=TEXT_PRIMARY).pack(anchor="w")
        ctk.CTkLabel(brand, text="Forensics Framework v4.0",
                     font=FONT_UI_SM, text_color=TEXT_MUTED).pack(anchor="w")

        # Separator
        ctk.CTkFrame(self.sidebar, height=1, fg_color=BG_HOVER).pack(
            fill="x", padx=12, pady=8)

        self._nav_buttons = {}
        nav_items = [
            ("dashboard",   "🏠  Dashboard",         None),
            (None,          "── FILE ANALYSIS ──",    "section"),
            ("integrity",   "🔒  Integrity Check",    None),
            ("header",      "🔎  Header Analysis",    None),
            ("hex",         "📟  Hex Viewer",          None),
            ("imaging",     "💾  Forensic Imaging",    None),
            ("metadata",    "📋  Metadata / EXIF",     None),
            (None,          "── MALWARE ANALYSIS ──",  "section"),
            ("pe",          "⚙️  PE Analysis",         None),
            ("strings",     "📝  Strings",             None),
            ("yara",        "🛡️  YARA Scan",           None),
            ("virustotal",  "🦠  VirusTotal",          None),
            (None,          "── WINDOWS FORENSICS ──", "section"),
            ("ads",         "🔍  ADS Scanner",         None),
            ("processes",   "📊  Processes",           None),
            ("network",     "🌐  Network",             None),
            ("signatures",  "✍️  Signatures",          None),
            ("eventlogs",   "📜  Event Logs",          None),
            (None,          "── OUTPUT ──",            "section"),
            ("reports",     "📊  Reports",             None),
        ]

        for key, label, kind in nav_items:
            if kind == "section":
                ctk.CTkLabel(self.sidebar, text=label, font=("Segoe UI", 10),
                             text_color=TEXT_MUTED).pack(anchor="w", padx=20, pady=(12, 2))
            else:
                btn = ctk.CTkButton(
                    self.sidebar, text=label, font=FONT_UI_SM,
                    fg_color="transparent", hover_color=BG_HOVER,
                    text_color=TEXT_SECOND, anchor="w",
                    height=32, corner_radius=6,
                    command=lambda k=key: self._show_panel(k)
                )
                btn.pack(fill="x", padx=8, pady=1)
                self._nav_buttons[key] = btn

        # Footer
        spacer = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        spacer.pack(fill="both", expand=True)
        ctk.CTkFrame(self.sidebar, height=1, fg_color=BG_HOVER).pack(
            fill="x", padx=12, pady=4)
        ctk.CTkLabel(self.sidebar, text="● v4.0.0 · By Rohit",
                     font=("Segoe UI", 10), text_color=TEXT_MUTED).pack(
            anchor="w", padx=16, pady=(4, 12))

    # ── Top Bar ────────────────────────────────────────────────
    def _build_topbar(self, parent):
        topbar = ctk.CTkFrame(parent, height=56, fg_color=BG_SURFACE,
                              corner_radius=0)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)

        inner = ctk.CTkFrame(topbar, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=10)

        ctk.CTkLabel(inner, text="📂", font=("Segoe UI", 16)).pack(
            side="left", padx=(0, 6))

        self.file_entry = ctk.CTkEntry(
            inner, placeholder_text="Enter or browse target file path...",
            font=FONT_MONO_SM, width=450, height=34,
            fg_color=BG_CARD, border_color=BG_HOVER,
            text_color=TEXT_PRIMARY
        )
        self.file_entry.pack(side="left", padx=(0, 8))

        ctk.CTkButton(inner, text="Browse", font=FONT_UI_SM,
                      width=80, height=34, fg_color=BG_HOVER,
                      hover_color="#2a2a48", text_color=TEXT_PRIMARY,
                      command=self._browse_file).pack(side="left", padx=(0, 8))

        ctk.CTkButton(inner, text="🔍 Analyze", font=FONT_UI_BOLD,
                      width=110, height=34,
                      fg_color=ACCENT_RED, hover_color="#b30000",
                      text_color="white",
                      command=self._run_full_analysis).pack(side="left")

        # Stats
        stats_frame = ctk.CTkFrame(inner, fg_color="transparent")
        stats_frame.pack(side="right")
        for label, val in [("Modules", "14"), ("YARA", str(get_rule_count()) if YARA_AVAILABLE else "N/A"),
                           ("Sigs", str(len(SIGNATURES)))]:
            ctk.CTkLabel(stats_frame, text=f"{label}: ",
                         font=FONT_UI_SM, text_color=TEXT_MUTED).pack(side="left")
            ctk.CTkLabel(stats_frame, text=val,
                         font=("Segoe UI", 12, "bold"),
                         text_color=TEXT_PRIMARY).pack(side="left", padx=(0, 14))

    # ── Panel Switching ────────────────────────────────────────
    def _show_panel(self, panel_id):
        # Update nav highlight
        for key, btn in self._nav_buttons.items():
            if key == panel_id:
                btn.configure(fg_color=ACCENT_RED, text_color="white",
                              hover_color="#b30000")
            else:
                btn.configure(fg_color="transparent", text_color=TEXT_SECOND,
                              hover_color=BG_HOVER)

        # Clear content
        for w in self.content_frame.winfo_children():
            w.destroy()

        self._current_panel = panel_id

        # Build panel
        builders = {
            "dashboard":   self._panel_dashboard,
            "integrity":   self._panel_integrity,
            "header":      self._panel_header,
            "hex":         self._panel_hex,
            "imaging":     self._panel_imaging,
            "metadata":    self._panel_metadata,
            "pe":          self._panel_pe,
            "strings":     self._panel_strings,
            "yara":        self._panel_yara,
            "virustotal":  self._panel_virustotal,
            "ads":         self._panel_ads,
            "processes":   self._panel_processes,
            "network":     self._panel_network,
            "signatures":  self._panel_signatures,
            "eventlogs":   self._panel_eventlogs,
            "reports":     self._panel_reports,
        }
        builder = builders.get(panel_id, self._panel_dashboard)
        builder()

    # ── Helpers ────────────────────────────────────────────────
    def _browse_file(self):
        path = filedialog.askopenfilename(title="Select Target File")
        if path:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, path)
            self.file_path = path

    def _get_file(self):
        path = self.file_entry.get().strip().strip('"').strip("'")
        if not path or not os.path.isfile(path):
            messagebox.showwarning("BitWitness",
                                   "Please select a valid file first.")
            return None
        self.file_path = path
        return path

    def _make_scrollable(self, parent=None):
        """Create a scrollable frame in the content area."""
        if parent is None:
            parent = self.content_frame
        scroll = ctk.CTkScrollableFrame(parent, fg_color="transparent",
                                         corner_radius=0)
        scroll.pack(fill="both", expand=True)
        return scroll

    def _add_title(self, parent, icon, title, desc=""):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(frame, text=f"{icon}  {title}", font=FONT_TITLE,
                     text_color=TEXT_PRIMARY).pack(side="left")
        if desc:
            ctk.CTkLabel(frame, text=f"  — {desc}", font=FONT_UI,
                         text_color=TEXT_MUTED).pack(side="left", padx=(4, 0))

    def _add_card(self, parent, title=None):
        card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BG_HOVER)
        card.pack(fill="x", pady=(0, 12))
        if title:
            ctk.CTkLabel(card, text=title, font=FONT_UI_BOLD,
                         text_color=TEXT_SECOND).pack(
                anchor="w", padx=16, pady=(12, 4))
        return card

    def _add_row(self, parent, label, value, val_color=TEXT_PRIMARY):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=3)
        ctk.CTkLabel(row, text=label, font=FONT_UI_SM,
                     text_color=TEXT_MUTED, width=160,
                     anchor="w").pack(side="left")
        ctk.CTkLabel(row, text=str(value), font=FONT_MONO_SM,
                     text_color=val_color, anchor="w",
                     wraplength=700).pack(side="left", fill="x", expand=True)

    def _add_status(self, parent, text, color=ACCENT_GREEN):
        ctk.CTkLabel(parent, text=text, font=FONT_UI_SM,
                     text_color=color).pack(anchor="w", padx=16, pady=4)

    def _run_threaded(self, func, callback, *args):
        """Run func in a thread, call callback(result) on completion."""
        def worker():
            try:
                result = func(*args)
                self.after(0, callback, result)
            except Exception as e:
                self.after(0, callback, {"error": str(e)})
        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def _add_loading(self, parent, msg="Analyzing..."):
        lbl = ctk.CTkLabel(parent, text=f"⏳ {msg}", font=FONT_UI,
                           text_color=ACCENT_CYAN)
        lbl.pack(anchor="w", padx=16, pady=8)
        return lbl

    # ── Risk Gauge (Canvas) ─────────────────────────────────
    def _draw_risk_gauge(self, parent, score):
        """Draw an animated arc-based risk gauge on a Canvas."""
        size = 180
        canvas = tk.Canvas(parent, width=size, height=size,
                           bg=BG_CARD, highlightthickness=0, bd=0)
        canvas.pack(pady=(12, 4))

        cx, cy, r = size // 2, size // 2, 70
        lw = 12

        # Background arc (270 degrees, from 135 to 405)
        canvas.create_arc(cx - r, cy - r, cx + r, cy + r,
                          start=135, extent=270,
                          style="arc", width=lw, outline=BG_HOVER)

        # Score arc
        color = ACCENT_RED if score >= 70 else ACCENT_ORANGE if score >= 40 else ACCENT_GREEN
        extent = (score / 100) * 270
        canvas.create_arc(cx - r, cy - r, cx + r, cy + r,
                          start=135 + 270 - extent, extent=extent,
                          style="arc", width=lw, outline=color)

        # Center text
        canvas.create_text(cx, cy - 8, text=str(score),
                           fill=color, font=("Segoe UI", 28, "bold"))
        canvas.create_text(cx, cy + 18, text="RISK SCORE",
                           fill=TEXT_MUTED, font=("Segoe UI", 8))
        return canvas

    # ── Summary Stat Card ──────────────────────────────────────
    def _add_stat_card(self, parent, icon, label, value, color=TEXT_PRIMARY):
        """Small stat card with icon, label, value."""
        card = ctk.CTkFrame(parent, fg_color=BG_ELEVATED, corner_radius=10,
                            border_width=1, border_color=BG_HOVER,
                            height=80)
        card.pack_propagate(False)
        ctk.CTkLabel(card, text=icon, font=("Segoe UI", 20)).pack(
            anchor="w", padx=14, pady=(10, 0))
        ctk.CTkLabel(card, text=str(value), font=("Segoe UI", 16, "bold"),
                     text_color=color).pack(anchor="w", padx=14)
        ctk.CTkLabel(card, text=label, font=("Segoe UI", 9),
                     text_color=TEXT_MUTED).pack(anchor="w", padx=14)
        return card

    # ══════════════════════════════════════════════════════════
    #  PANEL: Dashboard
    # ══════════════════════════════════════════════════════════
    def _panel_dashboard(self):
        scroll = self._make_scrollable()
        self._add_title(scroll, "🏠", "Dashboard", "Overview & Risk Assessment")

        has_file = self.file_path and os.path.isfile(self.file_path)
        has_data = bool(self._analysis_data)

        # ── Top row: Risk Gauge + File Info ───
        top_row = ctk.CTkFrame(scroll, fg_color="transparent")
        top_row.pack(fill="x", pady=(0, 12))

        # Risk gauge card
        gauge_card = ctk.CTkFrame(top_row, fg_color=BG_CARD, corner_radius=12,
                                   border_width=1, border_color=BG_HOVER,
                                   width=220)
        gauge_card.pack(side="left", fill="y", padx=(0, 12))
        gauge_card.pack_propagate(False)

        if has_data:
            score = calculate_risk_score(self._analysis_data)
            verdict, _ = get_risk_verdict(score)
            color = ACCENT_RED if score >= 70 else ACCENT_ORANGE if score >= 40 else ACCENT_GREEN
            self._draw_risk_gauge(gauge_card, score)
            ctk.CTkLabel(gauge_card, text=verdict, font=FONT_UI_BOLD,
                         text_color=color).pack(pady=(0, 8))
        else:
            self._draw_risk_gauge(gauge_card, 0)
            ctk.CTkLabel(gauge_card, text="NO DATA", font=FONT_UI_SM,
                         text_color=TEXT_MUTED).pack(pady=(0, 8))

        # File info card
        file_card = ctk.CTkFrame(top_row, fg_color=BG_CARD, corner_radius=12,
                                  border_width=1, border_color=BG_HOVER)
        file_card.pack(side="left", fill="both", expand=True)
        ctk.CTkLabel(file_card, text="🎯 TARGET FILE", font=FONT_UI_BOLD,
                     text_color=TEXT_SECOND).pack(
            anchor="w", padx=16, pady=(12, 4))

        if has_file:
            size = os.path.getsize(self.file_path)
            size_mb = size / (1024 * 1024)
            self._add_row(file_card, "Filename", os.path.basename(self.file_path))
            self._add_row(file_card, "Path", self.file_path)
            self._add_row(file_card, "Size", f"{size:,} bytes ({size_mb:.2f} MB)")
            self._add_row(file_card, "Extension",
                          os.path.splitext(self.file_path)[1] or "N/A")
            # Show key results if available
            if self._analysis_data.get("hashes"):
                sha256 = self._analysis_data["hashes"].get("sha256", "")
                self._add_row(file_card, "SHA-256", sha256, ACCENT_GREEN)
            if self._analysis_data.get("vt"):
                vt = self._analysis_data["vt"]
                if vt.get("status") == "found":
                    self._add_row(file_card, "VT Verdict",
                                  f"{vt.get('verdict', '?')} ({vt.get('detection_ratio', '?')})",
                                  ACCENT_RED if vt.get('verdict') == 'MALICIOUS' else ACCENT_ORANGE)
        else:
            self._add_status(file_card,
                            "No file selected — use Browse or enter a path above.",
                            TEXT_MUTED)
        ctk.CTkFrame(file_card, height=8, fg_color="transparent").pack()

        # ── Summary stat cards row ───
        if has_data:
            stats_row = ctk.CTkFrame(scroll, fg_color="transparent")
            stats_row.pack(fill="x", pady=(0, 12))
            stats_row.columnconfigure((0,1,2,3), weight=1)

            # Gather stats
            n_strings = self._analysis_data.get("strings", {}).get("suspicious_count", 0)
            n_yara = self._analysis_data.get("yara", {}).get("total_matches", 0)
            n_sus_apis = len(self._analysis_data.get("pe_analysis", {}).get("suspicious_apis", []))
            entropy_val = self._analysis_data.get("entropy", "N/A")
            if isinstance(entropy_val, float):
                entropy_str = f"{entropy_val:.2f}"
            else:
                entropy_str = str(entropy_val)

            stat_data = [
                ("📝", "Sus. Strings", str(n_strings), ACCENT_RED if n_strings > 0 else ACCENT_GREEN),
                ("🛡️", "YARA Matches", str(n_yara), ACCENT_RED if n_yara > 0 else ACCENT_GREEN),
                ("⚠️", "Sus. APIs", str(n_sus_apis), ACCENT_ORANGE if n_sus_apis > 0 else ACCENT_GREEN),
                ("📊", "Entropy", entropy_str, ACCENT_ORANGE if isinstance(entropy_val, float) and entropy_val > 6.5 else ACCENT_CYAN),
            ]
            for col, (ic, lbl, val, clr) in enumerate(stat_data):
                sc = self._add_stat_card(stats_row, ic, lbl, val, clr)
                sc.grid(row=0, column=col, padx=4, sticky="nsew")
                sc.pack_forget()  # Remove pack since we're using grid
                sc.grid(row=0, column=col, padx=4, sticky="nsew")

        # ── Module status ───
        card2 = self._add_card(scroll, "📦 Module Status")
        modules = [
            ("pefile", PEFILE_AVAILABLE), ("yara-python", YARA_AVAILABLE),
            ("ssdeep", SSDEEP_AVAILABLE), ("WinAPI: ADS", ADS_AVAILABLE),
            ("WinAPI: Process", PROCESS_ANALYZER_AVAILABLE),
            ("WinAPI: Network", NETWORK_INSPECTOR_AVAILABLE),
            ("WinAPI: Signatures", SIG_VERIFIER_AVAILABLE),
            ("WinAPI: EventLog", EVENTLOG_AVAILABLE),
        ]
        grid = ctk.CTkFrame(card2, fg_color="transparent")
        grid.pack(fill="x", padx=16, pady=(4, 12))
        for i, (name, avail) in enumerate(modules):
            icon = "✅" if avail else "❌"
            color = ACCENT_GREEN if avail else ACCENT_RED
            lbl = ctk.CTkLabel(grid, text=f"{icon} {name}",
                               font=FONT_UI_SM, text_color=color)
            lbl.grid(row=i // 4, column=i % 4, sticky="w", padx=10, pady=3)

        # ── Threat indicators ───
        if self._analysis_data.get("pe_analysis"):
            card3 = self._add_card(scroll, "⚠️ Threat Indicators")
            for ind in self._analysis_data["pe_analysis"].get("indicators", []):
                sev = ind["severity"]
                color = ACCENT_RED if sev == "HIGH" else ACCENT_ORANGE if sev == "MEDIUM" else ACCENT_CYAN
                self._add_status(card3, f"[{sev}] {ind['type']}: {ind['detail']}", color)
            ctk.CTkFrame(card3, height=8, fg_color="transparent").pack()

    # ══════════════════════════════════════════════════════════
    #  PANEL: Integrity Check
    # ══════════════════════════════════════════════════════════
    def _panel_integrity(self):
        scroll = self._make_scrollable()
        self._add_title(scroll, "🔒", "Integrity Check", "Multi-Algorithm Hashing")

        fp = self._get_file()
        if not fp:
            return

        card = self._add_card(scroll, "Computing hashes...")
        loading = self._add_loading(card)

        def on_done(hashes):
            loading.destroy()
            if "error" in hashes:
                self._add_status(card, f"Error: {hashes['error']}", ACCENT_RED)
                return
            self._analysis_data["hashes"] = hashes
            for algo in ["md5", "sha1", "sha256", "sha512"]:
                color = ACCENT_GREEN if algo == "sha256" else TEXT_PRIMARY
                self._add_row(card, algo.upper(), hashes[algo], color)

            fuzzy = get_fuzzy_hash(fp)
            if fuzzy:
                self._add_row(card, "SSDEEP", fuzzy, ACCENT_CYAN)
            elif not SSDEEP_AVAILABLE:
                self._add_row(card, "SSDEEP", "Not installed", TEXT_MUTED)
            ctk.CTkFrame(card, height=8, fg_color="transparent").pack()

        self._run_threaded(get_all_hashes, on_done, fp)

    # ══════════════════════════════════════════════════════════
    #  PANEL: Header Analysis
    # ══════════════════════════════════════════════════════════
    def _panel_header(self):
        scroll = self._make_scrollable()
        self._add_title(scroll, "🔎", "Header Analysis", "File Signature & Entropy")

        fp = self._get_file()
        if not fp:
            return

        card = self._add_card(scroll, "File Type Detection")
        result = check_header(fp)
        types = identify_file_type(fp)
        for t in types:
            color = ACCENT_GREEN if t["confidence"] == "HIGH" else ACCENT_ORANGE
            self._add_row(card, "Detected", f"{t['type']}  [{t['confidence']}]", color)
        self._add_row(card, "Verdict", result)

        # Raw header
        try:
            with open(fp, "rb") as f:
                raw = f.read(16)
            hex_str = " ".join(f"{b:02X}" for b in raw)
            self._add_row(card, "Raw Header", hex_str, ACCENT_CYAN)
        except Exception:
            pass

        # Entropy
        entropy = get_file_entropy(fp)
        if isinstance(entropy, float):
            verdict = get_entropy_verdict(entropy)
            color = ACCENT_RED if entropy > 7.0 else ACCENT_ORANGE if entropy > 6.0 else ACCENT_GREEN
            self._add_row(card, "Entropy", f"{entropy:.4f} — {verdict}", color)

        self._add_row(card, "Known Signatures", f"{len(SIGNATURES)} in database")
        ctk.CTkFrame(card, height=8, fg_color="transparent").pack()

    # ══════════════════════════════════════════════════════════
    #  PANEL: Hex Viewer
    # ══════════════════════════════════════════════════════════
    def _panel_hex(self):
        scroll = self._make_scrollable()
        self._add_title(scroll, "📟", "Hex Viewer", "Binary Data Inspector")

        fp = self._get_file()
        if not fp:
            return

        card = self._add_card(scroll, "Hex Dump (first 256 bytes)")
        dump = hex_dump(fp, 0, 256)

        # Header row
        hdr = ctk.CTkFrame(card, fg_color=BG_ELEVATED)
        hdr.pack(fill="x", padx=12, pady=(8, 0))
        ctk.CTkLabel(hdr, text="OFFSET", font=("Consolas", 10, "bold"),
                     text_color=TEXT_MUTED, width=80).pack(side="left", padx=4)
        ctk.CTkLabel(hdr, text="HEX DUMP", font=("Consolas", 10, "bold"),
                     text_color=TEXT_MUTED, width=400).pack(side="left", padx=4)
        ctk.CTkLabel(hdr, text="ASCII", font=("Consolas", 10, "bold"),
                     text_color=TEXT_MUTED).pack(side="left", padx=4)

        for dl in dump:
            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=1)
            ctk.CTkLabel(row, text=dl["offset"], font=FONT_MONO_SM,
                         text_color=ACCENT_CYAN, width=80).pack(side="left", padx=4)
            ctk.CTkLabel(row, text=dl["hex"], font=FONT_MONO_SM,
                         text_color=TEXT_PRIMARY, width=400,
                         anchor="w").pack(side="left", padx=4)
            ctk.CTkLabel(row, text=dl["ascii"], font=FONT_MONO_SM,
                         text_color=ACCENT_GREEN).pack(side="left", padx=4)
        ctk.CTkFrame(card, height=8, fg_color="transparent").pack()

    # ══════════════════════════════════════════════════════════
    #  PANEL: Forensic Imaging
    # ══════════════════════════════════════════════════════════
    def _panel_imaging(self):
        scroll = self._make_scrollable()
        self._add_title(scroll, "💾", "Forensic Imaging", "Bit-for-Bit Copy")

        card = self._add_card(scroll, "Create Forensic Image")
        self._add_status(card, "Select source file above, then choose destination.",
                        TEXT_MUTED)

        dest_entry = ctk.CTkEntry(card, placeholder_text="Destination path...",
                                   font=FONT_MONO_SM, width=450,
                                   fg_color=BG_ELEVATED, border_color=BG_HOVER)
        dest_entry.pack(padx=16, pady=8)

        def do_imaging():
            fp = self._get_file()
            if not fp:
                return
            dest = dest_entry.get().strip()
            if not dest:
                dest = filedialog.asksaveasfilename(
                    title="Save Forensic Copy",
                    defaultextension=os.path.splitext(fp)[1])
            if not dest:
                return
            ok = create_image(fp, dest)
            if ok:
                self._add_status(card, f"✅ Image saved → {dest}", ACCENT_GREEN)
            else:
                self._add_status(card, "❌ Imaging failed", ACCENT_RED)

        ctk.CTkButton(card, text="Create Image", font=FONT_UI_BOLD,
                      fg_color=ACCENT_RED, hover_color="#b30000",
                      command=do_imaging).pack(padx=16, pady=(0, 12))

    # ══════════════════════════════════════════════════════════
    #  PANEL: Metadata
    # ══════════════════════════════════════════════════════════
    def _panel_metadata(self):
        scroll = self._make_scrollable()
        self._add_title(scroll, "📋", "Metadata Extraction", "File Properties & EXIF")

        fp = self._get_file()
        if not fp:
            return

        # File metadata
        meta = get_file_metadata(fp)
        card = self._add_card(scroll, "📁 File System Properties")
        if "error" not in meta:
            for key in ["file_name", "full_path", "size_human", "created",
                        "modified", "accessed", "permissions"]:
                self._add_row(card, key.replace("_", " ").title(),
                              meta.get(key, "N/A"))
        ctk.CTkFrame(card, height=8, fg_color="transparent").pack()

        # EXIF
        exif = get_exif_data(fp)
        if exif.get("available"):
            card2 = self._add_card(scroll,
                                    f"📸 EXIF Data ({exif.get('tag_count', 0)} tags)")
            for k, v in exif.get("summary", {}).items():
                self._add_row(card2, k, str(v)[:80])
            gps = exif.get("gps", {})
            if gps:
                self._add_status(card2, "⚠️ GPS LOCATION DATA FOUND", ACCENT_RED)
                for k, v in gps.items():
                    self._add_row(card2, f"GPS.{k}", str(v)[:80], ACCENT_RED)
            ctk.CTkFrame(card2, height=8, fg_color="transparent").pack()

        # PE version info
        pe_meta = get_pe_metadata(fp)
        if pe_meta.get("available"):
            card3 = self._add_card(scroll, "⚙️ PE Version Info")
            for k, v in pe_meta["version_info"].items():
                self._add_row(card3, k, str(v)[:80])
            ctk.CTkFrame(card3, height=8, fg_color="transparent").pack()

    # ══════════════════════════════════════════════════════════
    #  PANEL: PE Analysis
    # ══════════════════════════════════════════════════════════
    def _panel_pe(self):
        scroll = self._make_scrollable()
        self._add_title(scroll, "⚙️", "PE Static Analysis", "PEStudio-Style")

        fp = self._get_file()
        if not fp:
            return

        if not PEFILE_AVAILABLE:
            self._add_status(scroll, "pefile not installed: pip install pefile",
                            ACCENT_RED)
            return
        if not is_pe_file(fp):
            self._add_status(scroll, "Not a PE file — skipping.", ACCENT_ORANGE)
            return

        card = self._add_card(scroll, "Parsing PE structure...")
        loading = self._add_loading(card)

        def on_done(result):
            loading.destroy()
            if "error" in result:
                self._add_status(card, f"Error: {result['error']}", ACCENT_RED)
                return
            self._analysis_data["pe_analysis"] = result

            # ── Tabbed view ──
            tabview = ctk.CTkTabview(scroll, fg_color=BG_CARD,
                                     segmented_button_fg_color=BG_ELEVATED,
                                     segmented_button_selected_color=ACCENT_RED,
                                     segmented_button_unselected_color=BG_HOVER,
                                     corner_radius=12, height=500)
            tabview.pack(fill="x", pady=(0, 12))

            # Tab 1: Headers
            tab_hdr = tabview.add("Headers")
            basic = result.get("basic", {})
            for key in ["pe_type", "machine", "compile_time", "entry_point",
                        "image_base", "subsystem", "num_sections"]:
                self._add_row(tab_hdr, key.replace("_", " ").title(),
                              basic.get(key, "N/A"))
            imphash = result.get("imphash")
            if imphash:
                self._add_row(tab_hdr, "Imphash", imphash, ACCENT_VIOLET)

            # Tab 2: Sections with entropy bars
            tab_sec = tabview.add("Sections")
            sections = result.get("sections", [])
            for s in sections:
                sec_row = ctk.CTkFrame(tab_sec, fg_color=BG_ELEVATED,
                                       corner_radius=8)
                sec_row.pack(fill="x", padx=8, pady=3)

                # Name + flags
                flags = []
                if s["high_entropy"]:
                    flags.append("⚠ PACKED")
                if s["suspicious_name"]:
                    flags.append("⚠ SUS")
                name_color = ACCENT_RED if flags else ACCENT_CYAN
                ctk.CTkLabel(sec_row, text=s["name"], font=FONT_MONO,
                             text_color=name_color, width=80).pack(
                    side="left", padx=(10, 6))

                # Sizes
                ctk.CTkLabel(sec_row, text=f"V:{s['virtual_size']:,}  R:{s['raw_size']:,}",
                             font=("Consolas", 10), text_color=TEXT_MUTED,
                             width=200).pack(side="left", padx=4)

                # Entropy progress bar
                ent = s["entropy"]
                ent_color = ACCENT_RED if ent > 7.0 else ACCENT_ORANGE if ent > 6.0 else ACCENT_GREEN
                bar = ctk.CTkProgressBar(sec_row, width=100, height=8,
                                          progress_color=ent_color,
                                          fg_color=BG_HOVER, corner_radius=4)
                bar.pack(side="left", padx=6)
                bar.set(ent / 8.0)
                ctk.CTkLabel(sec_row, text=f"{ent:.2f}",
                             font=("Consolas", 10, "bold"),
                             text_color=ent_color).pack(side="left", padx=4)

                if flags:
                    ctk.CTkLabel(sec_row, text=" ".join(flags),
                                 font=("Segoe UI", 9, "bold"),
                                 text_color=ACCENT_RED).pack(side="left", padx=6)
                ctk.CTkFrame(sec_row, height=4, fg_color="transparent").pack()

            # Tab 3: Imports
            tab_imp = tabview.add("Imports")
            imports = result.get("imports", [])
            if imports:
                for imp in imports:
                    self._add_row(tab_imp, imp.get("dll", "?"),
                                  f"{imp.get('count', '?')} functions", ACCENT_CYAN)
            else:
                self._add_status(tab_imp, "No import data available.", TEXT_MUTED)

            # Tab 4: Suspicious APIs
            tab_sus = tabview.add("Sus. APIs")
            sus = result.get("suspicious_apis", [])
            if sus:
                ctk.CTkLabel(tab_sus, text=f"⚠ {len(sus)} Suspicious API Imports",
                             font=FONT_UI_BOLD, text_color=ACCENT_RED).pack(
                    anchor="w", padx=12, pady=6)
                for a in sus:
                    row = ctk.CTkFrame(tab_sus, fg_color=BG_ELEVATED,
                                       corner_radius=6)
                    row.pack(fill="x", padx=8, pady=2)
                    ctk.CTkLabel(row, text=a["dll"], font=FONT_MONO_SM,
                                 text_color=ACCENT_GOLD, width=160).pack(
                        side="left", padx=(10, 4))
                    ctk.CTkLabel(row, text="→", font=FONT_UI_SM,
                                 text_color=TEXT_MUTED).pack(side="left")
                    ctk.CTkLabel(row, text=a["func"], font=("Consolas", 12, "bold"),
                                 text_color=ACCENT_RED).pack(
                        side="left", padx=6)
            else:
                self._add_status(tab_sus, "✅ No suspicious APIs detected.",
                                ACCENT_GREEN)

            # Tab 5: Threats
            tab_thr = tabview.add("Threats")
            inds = result.get("indicators", [])
            if inds:
                for ind in inds:
                    sev = ind["severity"]
                    color = (ACCENT_RED if sev == "HIGH" else
                             ACCENT_ORANGE if sev == "MEDIUM" else
                             ACCENT_CYAN if sev == "LOW" else ACCENT_GREEN)
                    icon = {"HIGH": "🔴", "MEDIUM": "🟠",
                            "LOW": "🟡", "OK": "🟢"}.get(sev, "⚪")
                    self._add_status(tab_thr,
                                    f"{icon} [{sev}] {ind['type']}: {ind['detail']}",
                                    color)
            else:
                self._add_status(tab_thr, "✅ No threat indicators found.",
                                ACCENT_GREEN)

        self._run_threaded(analyze_pe, on_done, fp)

    # ══════════════════════════════════════════════════════════
    #  PANEL: Strings
    # ══════════════════════════════════════════════════════════
    def _panel_strings(self):
        scroll = self._make_scrollable()
        self._add_title(scroll, "📝", "Strings Extraction", "ASCII & Unicode")

        fp = self._get_file()
        if not fp:
            return

        card = self._add_card(scroll, "Extracting strings...")
        loading = self._add_loading(card)

        def on_done(result):
            loading.destroy()
            if "error" in result:
                self._add_status(card, f"Error: {result['error']}", ACCENT_RED)
                return
            self._analysis_data["strings"] = result
            self._add_row(card, "Total", f"{result['total_count']:,}")
            self._add_row(card, "ASCII", f"{result['ascii_count']:,}")
            self._add_row(card, "Unicode", f"{result['unicode_count']:,}")
            self._add_row(card, "Suspicious",
                          f"{result.get('suspicious_count', 0)}",
                          ACCENT_RED if result.get('suspicious_count', 0) > 0 else ACCENT_GREEN)
            ctk.CTkFrame(card, height=8, fg_color="transparent").pack()

            suspicious = result.get("suspicious", {})
            if suspicious:
                card2 = self._add_card(scroll, "⚠️ Suspicious Strings")
                for cat, items in suspicious.items():
                    self._add_status(card2, f"  {cat} ({len(items)} found):",
                                    ACCENT_GOLD)
                    for item in items[:8]:
                        self._add_status(card2, f"    ▸ {item}", TEXT_PRIMARY)
                    if len(items) > 8:
                        self._add_status(card2,
                                        f"    ... and {len(items) - 8} more",
                                        TEXT_MUTED)
                ctk.CTkFrame(card2, height=8, fg_color="transparent").pack()

        self._run_threaded(get_strings_summary, on_done, fp, 80)

    # ══════════════════════════════════════════════════════════
    #  PANEL: YARA Scan
    # ══════════════════════════════════════════════════════════
    def _panel_yara(self):
        scroll = self._make_scrollable()
        self._add_title(scroll, "🛡️", "YARA Scan", "Rule-Based Detection")

        if not YARA_AVAILABLE:
            self._add_status(scroll,
                            "yara-python not installed: pip install yara-python",
                            ACCENT_ORANGE)
            return

        fp = self._get_file()
        if not fp:
            return

        card = self._add_card(scroll, f"Scanning with {get_rule_count()} rules...")
        loading = self._add_loading(card)

        def on_done(result):
            loading.destroy()
            if "error" in result:
                self._add_status(card, f"Error: {result['error']}", ACCENT_RED)
                return
            self._analysis_data["yara"] = result
            total = result.get("total_matches", 0)
            if total == 0:
                self._add_status(card, "✅ No YARA rules matched — file appears clean.",
                                ACCENT_GREEN)
            else:
                self._add_status(card, f"⚠️ {total} rule(s) matched!", ACCENT_RED)
            ctk.CTkFrame(card, height=8, fg_color="transparent").pack()

            for m in result.get("matches", []):
                sev = m.get("severity", "low")
                color = (ACCENT_RED if sev == "critical" else
                         ACCENT_ORANGE if sev == "high" else
                         ACCENT_GOLD if sev == "medium" else ACCENT_CYAN)
                icon = {"critical": "🔴", "high": "🟠",
                        "medium": "🟡", "low": "🟢"}.get(sev, "⚪")
                mc = self._add_card(scroll,
                                     f"{icon} {m['rule']}  [{sev.upper()}]")
                self._add_status(mc, m.get("description", "N/A"), TEXT_SECOND)
                self._add_status(mc, f"Category: {m.get('category', 'N/A')}",
                                TEXT_MUTED)
                for ms in m.get("matched_strings", [])[:5]:
                    self._add_status(
                        mc,
                        f"  @ {ms['offset']} {ms['identifier']}: {ms['data']}",
                        TEXT_MUTED)
                ctk.CTkFrame(mc, height=8, fg_color="transparent").pack()

        self._run_threaded(yara_scan_file, on_done, fp)

    # ══════════════════════════════════════════════════════════
    #  PANEL: VirusTotal
    # ══════════════════════════════════════════════════════════
    def _panel_virustotal(self):
        scroll = self._make_scrollable()
        self._add_title(scroll, "🦠", "VirusTotal Lookup", "Hash-Based")

        fp = self._get_file()
        if not fp:
            return

        # ── Check if API key already exists ──
        from vt_lookup import _get_api_key
        existing_key = _get_api_key()

        if not existing_key:
            # Show API key input card
            key_card = self._add_card(scroll, "🔑 VirusTotal API Key Required")
            self._add_status(key_card,
                            "No API key found. Get a free key from virustotal.com",
                            ACCENT_ORANGE)
            self._add_status(key_card,
                            "Your key will be saved locally and reused automatically.",
                            TEXT_MUTED)

            key_entry = ctk.CTkEntry(key_card,
                                      placeholder_text="Paste your VirusTotal API key here...",
                                      font=FONT_MONO_SM, width=500,
                                      fg_color=BG_ELEVATED, border_color=BG_HOVER,
                                      show="•")
            key_entry.pack(padx=16, pady=(8, 4))

            # Toggle visibility
            show_var = ctk.BooleanVar(value=False)
            def toggle_show():
                key_entry.configure(show="" if show_var.get() else "•")
            ctk.CTkCheckBox(key_card, text="Show key", variable=show_var,
                           command=toggle_show, font=FONT_UI_SM,
                           text_color=TEXT_MUTED, fg_color=ACCENT_RED,
                           hover_color="#b30000").pack(anchor="w", padx=16, pady=(0, 4))

            status_label = ctk.CTkLabel(key_card, text="", font=FONT_UI_SM,
                                         text_color=ACCENT_RED)
            status_label.pack(anchor="w", padx=16)

            def save_and_lookup():
                api_key = key_entry.get().strip()
                if not api_key:
                    status_label.configure(text="⚠️ Please enter an API key.")
                    return
                if len(api_key) < 20:
                    status_label.configure(text="⚠️ Key looks too short. Check and retry.")
                    return
                # Save key to .vt_api_key in project root
                key_file = os.path.join(SCRIPT_DIR, ".vt_api_key")
                try:
                    with open(key_file, "w") as f:
                        f.write(api_key)
                    status_label.configure(text="✅ Key saved!", text_color=ACCENT_GREEN)
                except Exception as e:
                    status_label.configure(text=f"❌ Could not save: {e}")
                    return
                # Now run the lookup
                key_card.pack_forget()
                self._do_vt_lookup(scroll, fp, api_key)

            ctk.CTkButton(key_card, text="💾  Save & Lookup", font=FONT_UI_BOLD,
                          fg_color=ACCENT_RED, hover_color="#b30000",
                          command=save_and_lookup).pack(padx=16, pady=(4, 12))
            return

        # Key exists — run lookup directly
        self._do_vt_lookup(scroll, fp, existing_key)

    def _do_vt_lookup(self, scroll, fp, api_key):
        """Run the actual VirusTotal lookup with the given API key."""
        card = self._add_card(scroll, "Querying VirusTotal...")
        self._add_status(card,
                        "Only the file HASH is sent — file is NEVER uploaded.",
                        TEXT_MUTED)
        loading = self._add_loading(card)

        def on_done(result):
            loading.destroy()
            self._analysis_data["vt"] = result
            status = result.get("status", "")
            if status == "found":
                verdict = result.get("verdict", "UNKNOWN")
                color = (ACCENT_RED if verdict == "MALICIOUS" else
                         ACCENT_ORANGE if verdict == "SUSPICIOUS" else
                         ACCENT_GREEN)
                self._add_row(card, "Verdict", verdict, color)
                self._add_row(card, "Detection",
                              result.get("detection_ratio", "N/A"), color)
                self._add_row(card, "Threat Label",
                              result.get("threat_label", "N/A"), ACCENT_ORANGE)
                self._add_row(card, "File Type",
                              result.get("file_type", "N/A"))
                self._add_row(card, "Reputation",
                              str(result.get("reputation", "N/A")))
                ctk.CTkFrame(card, height=8, fg_color="transparent").pack()

                dets = result.get("detections", [])
                if dets:
                    card2 = self._add_card(scroll,
                                            f"🔍 Engine Detections ({len(dets)})")
                    for d in dets[:20]:
                        self._add_row(card2, d["engine"], d["result"],
                                      ACCENT_RED)
                    ctk.CTkFrame(card2, height=8, fg_color="transparent").pack()
            elif status == "not_found":
                self._add_status(card, "File hash not found in VT database.",
                                ACCENT_CYAN)
            elif status == "no_key":
                self._add_status(card,
                                "No API key. Set VT_API_KEY or create .vt_api_key",
                                ACCENT_ORANGE)
            else:
                self._add_status(card,
                                f"Error: {result.get('error', 'Unknown')}",
                                ACCENT_RED)

        self._run_threaded(lookup_hash, on_done, fp, api_key)

    # ══════════════════════════════════════════════════════════
    #  PANEL: ADS Scanner
    # ══════════════════════════════════════════════════════════
    def _panel_ads(self):
        scroll = self._make_scrollable()
        self._add_title(scroll, "🔍", "ADS Scanner", "NTFS Alternate Data Streams")

        if not ADS_AVAILABLE:
            self._add_status(scroll, "ADS scanning requires Windows.", ACCENT_ORANGE)
            return

        fp = self._get_file()
        if not fp:
            return

        card = self._add_card(scroll, "Scanning for hidden streams...")
        loading = self._add_loading(card)

        def on_done(result):
            loading.destroy()
            if "error" in result:
                self._add_status(card, f"Error: {result['error']}", ACCENT_RED)
                return
            streams = result.get("streams", [])
            hidden = result.get("hidden_count", 0)
            self._add_row(card, "Total Streams", str(len(streams)))
            self._add_row(card, "Hidden Streams", str(hidden),
                          ACCENT_RED if hidden > 0 else ACCENT_GREEN)
            for s in streams:
                color = ACCENT_RED if s.get("suspicious") else TEXT_PRIMARY
                self._add_row(card, s.get("name", "N/A"),
                              f"{s.get('size_human', 'N/A')}", color)
            ctk.CTkFrame(card, height=8, fg_color="transparent").pack()

        self._run_threaded(scan_ads, on_done, fp)

    # ══════════════════════════════════════════════════════════
    #  PANEL: Process Analyzer
    # ══════════════════════════════════════════════════════════
    def _panel_processes(self):
        scroll = self._make_scrollable()
        self._add_title(scroll, "📊", "Process Analyzer", "Running Process Audit")

        if not PROCESS_ANALYZER_AVAILABLE:
            self._add_status(scroll, "Process analysis requires Windows.",
                            ACCENT_ORANGE)
            return

        card = self._add_card(scroll, "Enumerating processes...")
        loading = self._add_loading(card)

        def on_done(result):
            loading.destroy()
            if "error" in result:
                self._add_status(card, f"Error: {result['error']}", ACCENT_RED)
                return
            procs = result.get("processes", [])
            suspicious = result.get("suspicious_procs", [])
            self._add_row(card, "Total Processes", str(result.get("total_count", 0)))
            self._add_row(card, "Suspicious",
                          str(result.get("suspicious_count", 0)),
                          ACCENT_RED if suspicious else ACCENT_GREEN)
            ctk.CTkFrame(card, height=8, fg_color="transparent").pack()

            if suspicious:
                card2 = self._add_card(scroll,
                                        f"⚠️ Suspicious Processes ({len(suspicious)})")
                for p in suspicious:
                    self._add_row(card2, f"PID {p.get('pid', '?')}",
                                  f"{p.get('name', '?')} — {', '.join(p.get('flags', []))}",
                                  ACCENT_RED)
                ctk.CTkFrame(card2, height=8, fg_color="transparent").pack()

        self._run_threaded(enumerate_processes, on_done)

    # ══════════════════════════════════════════════════════════
    #  PANEL: Network Inspector
    # ══════════════════════════════════════════════════════════
    def _panel_network(self):
        scroll = self._make_scrollable()
        self._add_title(scroll, "🌐", "Network Inspector", "Active Connections")

        if not NETWORK_INSPECTOR_AVAILABLE:
            self._add_status(scroll, "Network inspection requires Windows.",
                            ACCENT_ORANGE)
            return

        card = self._add_card(scroll, "Reading TCP connections...")
        loading = self._add_loading(card)

        def on_done(result):
            loading.destroy()
            if "error" in result:
                self._add_status(card, f"Error: {result['error']}", ACCENT_RED)
                return
            conns = result.get("connections", [])
            self._add_row(card, "Total", str(result.get("total", 0)))
            self._add_row(card, "Established",
                          str(result.get("established", 0)))
            self._add_row(card, "Listening", str(result.get("listening", 0)))
            suspicious = result.get("suspicious", [])
            self._add_row(card, "Suspicious",
                          str(result.get("suspicious_count", 0)),
                          ACCENT_RED if suspicious else ACCENT_GREEN)
            ctk.CTkFrame(card, height=8, fg_color="transparent").pack()

            if suspicious:
                card2 = self._add_card(scroll,
                                        f"⚠️ Suspicious Connections ({len(suspicious)})")
                for c in suspicious:
                    self._add_row(
                        card2, c.get("state", "?"),
                        f"{c.get('local', '?')} → {c.get('remote', '?')} "
                        f"[PID {c.get('pid', '?')} {c.get('process_name', '')}]",
                        ACCENT_RED)
                ctk.CTkFrame(card2, height=8, fg_color="transparent").pack()

        self._run_threaded(get_tcp_connections, on_done)

    # ══════════════════════════════════════════════════════════
    #  PANEL: Signature Verifier
    # ══════════════════════════════════════════════════════════
    def _panel_signatures(self):
        scroll = self._make_scrollable()
        self._add_title(scroll, "✍️", "Signature Verifier", "Authenticode Check")

        if not SIG_VERIFIER_AVAILABLE:
            self._add_status(scroll, "Signature verification requires Windows.",
                            ACCENT_ORANGE)
            return

        fp = self._get_file()
        if not fp:
            return

        card = self._add_card(scroll, "Verifying digital signature...")
        loading = self._add_loading(card)

        def on_done(result):
            loading.destroy()
            if "error" in result:
                self._add_status(card, f"Error: {result['error']}", ACCENT_RED)
                return
            status = result.get("status", "unknown")
            color = ACCENT_GREEN if status == "valid" else ACCENT_RED
            self._add_row(card, "Status", status.upper(), color)
            self._add_row(card, "Trust", result.get("trust_text", "N/A"), color)
            self._add_row(card, "Signer", result.get("signer", "N/A"))
            self._add_row(card, "Issuer", result.get("issuer", "N/A"))
            ctk.CTkFrame(card, height=8, fg_color="transparent").pack()

        self._run_threaded(verify_signature, on_done, fp)

    # ══════════════════════════════════════════════════════════
    #  PANEL: Event Log Reader
    # ══════════════════════════════════════════════════════════
    def _panel_eventlogs(self):
        scroll = self._make_scrollable()
        self._add_title(scroll, "📜", "Event Log Reader", "Forensic Events")

        if not EVENTLOG_AVAILABLE:
            self._add_status(scroll, "Event log reading requires Windows.",
                            ACCENT_ORANGE)
            return

        card = self._add_card(scroll, "Reading forensic events...")
        loading = self._add_loading(card)

        def on_done(result):
            loading.destroy()
            events = result.get("events", [])
            if not events:
                self._add_status(card, "No forensic events found (may need admin).",
                                TEXT_MUTED)
                return

            for e in events[:30]:
                sev = e.get("severity", "info")
                color = (ACCENT_RED if sev in ("critical", "high") else
                         ACCENT_ORANGE if sev == "warning" else ACCENT_CYAN)
                icon = {"critical": "🔴", "high": "🟠",
                        "warning": "🟡", "info": "🔵"}.get(sev, "⚪")
                self._add_status(
                    card,
                    f"{icon} [{e.get('event_id', '?')}] {e.get('description', 'N/A')} "
                    f"— {e.get('time_generated', '')}",
                    color)
            ctk.CTkFrame(card, height=8, fg_color="transparent").pack()

        self._run_threaded(read_forensic_events, on_done, 30)

    # ══════════════════════════════════════════════════════════
    #  PANEL: Reports
    # ══════════════════════════════════════════════════════════
    def _panel_reports(self):
        scroll = self._make_scrollable()
        self._add_title(scroll, "📊", "Reports", "Export Analysis Results")

        if not self._analysis_data:
            card = self._add_card(scroll, "No Analysis Data")
            self._add_status(card,
                            "Run an analysis first, then return here to export.",
                            TEXT_MUTED)
            ctk.CTkFrame(card, height=8, fg_color="transparent").pack()
            return

        for fmt, icon, desc in [
            ("PDF", "📄", "Professional forensic PDF report"),
            ("HTML", "🌐", "Self-contained dark-themed HTML"),
            ("JSON", "📦", "Structured JSON for SIEM / automation"),
        ]:
            card = self._add_card(scroll, f"{icon} {fmt} Report")
            self._add_status(card, desc, TEXT_SECOND)

            def gen(f=fmt):
                path = filedialog.asksaveasfilename(
                    title=f"Save {f} Report",
                    defaultextension=f".{f.lower()}",
                    filetypes=[(f"{f} files", f"*.{f.lower()}")])
                if not path:
                    return
                try:
                    if f == "PDF":
                        result = generate_pdf_report(self._analysis_data, path)
                    elif f == "HTML":
                        result = generate_html_report(self._analysis_data, path)
                    else:
                        result = generate_json_report(self._analysis_data, path)
                    messagebox.showinfo("BitWitness",
                                        f"{f} report saved to:\n{result}")
                except Exception as e:
                    messagebox.showerror("Error", str(e))

            ctk.CTkButton(card, text=f"Export {fmt}", font=FONT_UI_BOLD,
                          fg_color=ACCENT_RED, hover_color="#b30000",
                          command=gen).pack(padx=16, pady=(4, 12))

    # ══════════════════════════════════════════════════════════
    #  Full Analysis Runner
    # ══════════════════════════════════════════════════════════
    def _run_full_analysis(self):
        fp = self._get_file()
        if not fp:
            return
        self._analysis_data = {"file_path": fp}

        # Show progress panel
        for w in self.content_frame.winfo_children():
            w.destroy()

        scroll = self._make_scrollable()
        self._add_title(scroll, "🔍", "Full Analysis", "Running all modules...")

        progress_card = self._add_card(scroll, "📊 Analysis Progress")

        status_lbl = ctk.CTkLabel(progress_card, text="⏳ Initializing...",
                                   font=FONT_UI, text_color=ACCENT_CYAN)
        status_lbl.pack(anchor="w", padx=16, pady=(8, 4))

        progress_bar = ctk.CTkProgressBar(progress_card, width=600, height=12,
                                           progress_color=ACCENT_RED,
                                           fg_color=BG_HOVER, corner_radius=6)
        progress_bar.pack(padx=16, pady=(4, 12))
        progress_bar.set(0)

        log_card = self._add_card(scroll, "📋 Analysis Log")
        log_frame = ctk.CTkFrame(log_card, fg_color="transparent")
        log_frame.pack(fill="x", padx=16, pady=(4, 12))

        def update_progress(step_num, total, msg, icon="⏳"):
            self.after(0, lambda: status_lbl.configure(text=f"{icon} {msg}"))
            self.after(0, lambda: progress_bar.set(step_num / total))
            self.after(0, lambda: ctk.CTkLabel(
                log_frame, text=f"  ✅ Step {step_num}/{total}: {msg}",
                font=FONT_UI_SM, text_color=ACCENT_GREEN
            ).pack(anchor="w", pady=1))

        def run_all():
            data = self._analysis_data
            total = 7

            update_progress(1, total, "Computing file hashes (MD5, SHA-256...)")
            data["hashes"] = get_all_hashes(fp)

            update_progress(2, total, "Analyzing file header & entropy...")
            data["header"] = check_header(fp)
            data["file_types"] = identify_file_type(fp)
            data["entropy"] = get_file_entropy(fp)

            update_progress(3, total, "Extracting metadata...")
            data["metadata"] = get_file_metadata(fp)

            update_progress(4, total, "PE static analysis...")
            if PEFILE_AVAILABLE and is_pe_file(fp):
                data["pe_analysis"] = analyze_pe(fp)

            update_progress(5, total, "Extracting strings...")
            data["strings"] = get_strings_summary(fp, 80)

            update_progress(6, total, "Running YARA rules...")
            if YARA_AVAILABLE:
                data["yara"] = yara_scan_file(fp)

            update_progress(7, total, "Querying VirusTotal...")
            data["vt"] = lookup_hash(fp)

            return data

        def on_complete(data):
            self._analysis_data = data
            self._show_panel("dashboard")

        self._run_threaded(run_all, on_complete)


# ══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = BitWitnessApp()
    app.mainloop()
