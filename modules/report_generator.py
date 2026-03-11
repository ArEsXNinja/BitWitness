#!/usr/bin/env python3
"""
report_generator.py — Professional HTML and JSON forensic report generation.
Exports complete analysis results into shareable reports.
"""

import os
import json
import datetime

# Optional: fpdf2 for PDF generation
try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False


# ══════════════════════════════════════════════════════════════
#  RISK SCORE CALCULATOR
# ══════════════════════════════════════════════════════════════

def calculate_risk_score(analysis_data):
    """
    Calculate an overall risk score (0-100) from analysis results.

    Weighted factors:
        - VT detections (30%)
        - Suspicious API count (20%)
        - YARA matches (20%)
        - Entropy indicators (15%)
        - Packer detection (15%)
    """
    score = 0

    # VT detections (max 30 points)
    vt = analysis_data.get("vt_lookup", {})
    if vt.get("status") == "found":
        malicious = vt.get("malicious", 0)
        if malicious >= 10:
            score += 30
        elif malicious >= 5:
            score += 25
        elif malicious >= 1:
            score += 15

    # Suspicious APIs (max 20 points)
    pe = analysis_data.get("pe_analysis", {})
    sus_apis = pe.get("suspicious_apis", [])
    if len(sus_apis) >= 10:
        score += 20
    elif len(sus_apis) >= 5:
        score += 15
    elif len(sus_apis) >= 1:
        score += 8

    # YARA matches (max 20 points)
    yara_data = analysis_data.get("yara_scan", {})
    yara_matches = yara_data.get("matches", [])
    severity_sum = yara_data.get("severity_summary", {})
    critical = severity_sum.get("critical", 0)
    high = severity_sum.get("high", 0)
    if critical > 0:
        score += 20
    elif high > 0:
        score += 15
    elif len(yara_matches) > 0:
        score += 8

    # Entropy (max 15 points)
    sections = pe.get("sections", [])
    high_entropy_count = sum(1 for s in sections if s.get("high_entropy"))
    if high_entropy_count >= 3:
        score += 15
    elif high_entropy_count >= 1:
        score += 10

    # Packer detection (max 15 points)
    indicators = pe.get("indicators", [])
    for ind in indicators:
        if "pack" in ind.get("type", "").lower() or "pack" in ind.get("detail", "").lower():
            score += 15
            break

    return min(score, 100)


def get_risk_verdict(score):
    """Return verdict string and color class from risk score."""
    if score >= 75:
        return "CRITICAL", "critical"
    elif score >= 50:
        return "HIGH", "high"
    elif score >= 25:
        return "MEDIUM", "medium"
    elif score > 0:
        return "LOW", "low"
    else:
        return "CLEAN", "clean"


# ══════════════════════════════════════════════════════════════
#  JSON REPORT
# ══════════════════════════════════════════════════════════════

def generate_json_report(analysis_data, output_path):
    """
    Export analysis results as structured JSON.

    Args:
        analysis_data: dict with all analysis results
        output_path:   path for the output .json file

    Returns:
        Absolute path of generated report, or error string.
    """
    risk_score = calculate_risk_score(analysis_data)
    verdict, _ = get_risk_verdict(risk_score)

    report = {
        "tool": "BitWitness",
        "version": "3.0.0",
        "generated_at": datetime.datetime.now().isoformat(),
        "risk_score": risk_score,
        "verdict": verdict,
        "analysis": analysis_data,
    }

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        return os.path.abspath(output_path)
    except Exception as e:
        return f"Error: {e}"


# ══════════════════════════════════════════════════════════════
#  HTML REPORT
# ══════════════════════════════════════════════════════════════

def generate_html_report(analysis_data, output_path):
    """
    Generate a professional, self-contained HTML report.

    Args:
        analysis_data: dict with all analysis results
        output_path:   path for the output .html file

    Returns:
        Absolute path of generated report, or error string.
    """
    risk_score = calculate_risk_score(analysis_data)
    verdict, verdict_class = get_risk_verdict(risk_score)

    file_info = analysis_data.get("file_info", {})
    hashes = analysis_data.get("hashes", {})
    header = analysis_data.get("header_analysis", "")
    pe = analysis_data.get("pe_analysis", {})
    strings_data = analysis_data.get("strings", {})
    yara_data = analysis_data.get("yara_scan", {})
    vt = analysis_data.get("vt_lookup", {})
    metadata = analysis_data.get("metadata", {})

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BitWitness Report — {file_info.get('file_name', 'Unknown')}</title>
<style>
:root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --text-dim: #8b949e; --accent: #58a6ff;
    --green: #3fb950; --yellow: #d29922; --orange: #db6d28;
    --red: #f85149; --purple: #bc8cff;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', -apple-system, sans-serif; padding: 2rem; line-height: 1.6; }}
.container {{ max-width: 1000px; margin: 0 auto; }}
header {{ text-align: center; padding: 2rem 0; border-bottom: 1px solid var(--border); margin-bottom: 2rem; }}
header h1 {{ font-size: 2rem; color: var(--accent); margin-bottom: 0.5rem; }}
header .subtitle {{ color: var(--text-dim); }}
.risk-badge {{ display: inline-block; padding: 0.8rem 2rem; border-radius: 12px; font-size: 1.5rem; font-weight: 700; margin: 1.5rem 0; letter-spacing: 2px; }}
.risk-badge.critical {{ background: rgba(248,81,73,0.2); color: var(--red); border: 2px solid var(--red); }}
.risk-badge.high {{ background: rgba(219,109,40,0.2); color: var(--orange); border: 2px solid var(--orange); }}
.risk-badge.medium {{ background: rgba(210,153,34,0.2); color: var(--yellow); border: 2px solid var(--yellow); }}
.risk-badge.low {{ background: rgba(63,185,80,0.15); color: var(--green); border: 2px solid var(--green); }}
.risk-badge.clean {{ background: rgba(63,185,80,0.15); color: var(--green); border: 2px solid var(--green); }}
.score {{ font-size: 3rem; font-weight: 700; margin: 0.5rem 0; }}
section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
section h2 {{ color: var(--accent); font-size: 1.1rem; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }}
table {{ width: 100%; border-collapse: collapse; }}
table td {{ padding: 0.4rem 0.8rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
table td:first-child {{ color: var(--text-dim); width: 200px; white-space: nowrap; }}
.tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; margin: 2px; }}
.tag-red {{ background: rgba(248,81,73,0.2); color: var(--red); }}
.tag-yellow {{ background: rgba(210,153,34,0.2); color: var(--yellow); }}
.tag-green {{ background: rgba(63,185,80,0.15); color: var(--green); }}
.tag-blue {{ background: rgba(88,166,255,0.15); color: var(--accent); }}
.mono {{ font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.85rem; word-break: break-all; }}
footer {{ text-align: center; color: var(--text-dim); padding: 2rem 0; font-size: 0.85rem; border-top: 1px solid var(--border); margin-top: 2rem; }}
</style>
</head>
<body>
<div class="container">

<header>
    <h1>🔍 BitWitness Forensic Report</h1>
    <div class="subtitle">Digital Forensics &amp; Static Malware Analysis</div>
    <div class="score" style="color: var(--{'red' if risk_score >= 50 else 'yellow' if risk_score >= 25 else 'green'})">{risk_score}/100</div>
    <div class="risk-badge {verdict_class}">{verdict}</div>
</header>

<section>
    <h2>📋 File Information</h2>
    <table>
        <tr><td>File Name</td><td>{_esc(file_info.get('file_name', 'N/A'))}</td></tr>
        <tr><td>Full Path</td><td class="mono">{_esc(file_info.get('full_path', 'N/A'))}</td></tr>
        <tr><td>Size</td><td>{file_info.get('size_human', 'N/A')} ({file_info.get('size_bytes', 0):,} bytes)</td></tr>
        <tr><td>Header Detection</td><td>{_esc(str(header))}</td></tr>
    </table>
</section>
"""

    # Hashes section
    if hashes and "error" not in hashes:
        html += """<section>
    <h2>🔒 File Hashes</h2>
    <table>
"""
        for algo, digest in hashes.items():
            html += f'        <tr><td>{algo.upper()}</td><td class="mono">{_esc(digest)}</td></tr>\n'
        html += "    </table>\n</section>\n"

    # Metadata section
    if metadata and metadata.get("file_name"):
        html += """<section>
    <h2>📄 File Metadata</h2>
    <table>
"""
        for key in ["created", "modified", "accessed", "permissions", "is_hidden", "is_readonly"]:
            if key in metadata:
                html += f'        <tr><td>{key.replace("_"," ").title()}</td><td>{_esc(str(metadata[key]))}</td></tr>\n'
        html += "    </table>\n</section>\n"

    # PE Analysis section
    if pe and "basic" in pe:
        basic = pe["basic"]
        html += """<section>
    <h2>⚙️ PE Static Analysis</h2>
    <table>
"""
        for key, val in basic.items():
            html += f'        <tr><td>{key.replace("_"," ").title()}</td><td>{_esc(str(val))}</td></tr>\n'
        html += "    </table>\n"

        # Sections
        sections = pe.get("sections", [])
        if sections:
            html += '    <h2 style="margin-top:1rem">📊 PE Sections</h2>\n    <table>\n'
            html += '        <tr><td><b>Name</b></td><td><b>VirtSize</b></td></tr>\n'
            for s in sections:
                ent_tag = '<span class="tag tag-red">HIGH ENTROPY</span>' if s.get("high_entropy") else ""
                html += f'        <tr><td>{_esc(s["name"])}</td><td>{s.get("virtual_size",0):,} | Entropy: {s.get("entropy",0):.4f} {ent_tag}</td></tr>\n'
            html += "    </table>\n"

        # Suspicious APIs
        sus_apis = pe.get("suspicious_apis", [])
        if sus_apis:
            html += f'    <h2 style="margin-top:1rem">⚠️ Suspicious APIs ({len(sus_apis)})</h2>\n    <table>\n'
            for api in sus_apis:
                html += f'        <tr><td class="tag tag-red">{_esc(api.get("dll",""))}</td><td>{_esc(api.get("func",""))}</td></tr>\n'
            html += "    </table>\n"

        # Threat indicators
        indicators = pe.get("indicators", [])
        if indicators:
            html += '    <h2 style="margin-top:1rem">🎯 Threat Indicators</h2>\n    <table>\n'
            for ind in indicators:
                sev = ind.get("severity", "INFO")
                tag_class = "tag-red" if sev == "HIGH" else "tag-yellow" if sev == "MEDIUM" else "tag-green"
                html += f'        <tr><td><span class="tag {tag_class}">{sev}</span></td><td>{_esc(ind.get("type",""))} — {_esc(ind.get("detail",""))}</td></tr>\n'
            html += "    </table>\n"

        html += "</section>\n"

    # YARA section
    if yara_data and yara_data.get("matches"):
        matches = yara_data["matches"]
        html += f"""<section>
    <h2>🛡️ YARA Scan Results ({len(matches)} matches)</h2>
    <table>
"""
        for m in matches:
            sev = m.get("severity", "info")
            tag_class = "tag-red" if sev in ("critical", "high") else "tag-yellow" if sev == "medium" else "tag-green"
            html += f'        <tr><td><span class="tag {tag_class}">{sev.upper()}</span> {_esc(m["rule"])}</td><td>{_esc(m.get("description",""))}</td></tr>\n'
        html += "    </table>\n</section>\n"

    # Strings section
    if strings_data and strings_data.get("total_count", 0) > 0:
        html += f"""<section>
    <h2>📝 Strings Analysis</h2>
    <table>
        <tr><td>Total Strings</td><td>{strings_data.get('total_count',0):,}</td></tr>
        <tr><td>ASCII</td><td>{strings_data.get('ascii_count',0):,}</td></tr>
        <tr><td>Unicode</td><td>{strings_data.get('unicode_count',0):,}</td></tr>
        <tr><td>Suspicious</td><td>{strings_data.get('suspicious_count',0):,}</td></tr>
    </table>
"""
        suspicious = strings_data.get("suspicious", {})
        if suspicious:
            for cat, items in suspicious.items():
                html += f'    <p style="margin-top:0.5rem;color:var(--yellow)"><b>{_esc(cat)}</b> ({len(items)} found)</p>\n'
                for item in items[:5]:
                    html += f'    <p class="mono" style="margin-left:1rem;color:var(--text-dim)">&gt; {_esc(str(item)[:80])}</p>\n'
                if len(items) > 5:
                    html += f'    <p style="margin-left:1rem;color:var(--text-dim)">...and {len(items)-5} more</p>\n'
        html += "</section>\n"

    # VT section
    if vt and vt.get("status") == "found":
        vt_verdict = vt.get("verdict", "UNKNOWN")
        vt_color = "red" if vt_verdict == "MALICIOUS" else "yellow" if vt_verdict == "SUSPICIOUS" else "green"
        html += f"""<section>
    <h2>🦠 VirusTotal Results</h2>
    <table>
        <tr><td>Verdict</td><td style="color:var(--{vt_color});font-weight:700">{vt_verdict}</td></tr>
        <tr><td>Detection Ratio</td><td>{_esc(vt.get('detection_ratio','N/A'))}</td></tr>
        <tr><td>Threat Label</td><td>{_esc(vt.get('threat_label','N/A'))}</td></tr>
        <tr><td>File Type</td><td>{_esc(vt.get('file_type','N/A'))}</td></tr>
        <tr><td>Reputation</td><td>{vt.get('reputation','N/A')}</td></tr>
    </table>
"""
        detections = vt.get("detections", [])
        if detections:
            html += f'    <h2 style="margin-top:1rem">Engine Detections ({len(detections)})</h2>\n    <table>\n'
            for d in detections[:20]:
                html += f'        <tr><td>{_esc(d["engine"])}</td><td class="tag tag-red">{_esc(d.get("result",""))}</td></tr>\n'
            if len(detections) > 20:
                html += f'        <tr><td colspan="2" style="color:var(--text-dim)">...and {len(detections)-20} more</td></tr>\n'
            html += "    </table>\n"
        html += "</section>\n"

    html += f"""
<footer>
    <p>Generated by <b>BitWitness v3.0</b> — Digital Forensics &amp; Static Malware Analysis Framework</p>
    <p>{now}</p>
    <p style="margin-top:0.5rem">⚠️ For authorized forensic investigations only.</p>
</footer>

</div>
</body>
</html>"""

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        return os.path.abspath(output_path)
    except Exception as e:
        return f"Error: {e}"


def _esc(text):
    """HTML-escape a string."""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


# ══════════════════════════════════════════════════════════════
#  TEXT SUMMARY
# ══════════════════════════════════════════════════════════════

def generate_summary(analysis_data):
    """Generate a concise text summary of the analysis."""
    risk_score = calculate_risk_score(analysis_data)
    verdict, _ = get_risk_verdict(risk_score)

    lines = [
        "=" * 64,
        f"  BitWitness v3.0 — Analysis Summary",
        "=" * 64,
        f"  Risk Score : {risk_score}/100 ({verdict})",
    ]

    file_info = analysis_data.get("file_info", {})
    if file_info:
        lines.append(f"  File       : {file_info.get('file_name', 'N/A')}")
        lines.append(f"  Size       : {file_info.get('size_human', 'N/A')}")

    hashes = analysis_data.get("hashes", {})
    if hashes and "sha256" in hashes:
        lines.append(f"  SHA-256    : {hashes['sha256']}")

    pe = analysis_data.get("pe_analysis", {})
    if pe and "basic" in pe:
        lines.append(f"  PE Type    : {pe['basic'].get('pe_type', 'N/A')}")
        sus = pe.get("suspicious_apis", [])
        lines.append(f"  Suspicious : {len(sus)} API imports flagged")

    yara_data = analysis_data.get("yara_scan", {})
    if yara_data and yara_data.get("matches"):
        lines.append(f"  YARA       : {len(yara_data['matches'])} rules matched")

    vt = analysis_data.get("vt_lookup", {})
    if vt and vt.get("status") == "found":
        lines.append(f"  VirusTotal : {vt.get('detection_ratio', 'N/A')} detections — {vt.get('verdict', 'N/A')}")

    lines.append("=" * 64)
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════
#  PDF REPORT
# ══════════════════════════════════════════════════════════════

def generate_pdf_report(analysis_data, output_path):
    """
    Generate a professional forensic PDF report.

    Args:
        analysis_data: dict with all analysis results
        output_path:   path for the output .pdf file

    Returns:
        Absolute path of generated report, or error string.
    """
    if not FPDF_AVAILABLE:
        return "Error: fpdf2 not installed. Run: pip install fpdf2"

    risk_score = calculate_risk_score(analysis_data)
    verdict, _ = get_risk_verdict(risk_score)

    file_info = analysis_data.get("file_info", {})
    hashes    = analysis_data.get("hashes", {})
    header    = analysis_data.get("header_analysis", "")
    pe        = analysis_data.get("pe_analysis", {})
    strings_data = analysis_data.get("strings", {})
    yara_data = analysis_data.get("yara_scan", {})
    vt        = analysis_data.get("vt_lookup", {})
    metadata  = analysis_data.get("metadata", {})

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        def _sanitize(text):
            """Replace Unicode chars with ASCII-safe equivalents for PDF."""
            return (str(text)
                    .replace("\u2014", "--")    # em dash
                    .replace("\u2013", "-")     # en dash
                    .replace("\u2018", "'")     # left single quote
                    .replace("\u2019", "'")     # right single quote
                    .replace("\u201c", '"')     # left double quote
                    .replace("\u201d", '"')     # right double quote
                    .replace("\u2022", "*")     # bullet
                    .replace("\u2192", "->")    # right arrow
                    .replace("\u2500", "-")     # box drawing
                    .replace("\u2550", "=")     # double box
                    .replace("\u00b7", ".")     # middle dot
                    .replace("\u25cf", "*")     # black circle
                    .replace("\u2713", "[OK]")  # check mark
                    .replace("\u2717", "[X]")   # cross mark
                    .encode("latin-1", errors="replace")
                    .decode("latin-1"))

        # ── Title / Header ──
        pdf.set_fill_color(13, 17, 23)         # dark bg
        pdf.rect(0, 0, 210, 50, "F")
        pdf.set_font("Helvetica", "B", 22)
        pdf.set_text_color(88, 166, 255)        # accent blue
        pdf.set_y(12)
        pdf.cell(0, 10, "BitWitness Forensic Report", align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(139, 148, 158)
        pdf.cell(0, 6, "Digital Forensics & Static Malware Analysis", align="C", new_x="LMARGIN", new_y="NEXT")

        # Risk score
        if risk_score >= 75:
            r, g, b = 248, 81, 73    # red
        elif risk_score >= 50:
            r, g, b = 219, 109, 40   # orange
        elif risk_score >= 25:
            r, g, b = 210, 153, 34   # yellow
        else:
            r, g, b = 63, 185, 80    # green

        pdf.set_font("Helvetica", "B", 18)
        pdf.set_text_color(r, g, b)
        pdf.cell(0, 12, _sanitize(f"RISK SCORE: {risk_score}/100  --  {verdict}"), align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(6)
        pdf.set_text_color(0, 0, 0)

        # ── Helper functions ──
        def section_title(title):
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_fill_color(22, 27, 34)
            pdf.set_text_color(88, 166, 255)
            pdf.cell(0, 9, _sanitize(f"  {title}"), fill=True, new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
            pdf.ln(2)

        def kv_row(key, value):
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(55, 6, _sanitize(str(key)))
            pdf.set_text_color(30, 30, 30)
            pdf.set_font("Helvetica", "", 9)
            val_str = _sanitize(str(value)[:90])
            pdf.cell(0, 6, val_str, new_x="LMARGIN", new_y="NEXT")

        # ── File Information ──
        section_title("FILE INFORMATION")
        kv_row("File Name",        file_info.get("file_name", "N/A"))
        kv_row("Full Path",        str(file_info.get("full_path", "N/A"))[:80])
        kv_row("Size",             f"{file_info.get('size_human', 'N/A')}  ({file_info.get('size_bytes', 0):,} bytes)")
        kv_row("Header Detection", str(header)[:80])
        pdf.ln(3)

        # ── File Hashes ──
        if hashes and "error" not in hashes:
            section_title("FILE HASHES")
            for algo in ["md5", "sha1", "sha256", "sha512"]:
                if algo in hashes:
                    kv_row(algo.upper(), hashes[algo])
            pdf.ln(3)

        # ── File Metadata ──
        if metadata and metadata.get("file_name"):
            section_title("FILE METADATA")
            for key in ["created", "modified", "accessed", "permissions", "is_hidden", "is_readonly"]:
                if key in metadata:
                    kv_row(key.replace("_", " ").title(), str(metadata[key]))
            pdf.ln(3)

        # ── PE Analysis ──
        if pe and "basic" in pe:
            basic = pe["basic"]
            section_title("PE STATIC ANALYSIS")
            for key, val in basic.items():
                kv_row(key.replace("_", " ").title(), str(val)[:80])

            # Imphash
            imphash = pe.get("imphash")
            if imphash:
                kv_row("Imphash", imphash)

            # Digital signature
            sig = pe.get("digital_signature", {})
            kv_row("Digital Signature", sig.get("detail", "N/A"))

            # Overlay
            overlay = pe.get("overlay", {})
            if overlay.get("present"):
                kv_row("Overlay", f"Present — {overlay.get('size_human', '?')} at offset {overlay.get('offset', '?')}")
            pdf.ln(2)

            # Sections table
            sections = pe.get("sections", [])
            if sections:
                pdf.set_font("Helvetica", "B", 10)
                pdf.set_text_color(88, 166, 255)
                pdf.cell(0, 7, "  PE Sections", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_fill_color(40, 44, 52)
                pdf.set_text_color(200, 200, 200)
                pdf.cell(30, 6, "Name", border=1, fill=True)
                pdf.cell(30, 6, "Virt Size", border=1, fill=True)
                pdf.cell(30, 6, "Raw Size", border=1, fill=True)
                pdf.cell(24, 6, "Entropy", border=1, fill=True)
                pdf.cell(0, 6, "Flags", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

                pdf.set_font("Helvetica", "", 8)
                for s in sections:
                    pdf.set_text_color(30, 30, 30)
                    pdf.cell(30, 5, _sanitize(s["name"][:10]), border=1)
                    pdf.cell(30, 5, f"{s.get('virtual_size', 0):,}", border=1)
                    pdf.cell(30, 5, f"{s.get('raw_size', 0):,}", border=1)
                    ent = s.get("entropy", 0)
                    if ent > 7.0:
                        pdf.set_text_color(248, 81, 73)
                    else:
                        pdf.set_text_color(30, 30, 30)
                    pdf.cell(24, 5, f"{ent:.4f}", border=1)
                    flags = []
                    if s.get("high_entropy"):
                        flags.append("PACKED?")
                    if s.get("suspicious_name"):
                        flags.append("SUS_NAME")
                    pdf.set_text_color(200, 50, 50) if flags else pdf.set_text_color(30, 30, 30)
                    pdf.cell(0, 5, " ".join(flags), border=1, new_x="LMARGIN", new_y="NEXT")
                pdf.ln(2)

            # Suspicious APIs
            sus_apis = pe.get("suspicious_apis", [])
            if sus_apis:
                pdf.set_font("Helvetica", "B", 10)
                pdf.set_text_color(248, 81, 73)
                pdf.cell(0, 7, f"  Suspicious API Imports ({len(sus_apis)})", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 8)
                for api in sus_apis[:20]:
                    pdf.set_text_color(200, 100, 50)
                    pdf.cell(50, 5, _sanitize(api.get("dll", "")))
                    pdf.set_text_color(200, 30, 30)
                    pdf.cell(0, 5, _sanitize(api.get("func", "")), new_x="LMARGIN", new_y="NEXT")
                if len(sus_apis) > 20:
                    pdf.set_text_color(120, 120, 120)
                    pdf.cell(0, 5, f"  ... and {len(sus_apis) - 20} more", new_x="LMARGIN", new_y="NEXT")
                pdf.ln(2)

            # Threat indicators
            indicators = pe.get("indicators", [])
            if indicators:
                pdf.set_font("Helvetica", "B", 10)
                pdf.set_text_color(210, 153, 34)
                pdf.cell(0, 7, "  Threat Indicators", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 8)
                for ind in indicators:
                    sev = ind.get("severity", "INFO")
                    if sev == "HIGH":
                        pdf.set_text_color(248, 81, 73)
                    elif sev == "MEDIUM":
                        pdf.set_text_color(210, 153, 34)
                    else:
                        pdf.set_text_color(63, 185, 80)
                    pdf.cell(18, 5, f"[{sev}]")
                    pdf.set_text_color(30, 30, 30)
                    detail = _sanitize(f"{ind.get('type', '')} -- {ind.get('detail', '')}"[:80])
                    pdf.cell(0, 5, detail, new_x="LMARGIN", new_y="NEXT")
                pdf.ln(2)

            # TLS callbacks
            tls = pe.get("tls_callbacks", {})
            if tls.get("present"):
                pdf.set_font("Helvetica", "B", 10)
                pdf.set_text_color(248, 81, 73)
                pdf.cell(0, 7, f"  TLS Callbacks ({tls['count']})", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(30, 30, 30)
                for addr in tls.get("addresses", []):
                    pdf.cell(0, 5, _sanitize(f"  Callback at {addr}"), new_x="LMARGIN", new_y="NEXT")
                pdf.ln(2)

        # ── YARA Results ──
        if yara_data and yara_data.get("matches"):
            matches = yara_data["matches"]
            section_title(f"YARA SCAN RESULTS ({len(matches)} matches)")
            for m in matches:
                sev = m.get("severity", "info")
                if sev in ("critical", "high"):
                    pdf.set_text_color(248, 81, 73)
                elif sev == "medium":
                    pdf.set_text_color(210, 153, 34)
                else:
                    pdf.set_text_color(63, 185, 80)
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(0, 6, _sanitize(f"[{sev.upper()}]  {m['rule']}"), new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(80, 80, 80)
                pdf.cell(0, 5, _sanitize(f"  {m.get('description', '')}"), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)

        # ── Strings ──
        if strings_data and strings_data.get("total_count", 0) > 0:
            section_title("STRINGS ANALYSIS")
            kv_row("Total Strings", f"{strings_data.get('total_count', 0):,}")
            kv_row("ASCII", f"{strings_data.get('ascii_count', 0):,}")
            kv_row("Unicode", f"{strings_data.get('unicode_count', 0):,}")
            kv_row("Suspicious", f"{strings_data.get('suspicious_count', 0):,}")

            suspicious = strings_data.get("suspicious", {})
            if suspicious:
                pdf.ln(1)
                for cat, items in suspicious.items():
                    pdf.set_font("Helvetica", "B", 8)
                    pdf.set_text_color(210, 153, 34)
                    pdf.cell(0, 5, _sanitize(f"  {cat} ({len(items)} found)"), new_x="LMARGIN", new_y="NEXT")
                    pdf.set_font("Helvetica", "", 7)
                    pdf.set_text_color(80, 80, 80)
                    for item in items[:5]:
                        pdf.cell(0, 4, _sanitize(f"    > {str(item)[:70]}"), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)

        # ── VirusTotal ──
        if vt and vt.get("status") == "found":
            section_title("VIRUSTOTAL RESULTS")
            vt_verdict_label = vt.get("verdict", "UNKNOWN")
            kv_row("Verdict", vt_verdict_label)
            kv_row("Detection Ratio", vt.get("detection_ratio", "N/A"))
            kv_row("Threat Label", vt.get("threat_label", "N/A"))
            kv_row("File Type", vt.get("file_type", "N/A"))
            kv_row("Reputation", str(vt.get("reputation", "N/A")))

            detections = vt.get("detections", [])
            if detections:
                pdf.ln(1)
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(248, 81, 73)
                pdf.cell(0, 6, f"  Engine Detections ({len(detections)})", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 8)
                for d in detections[:15]:
                    pdf.set_text_color(30, 30, 30)
                    pdf.cell(55, 5, _sanitize(d.get("engine", "")))
                    pdf.set_text_color(200, 30, 30)
                    pdf.cell(0, 5, _sanitize(d.get("result", "")), new_x="LMARGIN", new_y="NEXT")
                if len(detections) > 15:
                    pdf.set_text_color(120, 120, 120)
                    pdf.cell(0, 5, f"  ... and {len(detections) - 15} more", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)

        # ── Footer ──
        pdf.ln(5)
        pdf.set_draw_color(48, 54, 61)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(3)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(139, 148, 158)
        pdf.cell(0, 5, f"Generated by BitWitness v3.0  |  {now}", align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 5, "For authorized forensic investigations only.", align="C", new_x="LMARGIN", new_y="NEXT")

        pdf.output(output_path)
        return os.path.abspath(output_path)

    except Exception as e:
        return f"Error: {e}"
