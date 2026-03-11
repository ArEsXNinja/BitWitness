#!/usr/bin/env python3
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  BitWitness Web Server — Flask REST API Backend
#  Exposes all analysis modules as JSON endpoints
#  Author : Rohit
#  Version: 4.0.0
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import os
import sys
import json
import tempfile
import time
import traceback
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS

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
#  APP SETUP
# ══════════════════════════════════════════════════════════════
app = Flask(__name__, static_folder="gui", static_url_path="")
CORS(app)

# Temp directory for uploaded files
UPLOAD_DIR = os.path.join(tempfile.gettempdir(), "bitwitness_uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Global store for analysis data (per-session, single-user tool)
analysis_store = {}


# ── Error handler decorator ──
def safe_endpoint(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            traceback.print_exc()
            return jsonify({"error": str(e)}), 500
    return wrapper


def get_file_path():
    """Extract file_path from JSON body or query string."""
    data = request.get_json(silent=True) or {}
    path = data.get("file_path") or request.args.get("file_path", "")
    path = path.strip().strip('"').strip("'")
    if not path or not os.path.isfile(path):
        return None
    return path


# ══════════════════════════════════════════════════════════════
#  STATIC FILE SERVING
# ══════════════════════════════════════════════════════════════
@app.route("/")
def serve_index():
    return send_from_directory(app.static_folder, "index.html")


# ══════════════════════════════════════════════════════════════
#  STATUS & INFO
# ══════════════════════════════════════════════════════════════
@app.route("/api/status")
@safe_endpoint
def api_status():
    return jsonify({
        "version": "4.0.0",
        "modules": {
            "pefile": PEFILE_AVAILABLE,
            "yara": YARA_AVAILABLE,
            "ssdeep": SSDEEP_AVAILABLE,
            "ads": ADS_AVAILABLE,
            "process_analyzer": PROCESS_ANALYZER_AVAILABLE,
            "network_inspector": NETWORK_INSPECTOR_AVAILABLE,
            "sig_verifier": SIG_VERIFIER_AVAILABLE,
            "eventlog": EVENTLOG_AVAILABLE,
        },
        "yara_rules": get_rule_count() if YARA_AVAILABLE else 0,
        "signatures": len(SIGNATURES),
    })


# ══════════════════════════════════════════════════════════════
#  FILE UPLOAD
# ══════════════════════════════════════════════════════════════
@app.route("/api/upload", methods=["POST"])
@safe_endpoint
def api_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    if f.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    # Save to upload dir
    safe_name = f.filename.replace("..", "").replace("/", "_").replace("\\", "_")
    save_path = os.path.join(UPLOAD_DIR, safe_name)
    f.save(save_path)

    size = os.path.getsize(save_path)
    size_mb = size / (1024 * 1024)

    return jsonify({
        "file_path": save_path,
        "file_name": safe_name,
        "size": size,
        "size_human": f"{size:,} bytes ({size_mb:.2f} MB)",
        "extension": os.path.splitext(safe_name)[1] or "N/A",
    })


# Also support setting a local file path directly (no upload)
@app.route("/api/set-file", methods=["POST"])
@safe_endpoint
def api_set_file():
    data = request.get_json(silent=True) or {}
    path = data.get("file_path", "").strip().strip('"').strip("'")
    if not path or not os.path.isfile(path):
        return jsonify({"error": f"File not found: {path}"}), 400

    size = os.path.getsize(path)
    size_mb = size / (1024 * 1024)
    return jsonify({
        "file_path": path,
        "file_name": os.path.basename(path),
        "size": size,
        "size_human": f"{size:,} bytes ({size_mb:.2f} MB)",
        "extension": os.path.splitext(path)[1] or "N/A",
    })


# ══════════════════════════════════════════════════════════════
#  INTEGRITY CHECK
# ══════════════════════════════════════════════════════════════
@app.route("/api/analyze/integrity", methods=["POST"])
@safe_endpoint
def api_integrity():
    fp = get_file_path()
    if not fp:
        return jsonify({"error": "Valid file_path required"}), 400

    hashes = get_all_hashes(fp)
    fuzzy = get_fuzzy_hash(fp)
    if fuzzy:
        hashes["ssdeep"] = fuzzy
    hashes["ssdeep_available"] = SSDEEP_AVAILABLE
    return jsonify(hashes)


# ══════════════════════════════════════════════════════════════
#  HEADER ANALYSIS
# ══════════════════════════════════════════════════════════════
@app.route("/api/analyze/header", methods=["POST"])
@safe_endpoint
def api_header():
    fp = get_file_path()
    if not fp:
        return jsonify({"error": "Valid file_path required"}), 400

    result = check_header(fp)
    types = identify_file_type(fp)
    entropy = get_file_entropy(fp)

    # Raw header hex
    raw_hex = ""
    try:
        with open(fp, "rb") as f:
            raw = f.read(16)
        raw_hex = " ".join(f"{b:02X}" for b in raw)
    except Exception:
        pass

    entropy_verdict = ""
    if isinstance(entropy, float):
        entropy_verdict = get_entropy_verdict(entropy)

    return jsonify({
        "verdict": result,
        "types": types,
        "entropy": entropy,
        "entropy_verdict": entropy_verdict,
        "raw_hex": raw_hex,
        "total_signatures": len(SIGNATURES),
    })


# ══════════════════════════════════════════════════════════════
#  HEX VIEWER
# ══════════════════════════════════════════════════════════════
@app.route("/api/analyze/hex", methods=["POST"])
@safe_endpoint
def api_hex():
    fp = get_file_path()
    if not fp:
        return jsonify({"error": "Valid file_path required"}), 400

    data = request.get_json(silent=True) or {}
    offset = data.get("offset", 0)
    length = data.get("length", 256)
    dump = hex_dump(fp, offset, length)
    return jsonify({"rows": dump, "offset": offset, "length": length})


# ══════════════════════════════════════════════════════════════
#  FORENSIC IMAGING
# ══════════════════════════════════════════════════════════════
@app.route("/api/analyze/imaging", methods=["POST"])
@safe_endpoint
def api_imaging():
    data = request.get_json(silent=True) or {}
    fp = data.get("file_path", "").strip()
    dest = data.get("dest_path", "").strip()

    if not fp or not os.path.isfile(fp):
        return jsonify({"error": "Valid file_path required"}), 400
    if not dest:
        return jsonify({"error": "dest_path required"}), 400

    ok = create_image(fp, dest)
    return jsonify({"success": ok, "dest_path": dest})


# ══════════════════════════════════════════════════════════════
#  METADATA / EXIF
# ══════════════════════════════════════════════════════════════
@app.route("/api/analyze/metadata", methods=["POST"])
@safe_endpoint
def api_metadata():
    fp = get_file_path()
    if not fp:
        return jsonify({"error": "Valid file_path required"}), 400

    meta = get_file_metadata(fp)
    exif = get_exif_data(fp)
    pe_meta = get_pe_metadata(fp)

    return jsonify({
        "file_metadata": meta,
        "exif": exif,
        "pe_metadata": pe_meta,
    })


# ══════════════════════════════════════════════════════════════
#  PE ANALYSIS
# ══════════════════════════════════════════════════════════════
@app.route("/api/analyze/pe", methods=["POST"])
@safe_endpoint
def api_pe():
    fp = get_file_path()
    if not fp:
        return jsonify({"error": "Valid file_path required"}), 400

    if not PEFILE_AVAILABLE:
        return jsonify({"error": "pefile not installed", "available": False})

    if not is_pe_file(fp):
        return jsonify({"error": "Not a PE file", "is_pe": False})

    result = analyze_pe(fp)
    return jsonify(result)


# ══════════════════════════════════════════════════════════════
#  STRINGS EXTRACTION
# ══════════════════════════════════════════════════════════════
@app.route("/api/analyze/strings", methods=["POST"])
@safe_endpoint
def api_strings():
    fp = get_file_path()
    if not fp:
        return jsonify({"error": "Valid file_path required"}), 400

    data = request.get_json(silent=True) or {}
    max_strings = data.get("max_strings", 80)
    result = get_strings_summary(fp, max_strings)
    return jsonify(result)


# ══════════════════════════════════════════════════════════════
#  YARA SCAN
# ══════════════════════════════════════════════════════════════
@app.route("/api/analyze/yara", methods=["POST"])
@safe_endpoint
def api_yara():
    if not YARA_AVAILABLE:
        return jsonify({"error": "yara-python not installed", "available": False})

    fp = get_file_path()
    if not fp:
        return jsonify({"error": "Valid file_path required"}), 400

    result = yara_scan_file(fp)
    result["rule_count"] = get_rule_count()
    return jsonify(result)


# ══════════════════════════════════════════════════════════════
#  VIRUSTOTAL LOOKUP
# ══════════════════════════════════════════════════════════════
@app.route("/api/analyze/virustotal", methods=["POST"])
@safe_endpoint
def api_virustotal():
    fp = get_file_path()
    if not fp:
        return jsonify({"error": "Valid file_path required"}), 400

    result = lookup_hash(fp)
    return jsonify(result)


# ══════════════════════════════════════════════════════════════
#  ADS SCANNER
# ══════════════════════════════════════════════════════════════
@app.route("/api/analyze/ads", methods=["POST"])
@safe_endpoint
def api_ads():
    if not ADS_AVAILABLE:
        return jsonify({"error": "ADS scanning requires Windows", "available": False})

    fp = get_file_path()
    if not fp:
        return jsonify({"error": "Valid file_path required"}), 400

    result = scan_ads(fp)
    return jsonify(result)


# ══════════════════════════════════════════════════════════════
#  PROCESS ANALYZER
# ══════════════════════════════════════════════════════════════
@app.route("/api/analyze/processes", methods=["GET"])
@safe_endpoint
def api_processes():
    if not PROCESS_ANALYZER_AVAILABLE:
        return jsonify({"error": "Process analysis requires Windows", "available": False})

    result = enumerate_processes()
    return jsonify(result)


# ══════════════════════════════════════════════════════════════
#  NETWORK INSPECTOR
# ══════════════════════════════════════════════════════════════
@app.route("/api/analyze/network", methods=["GET"])
@safe_endpoint
def api_network():
    if not NETWORK_INSPECTOR_AVAILABLE:
        return jsonify({"error": "Network inspection requires Windows", "available": False})

    result = get_tcp_connections()
    return jsonify(result)


# ══════════════════════════════════════════════════════════════
#  SIGNATURE VERIFIER
# ══════════════════════════════════════════════════════════════
@app.route("/api/analyze/signatures", methods=["POST"])
@safe_endpoint
def api_signatures():
    if not SIG_VERIFIER_AVAILABLE:
        return jsonify({"error": "Signature verification requires Windows", "available": False})

    fp = get_file_path()
    if not fp:
        return jsonify({"error": "Valid file_path required"}), 400

    result = verify_signature(fp)
    return jsonify(result)


# ══════════════════════════════════════════════════════════════
#  EVENT LOG READER
# ══════════════════════════════════════════════════════════════
@app.route("/api/analyze/eventlogs", methods=["GET"])
@safe_endpoint
def api_eventlogs():
    if not EVENTLOG_AVAILABLE:
        return jsonify({"error": "Event log reading requires Windows", "available": False})

    result = read_forensic_events(30)
    return jsonify(result)


# ══════════════════════════════════════════════════════════════
#  FULL ANALYSIS (all modules in sequence)
# ══════════════════════════════════════════════════════════════
@app.route("/api/analyze/all", methods=["POST"])
@safe_endpoint
def api_analyze_all():
    fp = get_file_path()
    if not fp:
        return jsonify({"error": "Valid file_path required"}), 400

    data = {"file_path": fp}

    # 1. Hashes
    data["hashes"] = get_all_hashes(fp)
    fuzzy = get_fuzzy_hash(fp)
    if fuzzy:
        data["hashes"]["ssdeep"] = fuzzy

    # 2. Header & entropy
    data["header"] = check_header(fp)
    data["file_types"] = identify_file_type(fp)
    data["entropy"] = get_file_entropy(fp)
    if isinstance(data["entropy"], float):
        data["entropy_verdict"] = get_entropy_verdict(data["entropy"])
    try:
        with open(fp, "rb") as f:
            raw = f.read(16)
        data["raw_hex"] = " ".join(f"{b:02X}" for b in raw)
    except Exception:
        data["raw_hex"] = ""

    # 3. Metadata
    data["metadata"] = get_file_metadata(fp)
    data["exif"] = get_exif_data(fp)
    data["pe_metadata"] = get_pe_metadata(fp)

    # 4. PE Analysis
    if PEFILE_AVAILABLE and is_pe_file(fp):
        data["pe_analysis"] = analyze_pe(fp)

    # 5. Strings
    data["strings"] = get_strings_summary(fp, 80)

    # 6. YARA
    if YARA_AVAILABLE:
        data["yara"] = yara_scan_file(fp)

    # 7. VirusTotal
    data["vt"] = lookup_hash(fp)

    # 8. File info
    size = os.path.getsize(fp)
    data["file_info"] = {
        "name": os.path.basename(fp),
        "path": fp,
        "size": size,
        "size_human": f"{size:,} bytes ({size / (1024 * 1024):.2f} MB)",
        "extension": os.path.splitext(fp)[1] or "N/A",
    }

    # Calculate risk score
    data["risk_score"] = calculate_risk_score(data)
    verdict, _ = get_risk_verdict(data["risk_score"])
    data["risk_verdict"] = verdict

    # Store for report generation
    global analysis_store
    analysis_store = data

    return jsonify(data)


# ══════════════════════════════════════════════════════════════
#  REPORT GENERATION
# ══════════════════════════════════════════════════════════════
@app.route("/api/report/<fmt>", methods=["POST"])
@safe_endpoint
def api_report(fmt):
    if not analysis_store:
        return jsonify({"error": "No analysis data — run Full Analysis first"}), 400

    fmt = fmt.lower()
    if fmt not in ("pdf", "html", "json"):
        return jsonify({"error": f"Unknown format: {fmt}"}), 400

    # Generate into temp file
    ext = fmt
    report_path = os.path.join(UPLOAD_DIR, f"bitwitness_report.{ext}")

    if fmt == "pdf":
        generate_pdf_report(analysis_store, report_path)
    elif fmt == "html":
        generate_html_report(analysis_store, report_path)
    else:
        generate_json_report(analysis_store, report_path)

    return send_file(report_path, as_attachment=True,
                     download_name=f"BitWitness_Report.{ext}")


# ══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("━" * 60)
    print("  🛡️  BitWitness Web Server v4.0.0")
    print("  📡  http://localhost:5000")
    print("  📂  Uploads → " + UPLOAD_DIR)
    print("━" * 60)
    app.run(host="0.0.0.0", port=5000, debug=True)
