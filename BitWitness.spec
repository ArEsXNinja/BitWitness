# -*- mode: python ; coding: utf-8 -*-
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  BitWitness — PyInstaller Spec File
#  Build with:  pyinstaller BitWitness.spec
#  Output:      dist/BitWitness.exe
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import os
import sys
from PyInstaller.utils.hooks import collect_data_files

# Paths
PROJECT_DIR = os.path.abspath('.')
MODULES_DIR = os.path.join(PROJECT_DIR, 'modules')

# Collect customtkinter theme/asset files (required for UI to render)
ctk_datas = collect_data_files('customtkinter')

# Icon file (optional — remove if you don't have one)
icon_path = os.path.join(PROJECT_DIR, 'bitwitness.ico')
icon_arg = icon_path if os.path.exists(icon_path) else None

a = Analysis(
    ['gui_app.py'],
    pathex=[PROJECT_DIR, MODULES_DIR],
    binaries=[],
    datas=[
        # Bundle the entire modules/ directory so imports work at runtime
        (os.path.join('modules', '*.py'), 'modules'),
    ] + ctk_datas,
    hiddenimports=[
        # ── Core analysis modules ──
        'integrity',
        'hex_engine',
        'imaging',
        'metadata_extractor',
        'pe_analyzer',
        'strings_extractor',
        'yara_scanner',
        'vt_lookup',
        'report_generator',
        'ads_scanner',
        'process_analyzer',
        'network_inspector',
        'sig_verifier',
        'eventlog_reader',
        # ── Third-party libs ──
        'pefile',
        'yara',
        'PIL',
        'PIL._tkinter_finder',
        'requests',
        'fpdf',
        'customtkinter',
        'ssdeep',
        # ── Windows-specific ctypes ──
        'ctypes',
        'ctypes.wintypes',
        'win32api',
        'win32con',
        'win32crypt',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'flask',        # Not needed in GUI-only build
        'flask_cors',
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='BitWitness',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # No console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_arg,
)
