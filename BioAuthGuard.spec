# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for a full BioAuthGuard.exe (GUI + scanner + PDF + AI).

Build:   pyinstaller BioAuthGuard.spec
Output:  dist/BioAuthGuard.exe

See docs/BUILD-EXE.md for the prerequisites — in particular weasyprint needs the
native GTK/Pango/Cairo libraries present on the *build* machine, and the target
device still needs the `adb` binary (it is an external CLI, not a Python package,
so it cannot be frozen in).
"""

import os

from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

# Make the GTK/Pango libraries visible to weasyprint's PyInstaller hook at build
# time, independent of the shell's environment (setx only affects new terminals).
# Adjust the path if MSYS2 lives elsewhere; skipped cleanly if it isn't present.
_GTK_BIN = os.environ.get("WEASYPRINT_DLL_DIRECTORIES", r"C:\msys64\mingw64\bin")
if os.path.isdir(_GTK_BIN):
    os.environ["PATH"] = _GTK_BIN + os.pathsep + os.environ.get("PATH", "")
    os.environ["WEASYPRINT_DLL_DIRECTORIES"] = _GTK_BIN
else:
    print(f"[spec] GTK bin dir not found ({_GTK_BIN}); PDF export may be unavailable in the exe")

datas = []
binaries = []
hiddenimports = []

# The Gemini SDK ships data files / dynamically imported submodules and has no
# built-in PyInstaller hook, so collect it in full. (pydantic, numpy, PySide6,
# weasyprint all have standard/contrib hooks — naming them here would only drag
# in their test suites and bloat the exe.)
for pkg in ("google.genai",):
    try:
        d, b, h = collect_all(pkg)
        datas += d
        binaries += b
        hiddenimports += h
    except Exception as exc:  # a missing optional package should not abort the build
        print(f"[spec] skipping {pkg}: {exc}")

# androguard: collect the parsing core + decompiler only. androguard.pentest's
# __init__ does `import frida` then `exit()` when frida is absent, which crashes
# PyInstaller's submodule collector — so we never walk it (and exclude it below).
datas += collect_data_files("androguard")
for subpkg in ("androguard.core", "androguard.decompiler"):
    try:
        hiddenimports += collect_submodules(subpkg)
    except Exception as exc:
        print(f"[spec] androguard: could not collect {subpkg}: {exc}")

# numpy is pulled in by its standard hook when named as a hidden import,
# without the giant .tests tree that collect_all would have added.
hiddenimports += ["numpy"]

# Ship the AI knowledge base and any bundled config alongside the exe.
datas += [("config", "config")]


a = Analysis(
    ["launcher.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["streamlit", "tkinter", "frida", "androguard.pentest", "google.genai.tests"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="BioAuthGuard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,   # windowed app; use console=True to keep a terminal for CLI mode
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
