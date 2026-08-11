# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for a full BioAudit.exe (GUI + scanner + PDF).

Build:   pyinstaller BioAudit.spec
Output:  dist/BioAudit.exe

See docs/FRONTEND-GUIDE.md for the prerequisites — in particular weasyprint needs the
native GTK/Pango/Cairo libraries present on the *build* machine, and the target
device still needs the `adb` binary (it is an external CLI, not a Python package,
so it cannot be frozen in).

AI explanation does not ship in this exe at all: it runs entirely on the backend
(the Gemini SDK lives only in backend/, a Node package), called over HTTPS through
ApiClient.explain_finding. There used to be a second, local AI path bundled in here
too (google-genai + a knowledge-base file), removed because it only worked on
whichever PC happened to have its own GEMINI_API_KEY set.
"""

import os

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

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

# Our own modules that are imported lazily inside functions, so that the CLI and the
# deterministic core start without pulling in PySide6 or the network client. PyInstaller
# analyses imports statically and does not follow a `from .signin import ...` sitting
# inside a method body, so anything reached only that way has to be named here or it is
# silently left out of the build and fails at runtime.
hiddenimports += [
    "bioaudit.api",
    "bioaudit.api.client",
    "bioaudit.gui.signin",
    "bioaudit.gui.theme",
    "bioaudit.gui.team",
    "bioaudit.gui.account_dialogs",
    "bioaudit.runtime.response_oracle",
    "bioaudit.session",
]

# Ship the bundled config (including config.example.yaml) alongside the exe.
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
    # `streamlit` itself is excluded because `dashboard` shells out to it as a separate
    # process (subprocess.call(["streamlit", ...])) rather than importing it in-process
    # — but PyInstaller still followed its *dependencies* into the build even with the
    # package itself excluded, since something in the graph re-imports them. pandas and
    # pyarrow are only ever needed by streamlit (confirmed via `pip show`, "Required-by:
    # streamlit"); nothing in bioaudit/ imports either. scipy has no "Required-by" at
    # all — dead weight, probably left over from an earlier version of the codebase.
    # QtQml/QtQuick/QtPdf are never imported either (only QtCore/QtGui/QtWidgets are) —
    # confirmed by grepping every `from PySide6.*` import in the source tree.
    excludes=[
        "streamlit", "tkinter", "frida", "androguard.pentest",
        "pandas", "pyarrow", "scipy",
        "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtQuickWidgets",
        "PySide6.QtPdf", "PySide6.QtPdfWidgets",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="BioAudit",
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
