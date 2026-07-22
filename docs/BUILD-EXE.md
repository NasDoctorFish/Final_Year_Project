# Building a standalone `BioAuthGuard.exe`

BioAuthGuard ships a native desktop GUI (PySide6) and can be packaged into a
single Windows executable with PyInstaller. The same exe doubles as the CLI.

## What the exe does and does not contain

- **Contains:** the Python runtime, the deterministic core, the GUI, and the heavy
  optional packages — androguard (APK decompilation), weasyprint (PDF export),
  google-genai + pydantic (the AI layer), numpy (statistics), PySide6 (GUI).
- **Does *not* contain `adb`.** ADB is an external command-line tool, not a Python
  package, so it cannot be frozen in. The machine running the exe still needs
  Android **platform-tools** with `adb` on `PATH` (or set `device.adb_path` in
  `config/config.yaml` to an `adb.exe` you ship next to the exe). This only matters
  for the *Assess Device* tab; *Scan APK* works with no device.
- **Does not include the Streamlit dashboard.** The native GUI replaces it; the
  `dashboard` subcommand is unavailable in the frozen build.

## Prerequisites (on the build machine)

1. Python 3.10+ and the project deps:
   ```
   pip install -r requirements.txt
   pip install pyinstaller
   ```
2. **weasyprint's native libraries** (GTK / Pango / Cairo / GObject). This is the
   one genuinely fiddly dependency on Windows. The MSYS2 route, verified working:
   ```
   winget install --id MSYS2.MSYS2 -e
   C:\msys64\usr\bin\pacman.exe -Sy --noconfirm mingw-w64-x86_64-pango
   setx WEASYPRINT_DLL_DIRECTORIES "C:\msys64\mingw64\bin"
   ```
   `pacman` installs Pango and its dependencies (glib2/gobject, cairo, harfbuzz,
   freetype, fontconfig) into `C:\msys64\mingw64\bin`; `WEASYPRINT_DLL_DIRECTORIES`
   tells weasyprint where to find them without touching `PATH`. Open a **new**
   terminal (so the env var is picked up) and verify *before* building:
   ```
   python -c "import weasyprint; print('weasyprint OK')"
   ```
   If that import fails, the exe will build but PDF export will silently fall back
   to HTML (the report generator already degrades gracefully). If you don't need
   PDF, you can drop `weasyprint` from the `collect_all` loop in `BioAuthGuard.spec`
   and remove the native-lib step entirely.

## Build

```
pyinstaller BioAuthGuard.spec
```

The result is `dist/BioAuthGuard.exe` (expect 150–300 MB — androguard and
PySide6 are large). Double-clicking it launches the GUI; from a terminal it also
behaves as the CLI:

```
BioAuthGuard.exe scan-apk app.apk
BioAuthGuard.exe assess --package com.example.app --apk app.apk --i-am-authorized
```

## Notes

- `console=False` in the spec makes it a windowed app (no terminal flashes on
  launch). Set `console=True` if you want a visible console for CLI usage.
- The AI layer needs a Gemini API key at runtime (`GEMINI_API_KEY`); it is
  never baked into the exe.
- `config/` (including the AI knowledge base) is bundled and unpacked next to the
  exe at runtime.
- First launch is slow — a one-file PyInstaller exe unpacks to a temp dir on start.
  For faster startup, switch the spec to one-folder mode (`COLLECT` instead of a
  one-file `EXE`).
