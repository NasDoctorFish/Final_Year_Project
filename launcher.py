"""Frozen-exe entry point.

Run with no arguments (e.g. double-clicking BioAuthGuard.exe) launches the
desktop GUI. Any arguments are forwarded to the normal CLI, so the same exe also
works as `BioAuthGuard.exe scan-apk app.apk`, `... assess --package ...`, etc.
"""

import os
import sys


def _ensure_std_streams() -> None:
    """A windowed PyInstaller build (console=False) has sys.stdout/stderr == None.

    Some libraries — notably androguard/loguru — write to stderr at *import* time,
    which raises 'NoneType has no attribute write' before our own error handling
    can run. Give the streams a real sink so those imports succeed. Must happen
    before importing anything heavy.
    """
    if sys.stdout is not None and sys.stderr is not None:
        return
    try:
        sink = open(os.devnull, "w", encoding="utf-8")
    except Exception:
        return
    if sys.stdout is None:
        sys.stdout = sink
    if sys.stderr is None:
        sys.stderr = sink


_ensure_std_streams()

from bioauthguard.cli import main  # noqa: E402 - must follow _ensure_std_streams()

if __name__ == "__main__":
    argv = sys.argv[1:] or ["gui"]
    sys.exit(main(argv))
