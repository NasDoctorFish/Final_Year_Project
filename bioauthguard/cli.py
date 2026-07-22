"""Command-line entry point and orchestration.

Commands:
  scan-apk <apk>                      static analysis only (no device)
  assess  --package P --i-am-authorized   full black-box assessment on a device
  dashboard                           launch the Streamlit UI
  gui                                 launch the PySide6 desktop app
"""

from __future__ import annotations

import argparse
import sys

from . import core
from .adb import AdbError
from .config import Config
from .models import TestRun


def cmd_scan_apk(args, cfg: Config) -> int:
    run = core.build_scan_apk(args.apk, cfg)
    _finish(run, cfg, explain=args.explain)
    return 0


def cmd_assess(args, cfg: Config) -> int:
    if not args.i_am_authorized:
        print("Refusing to test: pass --i-am-authorized to confirm you own or are "
              "authorized to test this app.", file=sys.stderr)
        return 2

    if not args.apk:
        print("Note: no --apk supplied; IPC oracle needs the exported-component list. "
              "Provide --apk for the headline check.", file=sys.stderr)

    try:
        run = core.build_assess(args.package, args.apk, cfg)
    except AdbError as exc:
        print(f"Device error: {exc}", file=sys.stderr)
        return 1

    _finish(run, cfg, explain=not args.no_ai)
    return 0


def cmd_dashboard(args, cfg: Config) -> int:
    import subprocess
    from pathlib import Path
    app = Path(__file__).parent / "dashboard" / "app.py"
    return subprocess.call(["streamlit", "run", str(app)])


def cmd_gui(args, cfg: Config) -> int:
    from .gui.app import run as run_gui
    return run_gui(cfg)


def _finish(run: TestRun, cfg: Config, explain: bool) -> None:
    path = core.finalize(run, cfg, explain)

    # Print a summary.
    counts = run.counts()
    print(f"\nAssessed {run.package}: " +
          ", ".join(f"{k} {v}" for k, v in counts.items() if v) or "no findings")
    for f in run.ranked():
        print(f"  [{f.severity.label:8}] {f.title}  ({', '.join(f.owasp)})")
    print(f"\nReport written to: {path}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bioauthguard",
        description="Android biometric auth security tester (Mode B: black-box, no root)")
    p.add_argument("--config", help="path to config.yaml")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan-apk", help="static analysis of an APK (no device)")
    s.add_argument("apk")
    s.add_argument("--explain", action="store_true", help="run the AI explanation layer")
    s.set_defaults(func=cmd_scan_apk)

    a = sub.add_parser("assess", help="full black-box assessment on a connected device")
    a.add_argument("--package", required=True)
    a.add_argument("--apk", help="APK on disk (enables the IPC oracle + static analysis)")
    a.add_argument("--i-am-authorized", action="store_true",
                   help="confirm you own or are authorized to test this app")
    a.add_argument("--no-ai", action="store_true", help="skip the AI explanation layer")
    a.set_defaults(func=cmd_assess)

    d = sub.add_parser("dashboard", help="launch the Streamlit dashboard")
    d.set_defaults(func=cmd_dashboard)

    g = sub.add_parser("gui", help="launch the PySide6 desktop app")
    g.set_defaults(func=cmd_gui)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = Config.load(args.config)
    return args.func(args, cfg)
