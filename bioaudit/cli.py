"""Command-line entry point and orchestration.

Commands:
  login   [--email E]                     sign in and remember the session
  logout                                  end the saved session
  register --email E --password P         create an account (add --organisation to admin
                                           a team, or --join-token to join one from an invite)
  whoami                                  show who is currently signed in
  scan-apk <apk>                          static analysis only (no device)
  assess  --package P --i-am-authorized   full black-box assessment on a device
  explain <scan-id>                       ask the server to explain a saved run's findings
  dashboard                               launch the Streamlit UI
  gui                                     launch the PySide6 desktop app

`scan-apk` and `assess` need a signed-in session (`bioaudit login` first): BioAudit keeps
no local copy of a scan, so the account you upload to is the only place a run is stored.

AI explanation is server-side only, by `explain` (mirrors the GUI's "Explain findings"
button) -- there used to also be a `--explain` flag on `scan-apk` that ran a local AI
call using a `GEMINI_API_KEY` read off the calling machine's own environment. It was
removed because that meant a flag that only worked on whichever computer happened to
have that variable set, and silently did nothing everywhere else.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from . import core
from .adb import AdbError
from .api import ApiClient, ApiClientError
from .config import Config
from .models import TestRun
from .session import default_base_dir, restore_session, save_session

_NOT_SIGNED_IN = (
    "Not signed in. BioAudit stores every scan on your account, so run "
    "`bioaudit login` first (or `bioaudit register` if you don't have one yet)."
)


def _require_session(cfg: Config) -> ApiClient | None:
    client = restore_session(default_base_dir(), cfg.api["base_url"])
    if client is None:
        print(_NOT_SIGNED_IN, file=sys.stderr)
    return client


def cmd_login(args, cfg: Config) -> int:
    server = args.server or cfg.api["base_url"]
    email = args.email or input("Email: ").strip()
    password = args.password or getpass.getpass("Password: ")

    client = ApiClient(server)
    try:
        client.login(email, password)
    except ApiClientError as exc:
        print(f"Sign-in failed: {exc}", file=sys.stderr)
        return 1

    if not args.no_remember:
        save_session(default_base_dir(), client)
    print(f"Signed in as {client.account.email} ({client.account.tier}"
          f"{', admin' if client.account.is_admin else ''}).")
    return 0


def cmd_logout(args, cfg: Config) -> int:
    base_dir = default_base_dir()
    client = restore_session(base_dir, cfg.api["base_url"])
    if client is not None:
        client.logout()
    from .session import clear_session
    clear_session(base_dir)
    print("Signed out.")
    return 0


def cmd_register(args, cfg: Config) -> int:
    if args.organisation and args.join_token:
        print("--organisation and --join-token cannot both be given: an account either "
              "starts a new team or joins an existing one.", file=sys.stderr)
        return 2

    server = args.server or cfg.api["base_url"]
    password = args.password or getpass.getpass("Password (at least 8 characters): ")
    if len(password) < 8:
        print("Use a password of at least 8 characters.", file=sys.stderr)
        return 2

    client = ApiClient(server)
    try:
        if args.organisation:
            client.register_admin(args.email, password, args.organisation, args.name)
        else:
            client.register(args.email, password, args.name)
            if args.join_token:
                # Joining revokes the session server-side so the new team permissions
                # take effect, so a fresh sign-in follows, matching the GUI's join flow.
                client.join_organisation(args.join_token)
                client.login(args.email, password)
    except ApiClientError as exc:
        print(f"Registration failed: {exc}", file=sys.stderr)
        return 1

    if not args.no_remember:
        save_session(default_base_dir(), client)
    print(f"Registered and signed in as {client.account.email} ({client.account.tier}"
          f"{', admin' if client.account.is_admin else ''}).")
    return 0


def cmd_whoami(args, cfg: Config) -> int:
    client = restore_session(default_base_dir(), cfg.api["base_url"])
    if client is None:
        print("Not signed in.")
        return 1
    account = client.account
    print(f"{account.email}  ·  {account.tier}"
          f"{'  ·  admin' if account.is_admin else ''}"
          f"{'  ·  org ' + account.organisation_id if account.organisation_id else ''}")
    return 0


def cmd_scan_apk(args, cfg: Config) -> int:
    client = _require_session(cfg)
    if client is None:
        return 2
    run = core.build_scan_apk(args.apk, cfg)
    # A static scan reads a file the user chose, so there is no live app to authorise
    # probing against; the GUI treats this the same way.
    return _finish(run, cfg, client, authorised=True, apk_file_name=os.path.basename(args.apk))


def cmd_assess(args, cfg: Config) -> int:
    if not args.i_am_authorized:
        print("Refusing to test: pass --i-am-authorized to confirm you own or are "
              "authorized to test this app.", file=sys.stderr)
        return 2

    client = _require_session(cfg)
    if client is None:
        return 2

    if not args.apk:
        print("Note: no --apk supplied; IPC oracle needs the exported-component list. "
              "Provide --apk for the headline check.", file=sys.stderr)

    try:
        run = core.build_assess(args.package, args.apk, cfg)
    except AdbError as exc:
        print(f"Device error: {exc}", file=sys.stderr)
        return 1

    apk_name = os.path.basename(args.apk) if args.apk else None
    return _finish(run, cfg, client, authorised=True, apk_file_name=apk_name)


def cmd_explain(args, cfg: Config) -> int:
    """Ask the server to write a plain-language explanation and fix for a saved run's
    findings. Mirrors the GUI's "Explain findings" button -- same server endpoint, same
    "skip anything already explained" behaviour, so paying for one twice never happens
    from either front end."""
    client = _require_session(cfg)
    if client is None:
        return 2

    try:
        scan = client.get_scan(args.scan_id)
    except ApiClientError as exc:
        print(f"Could not load that scan: {exc}", file=sys.stderr)
        return 1

    findings = scan.get("findings", [])
    if not findings:
        print("That run has no findings.")
        return 0

    explained = 0
    failures = []
    for index, finding in enumerate(findings):
        if finding.get("explanation") and finding.get("mitigation"):
            continue
        try:
            client.explain_finding(args.scan_id, index)
            explained += 1
            print(f"  explained: {finding.get('title', 'finding')}")
        except ApiClientError as exc:
            failures.append(f"{finding.get('title', 'finding')}: {exc}")

    if explained == 0 and not failures:
        print("Every finding in that run already has an explanation.")
        return 0

    print(f"\nExplained {explained} finding(s).")
    for line in failures:
        print(f"  could not explain: {line}", file=sys.stderr)
    return 1 if failures else 0


def cmd_dashboard(args, cfg: Config) -> int:
    import subprocess
    from pathlib import Path
    app = Path(__file__).parent / "dashboard" / "app.py"
    return subprocess.call(["streamlit", "run", str(app)])


def cmd_gui(args, cfg: Config) -> int:
    from .gui.app import run as run_gui
    return run_gui(cfg)


def _finish(run: TestRun, cfg: Config, client: ApiClient, *, authorised: bool,
           apk_file_name: str | None) -> int:
    """Rank, upload to the account (the only place the run is stored), and write the
    report file the user asked for. Uploading is not optional here: skipping it would
    leave the run nowhere at all once the process exits. Explaining findings with AI is
    a separate step (`bioaudit explain <scan-id>`) since it needs the scan id this
    function is what produces."""
    core.process_findings(run)

    counts = run.counts()
    print(f"\nAssessed {run.package}: " +
          (", ".join(f"{k} {v}" for k, v in counts.items() if v) or "no findings"))
    _print_findings(run)

    try:
        result = client.upload_run(run, authorised=authorised, apk_file_name=apk_file_name)
        upload_failed = None
    except ApiClientError as exc:
        upload_failed = exc

    # Written either way: a report the user can see with their own eyes is worth having
    # even when the upload — the run's only real storage — did not go through.
    path = core.write_report(run, cfg)

    if upload_failed is not None:
        print(f"\nCould not save this run to your account: {upload_failed}", file=sys.stderr)
        print("This run exists nowhere else; rerun this command once the problem is "
              "fixed (check your connection and `bioaudit whoami`).", file=sys.stderr)
        print(f"A copy of the findings was written to: {path}", file=sys.stderr)
        return 1

    scan_id = result["scan"]["id"]
    print(f"\nSaved to your account: {scan_id}")
    retention = result.get("retention")
    if retention and retention.get("removed"):
        print(retention["message"])
    print(f"Report written to: {path}")
    print(f"For plain-language explanations, run: bioaudit explain {scan_id}")
    return 0


def _print_findings(run: TestRun) -> None:
    for f in run.ranked():
        print(f"  [{f.severity.label:8}] {f.title}  ({', '.join(f.owasp)})")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bioaudit",
        description="Android biometric auth security tester (Mode B: black-box, no root)")
    p.add_argument("--config", help="path to config.yaml")
    sub = p.add_subparsers(dest="command", required=True)

    lg = sub.add_parser("login", help="sign in and remember the session")
    lg.add_argument("--email")
    lg.add_argument("--password", help="omit to be prompted (not echoed)")
    lg.add_argument("--server", help="override the configured API server")
    lg.add_argument("--no-remember", action="store_true",
                    help="do not save the session to disk (sign in for this command only)")
    lg.set_defaults(func=cmd_login)

    lo = sub.add_parser("logout", help="end the saved session")
    lo.set_defaults(func=cmd_logout)

    r = sub.add_parser("register", help="create an account")
    r.add_argument("--email", required=True)
    r.add_argument("--password", help="omit to be prompted (not echoed)")
    r.add_argument("--name", help="display name")
    r.add_argument("--organisation", help="create a team and make this account its admin")
    r.add_argument("--join-token", help="redeem a team invite instead of creating one")
    r.add_argument("--server", help="override the configured API server")
    r.add_argument("--no-remember", action="store_true",
                    help="do not save the session to disk (sign in for this command only)")
    r.set_defaults(func=cmd_register)

    w = sub.add_parser("whoami", help="show who is currently signed in")
    w.set_defaults(func=cmd_whoami)

    s = sub.add_parser("scan-apk", help="static analysis of an APK (no device)")
    s.add_argument("apk")
    s.set_defaults(func=cmd_scan_apk)

    a = sub.add_parser("assess", help="full black-box assessment on a connected device")
    a.add_argument("--package", required=True)
    a.add_argument("--apk", help="APK on disk (enables the IPC oracle + static analysis)")
    a.add_argument("--i-am-authorized", action="store_true",
                   help="confirm you own or are authorized to test this app")
    a.set_defaults(func=cmd_assess)

    e = sub.add_parser("explain", help="ask the server to explain a saved run's findings")
    e.add_argument("scan_id")
    e.set_defaults(func=cmd_explain)

    d = sub.add_parser("dashboard", help="launch the Streamlit dashboard")
    d.set_defaults(func=cmd_dashboard)

    g = sub.add_parser("gui", help="launch the PySide6 desktop app")
    g.set_defaults(func=cmd_gui)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = Config.load(args.config)
    return args.func(args, cfg)
