"""Saved-session persistence, shared by the CLI and the desktop GUI.

Kept free of any GUI toolkit import so the CLI can sign in without pulling in PySide6,
and so the GUI's sign-in dialog (`gui/signin.py`) can reuse the same file format.

An account is now required everywhere: BioAudit has no local storage and no guest mode,
so a saved session is what lets a second launch skip typing a password again, not an
optional convenience layered on top of an offline mode.

On storing the session: signing in returns a refresh token, which is long-lived and can
mint new access tokens. Writing it to disk is therefore a real trade-off, so it is opt-in
through a checkbox that defaults to off. When the user does opt in, the file goes in their
home directory with permissions narrowed as far as the platform allows.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Optional

from .api import ApiClient, ApiClientError, Session

SESSION_FILENAME = "session.json"


def session_path(base_dir: str | os.PathLike) -> Path:
    return Path(base_dir) / SESSION_FILENAME


def save_session(base_dir: str | os.PathLike, client: ApiClient) -> Optional[Path]:
    """Write the session so the next launch does not need a password.

    Returns the path written, or None if it could not be saved. A failure here is not
    worth interrupting the user for: they are already signed in for this run.
    """
    if client.session is None:
        return None

    path = session_path(base_dir)
    payload = {
        "base_url": client.base_url,
        "session": client.session.to_dict(),
        "email": client.account.email if client.account else None,
    }

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        # Narrow to owner-only. This is the main protection on POSIX; on Windows the
        # call is accepted but the real control is the user's own profile directory.
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        return path
    except OSError:
        return None


def clear_session(base_dir: str | os.PathLike) -> None:
    try:
        session_path(base_dir).unlink(missing_ok=True)
    except OSError:
        pass


def restore_session(base_dir: str | os.PathLike, default_base_url: str) -> Optional[ApiClient]:
    """Rebuild a signed-in client from a saved session, or return None.

    The stored access token has almost certainly expired, so this refreshes before
    handing the client back. If the refresh fails, for any reason from a revoked session
    to the server being down, the stored file is useless and is removed.
    """
    path = session_path(base_dir)
    if not path.exists():
        return None

    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        client = ApiClient(payload.get("base_url") or default_base_url)
        client.session = Session.from_dict(payload["session"])
    except (OSError, KeyError, ValueError, json.JSONDecodeError):
        clear_session(base_dir)
        return None

    try:
        client.refresh()
        client.get_profile()
    except ApiClientError:
        clear_session(base_dir)
        return None

    return client


def default_base_dir() -> Path:
    """Where the session file lives (the GUI also writes exported reports alongside it).

    Anchored under the user's home directory, not the current working directory, so a
    double-clicked exe or a CLI invoked from a read-only folder can always write here.
    """
    base = Path(os.path.expanduser("~")) / "BioAudit"
    base.mkdir(parents=True, exist_ok=True)
    return base
