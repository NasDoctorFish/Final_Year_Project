"""Thin wrapper around the `adb` CLI. No root is assumed anywhere.

Every runtime observation the tool makes goes through this class: shell commands,
component probing, logcat capture, screenshots, and backups.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional


class AdbError(RuntimeError):
    pass


def resolve_adb(adb_path: str = "adb") -> str:
    """Locate the adb binary.

    Honour an explicit path from config. Otherwise prefer adb on PATH, then fall
    back to the standard Android SDK locations — a machine can have the SDK's adb
    without it being on PATH (or with a stale PATH entry pointing at a moved
    platform-tools folder)."""
    if adb_path and adb_path != "adb":
        return adb_path  # explicitly configured; respect it
    if shutil.which("adb"):
        return "adb"
    candidates = [
        os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe"),
        os.path.expandvars(r"%USERPROFILE%\AppData\Local\Android\Sdk\platform-tools\adb.exe"),
        os.path.expandvars(r"%ANDROID_HOME%\platform-tools\adb.exe"),
        os.path.expandvars(r"%ANDROID_SDK_ROOT%\platform-tools\adb.exe"),
        os.path.expandvars(r"%ProgramFiles%\Android\android-sdk\platform-tools\adb.exe"),
        os.path.expanduser("~/Android/Sdk/platform-tools/adb"),          # Linux/macOS
        os.path.expanduser("~/Library/Android/sdk/platform-tools/adb"),  # macOS
    ]
    for cand in candidates:
        if cand and os.path.isfile(cand):
            return cand
    return "adb"  # give up; a clear "adb binary not found" error will follow


@dataclass
class AdbResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class Adb:
    def __init__(self, adb_path: str = "adb", serial: Optional[str] = None):
        self.adb_path = resolve_adb(adb_path)
        self.serial = serial

    def _base(self) -> list[str]:
        cmd = [self.adb_path]
        if self.serial:
            cmd += ["-s", self.serial]
        return cmd

    def run(self, *args: str, timeout: int = 60) -> AdbResult:
        kwargs = dict(
            capture_output=True,
            text=True,
            timeout=timeout,
            # A windowed (no-console) frozen build has no valid stdin/console;
            # redirect stdin and suppress console-window flashes, and decode
            # defensively since logcat can carry non-UTF-8 bytes.
            stdin=subprocess.DEVNULL,
            encoding="utf-8",
            errors="replace",
        )
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            proc = subprocess.run(self._base() + list(args), **kwargs)
        except FileNotFoundError as exc:
            raise AdbError(f"adb binary not found at '{self.adb_path}'") from exc
        except subprocess.TimeoutExpired as exc:
            raise AdbError(f"adb command timed out: {' '.join(args)}") from exc
        # capture_output should yield strings, but guard against None so callers
        # can always .splitlines() safely.
        return AdbResult(proc.returncode, proc.stdout or "", proc.stderr or "")

    def shell(self, *args: str, timeout: int = 60) -> AdbResult:
        return self.run("shell", *args, timeout=timeout)

    # --- device discovery -------------------------------------------------

    def devices(self) -> list[str]:
        res = self.run("devices")
        serials = []
        for line in res.stdout.splitlines()[1:]:
            line = line.strip()
            if line and line.endswith("device"):
                serials.append(line.split()[0])
        return serials

    def require_device(self) -> str:
        """Return the target serial, erroring if the selection is ambiguous."""
        serials = self.devices()
        if not serials:
            raise AdbError("no authorized device connected (check USB debugging)")
        if self.serial:
            if self.serial not in serials:
                raise AdbError(f"configured serial '{self.serial}' not connected")
            return self.serial
        if len(serials) > 1:
            raise AdbError(f"multiple devices connected; set device.serial: {serials}")
        self.serial = serials[0]
        return self.serial

    # --- app inspection ---------------------------------------------------

    def is_installed(self, package: str) -> bool:
        res = self.shell("pm", "list", "packages", package)
        return any(line.strip() == f"package:{package}" for line in res.stdout.splitlines())

    def list_packages(self, third_party_only: bool = True) -> list[str]:
        """Return installed package names, sorted. Third-party (user-installed)
        apps by default; pass third_party_only=False to include system apps."""
        args = ["pm", "list", "packages"]
        if third_party_only:
            args.append("-3")
        res = self.shell(*args)
        pkgs = [
            line.strip()[len("package:"):]
            for line in res.stdout.splitlines()
            if line.strip().startswith("package:")
        ]
        return sorted(pkgs)

    def dump_manifest(self, package: str) -> str:
        """Best-effort manifest dump for an installed app (no root)."""
        return self.shell("dumpsys", "package", package).stdout
