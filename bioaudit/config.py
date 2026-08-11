"""Load configuration from a YAML file, falling back to sane defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional

_DEFAULTS: dict[str, Any] = {
    "device": {"serial": None, "adb_path": "adb"},
    "runtime": {"trials_per_scenario": 30, "settle_seconds": 2},
    "report": {"output_dir": "reports"},
    # Backend for accounts and history. BioAudit keeps no local copy of a scan, so every
    # front end needs this to do anything: `enabled` just tracks whether the current
    # process has signed in yet, not whether it is allowed to. Points at the hosted
    # Cloud Run deployment by default, so signing up on one computer and signing in on
    # another just works with no setup. The GUI has no field for this any more (an
    # ordinary user never needs to see or change it); self-hosters override base_url in
    # config.yaml, or with --server on the CLI's login/register.
    "api": {
        "enabled": False,
        "base_url": "https://bioaudit-api-391854054876.us-central1.run.app/api",
    },
}


@dataclass
class Config:
    device: dict = field(default_factory=lambda: dict(_DEFAULTS["device"]))
    runtime: dict = field(default_factory=lambda: dict(_DEFAULTS["runtime"]))
    report: dict = field(default_factory=lambda: dict(_DEFAULTS["report"]))
    api: dict = field(default_factory=lambda: dict(_DEFAULTS["api"]))

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        cfg = cls()
        candidate = path or os.environ.get("BIOAUDIT_CONFIG", "config/config.yaml")
        if candidate and os.path.exists(candidate):
            import yaml  # optional; only needed to parse an on-disk config file
            with open(candidate, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
            for section in ("device", "runtime", "report", "api"):
                getattr(cfg, section).update(raw.get(section, {}))
        return cfg
