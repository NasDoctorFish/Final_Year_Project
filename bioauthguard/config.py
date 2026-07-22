"""Load configuration from a YAML file, falling back to sane defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional

_DEFAULTS: dict[str, Any] = {
    "device": {"serial": None, "adb_path": "adb"},
    "runtime": {"trials_per_scenario": 30, "settle_seconds": 2},
    "ai": {
        "enabled": True,
        "model": None,                     # None -> default (gemini-flash-latest)
        "redact_before_send": True,
        "effort": "medium",
        "knowledge_base": "config/knowledge_base/android_biometric_kb.md",
    },
    "storage": {"database": "bioauthguard.sqlite"},
    "report": {"output_dir": "reports"},
}


@dataclass
class Config:
    device: dict = field(default_factory=lambda: dict(_DEFAULTS["device"]))
    runtime: dict = field(default_factory=lambda: dict(_DEFAULTS["runtime"]))
    ai: dict = field(default_factory=lambda: dict(_DEFAULTS["ai"]))
    storage: dict = field(default_factory=lambda: dict(_DEFAULTS["storage"]))
    report: dict = field(default_factory=lambda: dict(_DEFAULTS["report"]))

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        cfg = cls()
        candidate = path or os.environ.get("BIOAUTHGUARD_CONFIG", "config/config.yaml")
        if candidate and os.path.exists(candidate):
            import yaml  # optional; only needed to parse an on-disk config file
            with open(candidate, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
            for section in ("device", "runtime", "ai", "storage", "report"):
                getattr(cfg, section).update(raw.get(section, {}))
        return cfg
