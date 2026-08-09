"""Redact secrets from finding evidence before it is sent to the model.

Inputs to the AI layer include decompiled internals and possibly leaked secrets
from logcat. Scrub them so real key material never leaves the machine in a prompt.
"""

from __future__ import annotations

import re

_REDACTORS = [
    (re.compile(r"(?i)(token|secret|api[_-]?key|password|passwd)(\s*[:=]\s*)(\S+)"),
     lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]"),
    (re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"), lambda m: "[REDACTED_BLOB]"),
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), lambda m: "[REDACTED_HEX]"),
]


def redact(text: str) -> str:
    if not text:
        return text
    for pattern, repl in _REDACTORS:
        text = pattern.sub(repl, text)
    return text
