"""Grounded explanation + mitigation via the Gemini API.

Uses the google-genai SDK with structured output (`response_schema`). Key:
GEMINI_API_KEY (or GOOGLE_API_KEY). The model only *explains* findings the
deterministic engine already confirmed — it never decides whether a vulnerability
exists. Degrades gracefully: if the SDK is missing, no key is available, or a
request fails, findings keep their deterministic data and simply lack the prose.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional

from ..models import Finding
from . import prompts
from .redaction import redact

# pydantic is only needed for the AI layer; keep it optional so the deterministic
# core (static analysis, IPC oracle, observers, reporting) runs without it.
try:
    from pydantic import BaseModel

    class Explanation(BaseModel):
        """Schema the model must fill for every finding."""

        explanation: str        # plain-language description of the risk
        mitigation: str         # concrete fix
        references: list[str]   # doc/OWASP anchors

    _HAVE_PYDANTIC = True
except ImportError:  # pragma: no cover - exercised only when AI deps are absent
    Explanation = None
    _HAVE_PYDANTIC = False


# A rolling alias so we track Google's current flash model; if even this is
# rejected, _call_gemini auto-discovers an available model from the API.
_DEFAULT_MODEL = "gemini-flash-latest"


def _looks_model_unavailable(exc: Exception) -> bool:
    s = str(exc).lower()
    return "not_found" in s or "404" in s or "no longer available" in s or "is not found" in s


def _looks_transient(exc: Exception) -> bool:
    """Server-side hiccups worth retrying: overload, rate limit, timeouts."""
    s = str(exc).lower()
    return any(t in s for t in (
        "503", "502", "500", "429", "unavailable", "overloaded",
        "high demand", "resource_exhausted", "timeout", "deadline",
    ))


class Explainer:
    def __init__(self, model: Optional[str] = None, effort: str = "medium",
                 redact_before_send: bool = True, knowledge_base_path: Optional[str] = None):
        self.model = self._resolve_model(model)
        self.effort = effort
        self.redact_before_send = redact_before_send
        self._kb = self._load_kb(knowledge_base_path)
        self._client = self._make_client()

    def _resolve_model(self, model: Optional[str]) -> str:
        """Use the configured model, falling back to the default when it is missing
        or not a Gemini model id (e.g. a stale id left in config)."""
        if not model:
            return _DEFAULT_MODEL
        if not (model.startswith("gemini") or model.startswith("models/gemini")):
            return _DEFAULT_MODEL
        return model

    def _make_client(self):
        if not _HAVE_PYDANTIC:
            return None
        try:
            from google import genai
        except ImportError:
            return None
        key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        try:
            return genai.Client(api_key=key) if key else genai.Client()
        except Exception:
            return None

    @staticmethod
    def _load_kb(path: Optional[str]) -> str:
        if path and Path(path).exists():
            return Path(path).read_text(encoding="utf-8")
        return ""

    @property
    def available(self) -> bool:
        return self._client is not None

    def explain(self, finding: Finding) -> Finding:
        """Attach explanation/mitigation to a finding; no-op if AI is unavailable."""
        if not self.available:
            return finding

        evidence = redact(finding.evidence) if self.redact_before_send else finding.evidence
        user = prompts.user_prompt(
            finding_evidence=evidence,
            category=finding.category,
            owasp=finding.owasp,
            knowledge_base=self._kb,
        )
        try:
            result = self._generate_with_retries(user)
            finding.explanation = result.explanation
            finding.mitigation = result.mitigation
            finding.references = result.references
        except Exception as exc:  # never let AI failure break the pipeline
            finding.explanation = finding.explanation or f"(AI explanation unavailable: {exc})"
        return finding

    def _generate_with_retries(self, user: str, attempts: int = 4) -> "Explanation":
        """Call the backend, retrying transient overloads with exponential backoff."""
        delay = 1.0
        for i in range(attempts):
            try:
                return self._call_gemini(user)
            except Exception as exc:
                if i == attempts - 1 or not _looks_transient(exc):
                    raise
                time.sleep(delay)
                delay *= 2

    def _call_gemini(self, user: str) -> "Explanation":
        from google.genai import types

        config = types.GenerateContentConfig(
            system_instruction=prompts.SYSTEM,
            response_mime_type="application/json",
            response_schema=Explanation,
        )
        try:
            response = self._client.models.generate_content(
                model=self.model, contents=user, config=config)
        except Exception as exc:  # model retired/unavailable → find a live one and retry
            if not _looks_model_unavailable(exc):
                raise
            better = self._discover_gemini_model(self._client, self.model)
            if better == self.model:
                raise
            self.model = better
            response = self._client.models.generate_content(
                model=self.model, contents=user, config=config)

        parsed = response.parsed
        if parsed is None:  # SDK returned raw text instead of a parsed object
            parsed = Explanation.model_validate_json(response.text)
        return parsed

    @staticmethod
    def _discover_gemini_model(client, preferred: str) -> str:
        """Return an available model that supports generateContent, preferring a
        flash-class model. Falls back to `preferred` if discovery fails."""
        import re

        try:
            names = [
                m.name.split("/")[-1]
                for m in client.models.list()
                if "generateContent" in (getattr(m, "supported_actions", None) or [])
            ]
        except Exception:
            return preferred
        if not names:
            return preferred
        if preferred in names:
            return preferred

        def version(n: str) -> float:
            match = re.search(r"(\d+\.\d+|\d+)", n)
            return float(match.group(1)) if match else 0.0

        # Plain flash text models first (skip image/tts/live/embedding variants),
        # newest version first; then any general-purpose text model.
        excluded = ("image", "tts", "vision", "live", "embedding", "aqa", "learnlm")
        flash = [n for n in names if "flash" in n and not any(x in n for x in excluded)]
        if flash:
            return sorted(flash, key=version, reverse=True)[0]
        general = [n for n in names if not any(x in n for x in excluded)]
        return sorted(general, key=version, reverse=True)[0] if general else names[0]

    def explain_all(self, findings: list[Finding]) -> list[Finding]:
        return [self.explain(f) for f in findings]
