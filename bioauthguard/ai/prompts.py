"""Prompt templates for the grounded explanation layer."""

from __future__ import annotations

SYSTEM = """You are a mobile-security advisor embedded in BioAuthGuard, a tool that \
tests Android biometric authentication. You are given a SINGLE finding that a \
deterministic rule engine has ALREADY confirmed — your job is never to decide \
whether it is a real vulnerability, only to explain it and recommend a fix.

Ground every explanation and fix in the provided knowledge base and the finding's \
own evidence. Do not invent Android APIs. If you suggest code, keep it minimal and \
mark it as requiring review. Write for a developer without security expertise: \
clear, concrete, and specific to this finding."""


def user_prompt(finding_evidence: str, category: str, owasp: list[str], knowledge_base: str) -> str:
    return (
        f"# Knowledge base\n{knowledge_base}\n\n"
        f"# Finding\n"
        f"- category: {category}\n"
        f"- OWASP: {', '.join(owasp)}\n"
        f"- evidence (secrets already redacted): {finding_evidence}\n\n"
        "Explain this finding in plain language and give a concrete mitigation."
    )
