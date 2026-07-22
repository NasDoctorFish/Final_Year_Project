"""Render a TestRun to a self-contained HTML report, optionally exporting to PDF."""

from __future__ import annotations

import html
import os
from datetime import datetime

from ..models import TestRun

_SEVERITY_COLORS = {
    "Critical": "#b00020", "High": "#d9534f", "Medium": "#f0ad4e",
    "Low": "#5bc0de", "Info": "#777",
}


def render_html(run: TestRun) -> str:
    counts = run.counts()
    rows = []
    for f in run.ranked():
        color = _SEVERITY_COLORS.get(f.severity.label, "#777")
        rows.append(f"""
        <div class="finding">
          <span class="sev" style="background:{color}">{f.severity.label}</span>
          <strong>{html.escape(f.title)}</strong>
          <span class="owasp">{html.escape(', '.join(f.owasp))}</span>
          <span class="conf">{html.escape(f.confidence)}</span>
          <div class="evidence"><em>Evidence:</em> {html.escape(f.evidence)}</div>
          {_optional('Explanation', f.explanation)}
          {_optional('Mitigation', f.mitigation)}
        </div>""")

    summary = " ".join(
        f'<span class="pill" style="background:{_SEVERITY_COLORS[k]}">{k}: {v}</span>'
        for k, v in counts.items() if v
    ) or "No findings."

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>BioAuthGuard report — {html.escape(run.package)}</title>
<style>
 body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#222}}
 .pill,.sev{{color:#fff;padding:2px 8px;border-radius:4px;font-size:.8rem}}
 .finding{{border:1px solid #eee;border-left:4px solid #ccc;padding:1rem;margin:1rem 0;border-radius:4px}}
 .owasp,.conf{{color:#666;font-size:.8rem;margin-left:.5rem}}
 .evidence{{margin-top:.5rem;font-size:.9rem;color:#444;word-break:break-word}}
 h1{{margin-bottom:.2rem}}
</style></head><body>
<h1>BioAuthGuard Security Report</h1>
<p><strong>Package:</strong> {html.escape(run.package)}<br>
<strong>Generated:</strong> {datetime.now():%Y-%m-%d %H:%M}</p>
<p>{summary}</p>
<hr>
{''.join(rows) or '<p>No findings.</p>'}
</body></html>"""


def export(run: TestRun, output_dir: str, to_pdf: bool = False) -> str:
    os.makedirs(output_dir, exist_ok=True)
    html_content = render_html(run)
    base = os.path.join(output_dir, f"report-{run.package}-{run.id}")
    html_path = base + ".html"
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_content)

    if to_pdf:
        try:
            from weasyprint import HTML
            pdf_path = base + ".pdf"
            HTML(string=html_content).write_pdf(pdf_path)
            return pdf_path
        except Exception:
            pass  # fall back to HTML if weasyprint isn't available
    return html_path


def _optional(label: str, value) -> str:
    if not value:
        return ""
    return f'<div class="evidence"><em>{label}:</em> {html.escape(str(value))}</div>'
