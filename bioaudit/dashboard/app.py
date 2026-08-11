"""Streamlit dashboard: browse test history and drill into findings.

Run with:  python -m bioaudit dashboard    (wraps `streamlit run`)

Reads from the account's server-side history, the same one the CLI and the desktop app
upload to, since BioAudit keeps no local copy of a scan. Sign in first with
`bioaudit login` — the dashboard has no login form of its own, both because Streamlit
reruns the whole script on every interaction (awkward for anything password-shaped) and
because a session created once with `bioaudit login` is exactly what all three front
ends are meant to share.
"""

from __future__ import annotations

from ..api import ApiClientError
from ..config import Config
from ..session import default_base_dir, restore_session


def main() -> None:
    import streamlit as st

    cfg = Config.load()

    st.set_page_config(page_title="BioAudit", page_icon="🔐", layout="wide")
    st.title("🔐 BioAudit")
    st.caption("Android biometric authentication security — account history")

    client = restore_session(default_base_dir(), cfg.api["base_url"])
    if client is None:
        st.warning(
            "Not signed in. Run `bioaudit login` in a terminal, then reload this page. "
            "BioAudit stores every scan on your account rather than on this computer, "
            "so there is nothing to show without one."
        )
        return

    account = client.account
    st.caption(
        f"Signed in as **{account.email}** · {account.tier} plan"
        + (" · admin" if account.is_admin else "")
    )

    try:
        data = client.list_history(limit=100)
    except ApiClientError as exc:
        st.error(f"Could not load your history: {exc}")
        return

    scans = data.get("scans", [])
    if not scans:
        st.info(
            "No scans saved yet. Run `bioaudit scan-apk <apk>` or "
            "`bioaudit assess --package ... --i-am-authorized` first."
        )
        return

    limit = data.get("historyLimit")
    if limit is not None:
        st.caption(f"Your plan keeps the newest {limit} runs; upgrade for the full history.")

    st.subheader("Runs")
    rows = [
        {
            "id": s.get("id"),
            "when": str(s.get("createdAt", ""))[:19],
            "type": s.get("type"),
            "target": (s.get("target") or {}).get("packageName")
            or (s.get("target") or {}).get("apkFileName") or "unknown",
            **(s.get("counts") or {}),
        }
        for s in scans
    ]
    st.dataframe(rows, use_container_width=True, hide_index=True)

    ids = [s["id"] for s in scans]
    selected = st.selectbox("Inspect a run", ids)
    if not selected:
        return

    try:
        scan = client.get_scan(selected)
    except ApiClientError as exc:
        st.error(f"Could not load that scan: {exc}")
        return

    counts = scan.get("counts", {})
    cols = st.columns(len(counts) or 1)
    for col, (label, value) in zip(cols, counts.items()):
        col.metric(label, value)

    st.subheader("Findings")
    findings = scan.get("findings", [])
    if not findings:
        st.write("No findings in this run.")
    for f in findings:
        owasp = ", ".join(f.get("owasp", []))
        with st.expander(f"[{f.get('severity', '?').upper()}] {f.get('title', '')}  ·  {owasp}"):
            st.write(f"**Evidence:** {f.get('evidence', '')}")
            if f.get("explanation"):
                st.write(f"**Explanation:** {f['explanation']}")
            if f.get("mitigation"):
                st.write(f"**Mitigation:** {f['mitigation']}")


if __name__ == "__main__":
    main()
