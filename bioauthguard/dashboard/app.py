"""Streamlit dashboard: browse test history and drill into findings.

Run with:  python -m bioauthguard dashboard    (wraps `streamlit run`)
"""

from __future__ import annotations

from ..config import Config
from ..storage.history import History


def main() -> None:
    import streamlit as st

    cfg = Config.load()
    history = History(cfg.storage["database"])

    st.set_page_config(page_title="BioAuthGuard", page_icon="🔐", layout="wide")
    st.title("🔐 BioAuthGuard")
    st.caption("Android biometric authentication security — test history")

    runs = history.list_runs()
    if not runs:
        st.info("No test runs yet. Run `python -m bioauthguard assess ...` first.")
        return

    st.subheader("Runs")
    st.dataframe(runs, use_container_width=True)

    ids = [r["id"] for r in runs]
    selected = st.selectbox("Inspect a run", ids)
    if selected:
        payload = history.get(selected)
        if payload:
            counts = payload["counts"]
            cols = st.columns(len(counts))
            for col, (label, value) in zip(cols, counts.items()):
                col.metric(label, value)
            st.subheader("Findings")
            for f in payload["findings"]:
                with st.expander(f"[{f['severity']}] {f['title']}  ·  {', '.join(f['owasp'])}"):
                    st.write(f"**Evidence:** {f['evidence']}")
                    if f.get("explanation"):
                        st.write(f"**Explanation:** {f['explanation']}")
                    if f.get("mitigation"):
                        st.write(f"**Mitigation:** {f['mitigation']}")


if __name__ == "__main__":
    main()
