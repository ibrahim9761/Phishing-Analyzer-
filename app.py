"""
AI Phishing Email Analyzer
---------------------------
Streamlit front-end. Paste a suspicious email (raw with headers, or just
the body) and get a rule-based risk report, with an optional local-AI
(Ollama) plain-English explanation.

Run with:  streamlit run app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

# Make src/ importable regardless of where streamlit is launched from
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.ai.ollama_explainer import explain_report, is_ollama_available
from src.analyzer.risk_scorer import analyze_email

st.set_page_config(
    page_title="AI Phishing Email Analyzer",
    page_icon="🛡️",
    layout="wide",
)

VERDICT_STYLE = {
    "Low": {"color": "#1f9d55", "emoji": "🟢"},
    "Medium": {"color": "#d97706", "emoji": "🟠"},
    "High": {"color": "#dc2626", "emoji": "🔴"},
}

SAMPLE_DIR = Path(__file__).resolve().parent / "data" / "sample_emails"


def load_samples() -> dict[str, str]:
    samples = {}
    if SAMPLE_DIR.exists():
        for f in sorted(SAMPLE_DIR.glob("*.txt")):
            samples[f.stem.replace("_", " ").title()] = f.read_text(encoding="utf-8")
    return samples


def render_verdict_badge(verdict: str, score: int) -> None:
    style = VERDICT_STYLE.get(verdict, {"color": "#666", "emoji": "⚪"})
    st.markdown(
        f"""
        <div style="
            display:inline-block; padding: 14px 28px; border-radius: 10px;
            background-color:{style['color']}22; border: 2px solid {style['color']};
            font-size: 1.4rem; font-weight: 700; color:{style['color']};">
            {style['emoji']} {verdict} Risk &nbsp;·&nbsp; Score: {score}
        </div>
        """,
        unsafe_allow_html=True,
    )


def main() -> None:
    st.title("🛡️ AI Phishing Email Analyzer")
    st.caption("Paste a suspicious email below. Everything runs locally — nothing is sent anywhere unless you explicitly enable the local Ollama explanation.")

    with st.sidebar:
        st.header("About")
        st.write(
            "This tool applies well-known, publicly documented phishing "
            "heuristics — suspicious URLs, urgency/credential-harvesting "
            "language, and sender-header inconsistencies — to score an "
            "email's risk. It is an educational / security-awareness "
            "project, not a substitute for enterprise email security."
        )
        st.divider()
        st.subheader("Sample emails")
        samples = load_samples()
        chosen_sample = st.selectbox("Load a sample", ["-- none --"] + list(samples.keys()))
        st.divider()
        st.subheader("Optional: Local AI explanation")
        use_ai = st.checkbox("Explain result with local AI (Ollama)", value=False)
        model_name = st.text_input("Ollama model", value="llama3", disabled=not use_ai)
        if use_ai:
            if is_ollama_available():
                st.success("Ollama detected on localhost:11434")
            else:
                st.warning("Ollama not detected — start it with `ollama serve`")

    default_text = samples.get(chosen_sample, "") if chosen_sample != "-- none --" else ""
    email_text = st.text_area(
        "Paste email content (raw with headers, or just the body)",
        value=default_text,
        height=300,
        placeholder="From: security@paypa1-support.com\nSubject: Your account will be suspended\n\nDear customer, we detected unusual activity...",
    )

    analyze_clicked = st.button("🔍 Analyze Email", type="primary", use_container_width=False)

    if analyze_clicked:
        if not email_text.strip():
            st.warning("Please paste an email first.")
            return

        report = analyze_email(email_text)

        st.divider()
        render_verdict_badge(report.verdict, report.score)

        st.markdown("#### Summary")
        for line in report.summary:
            st.write(f"- {line}")

        tab_urls, tab_keywords, tab_headers, tab_ai = st.tabs(
            ["🔗 URLs", "🔑 Keywords", "✉️ Headers", "🤖 AI Explanation"]
        )

        with tab_urls:
            if not report.urls:
                st.info("No URLs found in this email.")
            for f in report.urls:
                risk_icon = "⚠️" if f.flags else "✅"
                st.markdown(f"**{risk_icon} `{f.url}`** — risk points: {f.risk_points}")
                if f.flags:
                    for flag in f.flags:
                        st.write(f"  - {flag}")
                else:
                    st.write("  - No red flags detected for this link")

        with tab_keywords:
            if not report.keywords:
                st.info("No suspicious phrases detected.")
            else:
                by_category: dict[str, list] = {}
                for m in report.keywords:
                    by_category.setdefault(m.category, []).append(m)
                for category, matches in by_category.items():
                    st.markdown(f"**{category.replace('_', ' ').title()}**")
                    for m in matches:
                        st.write(f"  - \"{m.term}\" (weight {m.weight})")

        with tab_headers:
            h = report.headers
            if not h or not h.has_headers:
                st.info("No email headers were pasted — header-spoofing checks skipped. "
                         "Paste From:/Reply-To:/Subject: lines to enable this check.")
            else:
                st.write(f"**From display name:** {h.from_display_name or '(none)'}")
                st.write(f"**From address:** {h.from_address or '(none)'}")
                st.write(f"**Reply-To address:** {h.reply_to_address or '(none)'}")
                if h.flags:
                    st.markdown("**Flags:**")
                    for flag in h.flags:
                        st.write(f"  - ⚠️ {flag}")
                else:
                    st.write("No header inconsistencies detected.")

        with tab_ai:
            if not use_ai:
                st.info("Enable 'Explain result with local AI (Ollama)' in the sidebar to generate a plain-English explanation.")
            else:
                with st.spinner("Generating explanation via local Ollama model..."):
                    explanation = explain_report(report, model=model_name or "llama3")
                st.write(explanation)


if __name__ == "__main__":
    main()
