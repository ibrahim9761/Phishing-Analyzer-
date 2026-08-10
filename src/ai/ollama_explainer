"""
ollama_explainer.py
--------------------
Optional module that turns the structured RiskReport into a plain-English
explanation using a locally-running Ollama model (e.g. llama3, mistral).

This is fully optional -- the analyzer works standalone without it. If
Ollama is not installed/running, functions here return a friendly error
message instead of raising, so the Streamlit app degrades gracefully.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

# Respects OLLAMA_HOST env var so this works both locally (localhost) and
# inside Docker Compose (where the service is reachable as "ollama").
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_URL = f"{OLLAMA_HOST}/api/generate"
DEFAULT_MODEL = "llama3"
TIMEOUT_SECONDS = 30


def is_ollama_available() -> bool:
    try:
        req = urllib.request.Request(f"{OLLAMA_HOST}/api/tags")
        with urllib.request.urlopen(req, timeout=3):
            return True
    except Exception:
        return False


def _build_prompt(report) -> str:
    url_lines = []
    for f in report.urls:
        if f.flags:
            url_lines.append(f"- {f.url} -> " + "; ".join(f.flags))
    keyword_lines = [f"- \"{m.term}\" ({m.category})" for m in report.keywords]
    header_lines = report.headers.flags if report.headers else []

    prompt = f"""You are a security-awareness assistant helping a non-technical
employee understand why an email was flagged. Be concise (under 150 words),
avoid jargon, and end with one practical piece of advice.

Verdict: {report.verdict} risk (score: {report.score})

Suspicious URLs:
{chr(10).join(url_lines) or "None found"}

Suspicious phrases:
{chr(10).join(keyword_lines) or "None found"}

Header inconsistencies:
{chr(10).join(header_lines) or "None found"}

Explain in plain English why this email received this risk level, and what
the recipient should do next.
"""
    return prompt


def explain_report(report, model: str = DEFAULT_MODEL) -> str:
    """Return a plain-English explanation of a RiskReport using a local
    Ollama model. Falls back to a helpful message if Ollama isn't running."""
    if not is_ollama_available():
        return (
            f"Local AI explanation unavailable: Ollama doesn't seem to be reachable "
            f"at {OLLAMA_HOST}. Install it from https://ollama.com, pull a model "
            f"with `ollama pull {model}`, and start it with `ollama serve`. "
            "The rule-based analysis above still fully applies without it."
        )

    payload = {
        "model": model,
        "prompt": _build_prompt(report),
        "stream": False,
    }

    try:
        req = urllib.request.Request(
            OLLAMA_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("response", "").strip() or "No explanation returned by the model."
    except urllib.error.URLError as e:
        return f"Could not reach Ollama: {e}"
    except Exception as e:  # pragma: no cover - defensive fallback
        return f"Unexpected error generating AI explanation: {e}"
