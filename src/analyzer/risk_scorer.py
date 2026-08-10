"""
risk_scorer.py
---------------
Combines URL findings, keyword matches, and header findings into a single
composite score, then maps that score to a Low / Medium / High risk
verdict. Thresholds are intentionally conservative and tunable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .email_parser import HeaderFinding, analyze_headers
from .keyword_detector import KeywordMatch, detect_keywords, load_keyword_db
from .url_extractor import UrlFinding, analyze_urls

LOW_MAX = 6      # score <= LOW_MAX          -> Low
MEDIUM_MAX = 15   # LOW_MAX < score <= MEDIUM_MAX -> Medium
                  # score > MEDIUM_MAX        -> High


@dataclass
class RiskReport:
    verdict: str
    score: int
    urls: list[UrlFinding] = field(default_factory=list)
    keywords: list[KeywordMatch] = field(default_factory=list)
    headers: HeaderFinding = None
    summary: list[str] = field(default_factory=list)


def _verdict_for_score(score: int) -> str:
    if score <= LOW_MAX:
        return "Low"
    if score <= MEDIUM_MAX:
        return "Medium"
    return "High"


def analyze_email(raw_text: str) -> RiskReport:
    """Run the full detection pipeline on a pasted email (raw or plain body)."""
    kw_db = load_keyword_db()

    url_findings = analyze_urls(raw_text)
    keyword_matches = detect_keywords(raw_text, kw_db)
    header_finding = analyze_headers(raw_text)

    score = 0
    score += sum(f.risk_points for f in url_findings)
    score += sum(m.weight for m in keyword_matches)
    score += header_finding.risk_points

    # Small bump if multiple different suspicious URLs are present
    suspicious_url_count = sum(1 for f in url_findings if f.flags)
    if suspicious_url_count >= 2:
        score += 2

    verdict = _verdict_for_score(score)

    summary = []
    if suspicious_url_count:
        summary.append(f"{suspicious_url_count} suspicious link(s) detected")
    if keyword_matches:
        categories = sorted({m.category.replace('_', ' ') for m in keyword_matches})
        summary.append(f"Phishing language detected in categories: {', '.join(categories)}")
    if header_finding.flags:
        summary.append("Sender header inconsistencies detected")
    if not summary:
        summary.append("No strong phishing indicators detected")

    return RiskReport(
        verdict=verdict,
        score=score,
        urls=url_findings,
        keywords=keyword_matches,
        headers=header_finding,
        summary=summary,
    )
