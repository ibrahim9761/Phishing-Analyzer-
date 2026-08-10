"""
keyword_detector.py
--------------------
Scans email body text for phrases commonly associated with phishing
(urgency cues, credential-harvesting language, financial lures, authority
impersonation, and other generic red flags). The phrase list is
data-driven from data/keywords.json so it can be extended without
touching code.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

DEFAULT_KEYWORDS_PATH = Path(__file__).resolve().parents[2] / "data" / "keywords.json"


@dataclass
class KeywordMatch:
    term: str
    category: str
    weight: int


def load_keyword_db(path: Path = DEFAULT_KEYWORDS_PATH) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def detect_keywords(text: str, db: dict | None = None) -> list[KeywordMatch]:
    """Case-insensitive whole-phrase search across all categories."""
    if db is None:
        db = load_keyword_db()

    text_lower = text.lower()
    matches: list[KeywordMatch] = []

    for category, config in db.items():
        weight = config.get("weight", 1)
        for term in config.get("terms", []):
            pattern = r"\b" + re.escape(term.lower()) + r"\b"
            if re.search(pattern, text_lower):
                matches.append(KeywordMatch(term=term, category=category, weight=weight))

    return matches
