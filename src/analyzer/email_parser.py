"""
email_parser.py
----------------
Optional header-level analysis. If the user pastes a raw email (with
headers like From/Reply-To/Subject), this module checks for classic
sender-spoofing signals. If only a plain body is pasted, these checks
are skipped gracefully.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import message_from_string
from email.utils import parseaddr


@dataclass
class HeaderFinding:
    has_headers: bool
    from_display_name: str = ""
    from_address: str = ""
    reply_to_address: str = ""
    flags: list[str] = field(default_factory=list)
    risk_points: int = 0


def _looks_like_headers(text: str) -> bool:
    return bool(re.search(r"^(From|Subject|Reply-To|Return-Path):", text, re.MULTILINE))


def analyze_headers(raw_text: str) -> HeaderFinding:
    if not _looks_like_headers(raw_text):
        return HeaderFinding(has_headers=False)

    msg = message_from_string(raw_text)
    from_display, from_addr = parseaddr(msg.get("From", ""))
    _, reply_to_addr = parseaddr(msg.get("Reply-To", ""))

    finding = HeaderFinding(
        has_headers=True,
        from_display_name=from_display,
        from_address=from_addr,
        reply_to_address=reply_to_addr,
    )

    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
    reply_domain = reply_to_addr.split("@")[-1].lower() if "@" in reply_to_addr else ""

    # 1. Reply-To domain differs from From domain
    if reply_to_addr and reply_domain and from_domain and reply_domain != from_domain:
        finding.flags.append(
            f"Reply-To domain ('{reply_domain}') differs from From domain ('{from_domain}')"
        )
        finding.risk_points += 4

    # 2. Display name claims a well-known brand but address domain doesn't match
    known_brands = ["paypal", "microsoft", "apple", "amazon", "bank", "google", "irs", "netflix"]
    display_lower = from_display.lower()
    for brand in known_brands:
        if brand in display_lower and brand not in from_domain:
            finding.flags.append(
                f"Display name references '{brand}' but sending domain is '{from_domain}'"
            )
            finding.risk_points += 5
            break

    # 3. Free-mail domain sending on behalf of a "company"
    free_mail = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com"}
    if from_domain in free_mail and any(b in display_lower for b in known_brands):
        finding.flags.append("Claims to be a company but sent from a free consumer email domain")
        finding.risk_points += 3

    return finding
