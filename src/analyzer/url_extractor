"""
url_extractor.py
-----------------
Extracts URLs from raw email text and applies a set of heuristics commonly
used in phishing triage to flag suspicious links.

Heuristics implemented (each is a well-known, publicly documented phishing
indicator used in security-awareness training, not an attack technique):
  - IP address used instead of a domain name
  - Known URL-shortener domains (obscure the real destination)
  - '@' symbol in the URL (browser ignores everything before it -> spoofing)
  - Excessive subdomain depth (brand-name stuffing, e.g. paypal.com.evil.io)
  - Suspicious / high-abuse TLDs
  - Brand keyword present in the URL but NOT in the actual registrable domain
  - Punycode / IDN homograph indicators (xn--)
  - Non-standard ports
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

URL_REGEX = re.compile(
    r"""(?xi)
    \b
    (?:https?://|www\.)
    [^\s<>\"'\)\]]+
    """
)

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly", "s.id",
}

SUSPICIOUS_TLDS = {
    ".zip", ".top", ".xyz", ".click", ".country", ".gq", ".tk", ".ml",
    ".cf", ".work", ".fit", ".loan", ".men", ".date", ".stream", ".icu",
}

WELL_KNOWN_BRANDS = {
    "paypal", "microsoft", "apple", "google", "amazon", "netflix",
    "facebook", "instagram", "bankofamerica", "chase", "wellsfargo",
    "irs", "dhl", "fedex", "usps", "linkedin", "office365", "outlook",
}

IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


@dataclass
class UrlFinding:
    url: str
    domain: str
    flags: list[str] = field(default_factory=list)
    risk_points: int = 0


def extract_urls(text: str) -> list[str]:
    """Return a de-duplicated, order-preserved list of URLs found in text."""
    found = URL_REGEX.findall(text)
    cleaned = []
    seen = set()
    for u in found:
        u = u.rstrip(".,;:!?")
        if u.startswith("www."):
            u = "http://" + u
        if u not in seen:
            seen.add(u)
            cleaned.append(u)
    return cleaned


def _registrable_domain(netloc: str) -> str:
    """Very lightweight best-effort extraction of the 'real' domain
    (not a full public-suffix-list implementation, but sufficient for
    portfolio / educational purposes)."""
    netloc = netloc.split("@")[-1]  # drop userinfo if present
    netloc = netloc.split(":")[0]   # drop port
    parts = netloc.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return netloc


def analyze_url(raw_url: str) -> UrlFinding:
    parsed = urlparse(raw_url)
    netloc = parsed.netloc or parsed.path.split("/")[0]
    finding = UrlFinding(url=raw_url, domain=netloc)

    host_only = netloc.split("@")[-1].split(":")[0]

    # 1. IP address instead of domain
    if IP_REGEX.match(host_only):
        finding.flags.append("Uses a raw IP address instead of a domain name")
        finding.risk_points += 4

    # 2. URL shortener
    if host_only.lower() in SHORTENER_DOMAINS:
        finding.flags.append(f"Uses a URL shortener ({host_only}) that hides the true destination")
        finding.risk_points += 3

    # 3. '@' symbol trick
    if "@" in netloc:
        finding.flags.append("Contains an '@' symbol, which can hide the real destination host")
        finding.risk_points += 5

    # 4. Excessive subdomains
    label_count = host_only.count(".")
    if label_count >= 3:
        finding.flags.append("Unusually deep subdomain structure (possible brand stuffing)")
        finding.risk_points += 2

    # 5. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if host_only.lower().endswith(tld):
            finding.flags.append(f"Uses a high-abuse top-level domain ({tld})")
            finding.risk_points += 3
            break

    # 6. Brand keyword present but the registrable domain isn't genuinely that brand's.
    #    Catches two common lookalike patterns:
    #      a) subdomain stuffing:   paypal.com.verify-secure.xyz
    #      b) typosquat/hyphenated: paypal-secure-login.xyz
    reg_domain = _registrable_domain(host_only).lower()
    reg_base_label = reg_domain.split(".")[0]
    full_url_lower = raw_url.lower()
    for brand in WELL_KNOWN_BRANDS:
        if brand not in full_url_lower:
            continue
        if reg_base_label == brand:
            # Genuinely the brand's own registrable domain (e.g. paypal.com) - not flagged.
            continue
        if brand in reg_domain:
            finding.flags.append(
                f"Domain '{reg_domain}' combines brand '{brand}' with other words "
                "(possible typosquat / lookalike domain)"
            )
        else:
            finding.flags.append(
                f"Mentions brand '{brand}' but the actual domain is '{reg_domain}' (mismatch)"
            )
        finding.risk_points += 5
        break

    # 7. Punycode / IDN homograph
    if "xn--" in host_only.lower():
        finding.flags.append("Uses punycode encoding, often used for homograph/lookalike domains")
        finding.risk_points += 4

    # 8. Non-standard port
    if parsed.port and parsed.port not in (80, 443):
        finding.flags.append(f"Connects on a non-standard port ({parsed.port})")
        finding.risk_points += 2

    return finding


def analyze_urls(text: str) -> list[UrlFinding]:
    return [analyze_url(u) for u in extract_urls(text)]
