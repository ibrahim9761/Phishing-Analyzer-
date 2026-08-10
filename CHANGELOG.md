# Changelog

All notable changes to this project are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-08-11

### Added
- Initial release: Streamlit UI for pasting and analyzing suspicious emails.
- URL heuristic engine: IP-address links, shorteners, `@`-symbol tricks,
  punycode, suspicious TLDs, non-standard ports, and brand
  typosquatting/subdomain-stuffing detection.
- Data-driven keyword detector (`data/keywords.json`) covering urgency,
  credential-harvesting, financial-lure, authority-impersonation, and
  generic red-flag phrase categories.
- Email header analysis (Reply-To/From mismatch, display-name brand
  impersonation, free-mail-domain-as-company detection).
- Composite Low/Medium/High risk scoring engine with transparent breakdown.
- Optional local AI explanation via Ollama, with Docker Compose networking
  support (`OLLAMA_HOST` env var) and graceful fallback when Ollama isn't
  running.
- Four sample emails (three phishing, one legitimate control) for instant
  demoing.
- Full unit test suite (`tests/test_analyzer.py`).
- Docker + Docker Compose deployment.
- GitHub Actions CI (lint + multi-version test matrix).
