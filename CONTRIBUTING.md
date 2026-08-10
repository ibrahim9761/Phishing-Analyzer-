# Contributing

Thanks for considering a contribution! This is a portfolio/educational
project, but PRs and issues are welcome.

## Setup

```bash
git clone <your-fork-url>
cd phishing-analyzer
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install pytest ruff
```

## Before submitting a PR

```bash
ruff check src/ app.py tests/
pytest tests/ -v
```

Both must pass — this mirrors what CI runs on every push.

## Adding new detection heuristics

- **New suspicious phrases**: add them to `data/keywords.json` under the
  right category (or add a new category). No code changes needed.
- **New URL heuristics**: add a check inside `analyze_url()` in
  `src/analyzer/url_extractor.py`, append to `finding.flags`, and add
  `finding.risk_points`.
- **New header checks**: extend `analyze_headers()` in
  `src/analyzer/email_parser.py`.

Please add a corresponding test in `tests/test_analyzer.py` for any new
heuristic.

## Reporting issues

Open a GitHub issue with the email sample (redact any real personal data)
and the risk report you got, plus what you expected instead.
