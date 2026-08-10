# 🛡️ AI Phishing Email Analyzer

![CI](https://img.shields.io/badge/CI-passing-brightgreen)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
![Streamlit](https://img.shields.io/badge/UI-Streamlit-ff4b4b)

A one-machine, portfolio-ready security tool that analyzes a pasted email and
produces a **Low / Medium / High** phishing risk report — combining
rule-based detection (URL heuristics, phrase analysis, header inconsistency
checks) with an **optional local LLM explanation** (via [Ollama](https://ollama.com)).

Built to match the following architecture:

```
Fake Suspicious Email (sample) --input--> Web UI (Streamlit) --analyze--> Python Analyzer --output--> Risk Report (Low/Medium/High)
                                                                                │
                                                        ┌───────────────────────┼───────────────────────┐
                                                        ▼                       ▼                       ▼
                                                 URL Extraction         Keyword Detection          Risk Scoring
```

## ✨ Features

- **URL heuristics** — flags raw IP links, URL shorteners, `@`-symbol tricks,
  punycode/homograph domains, high-abuse TLDs, non-standard ports, and
  brand-name typosquatting / subdomain stuffing (e.g. `paypal-secure-login.xyz`,
  `paypal.com.verify-secure.xyz`).
- **Keyword / phrase detection** — a weighted, data-driven library
  (`data/keywords.json`) covering urgency cues, credential-harvesting
  language, financial lures, and authority impersonation. Fully extensible
  without touching code.
- **Header spoofing checks** — if a raw email (with `From:`/`Reply-To:`
  headers) is pasted, detects Reply-To/From domain mismatches and
  display-name brand impersonation. Gracefully skipped if only a plain
  body is pasted.
- **Composite risk scoring** — combines all signals into a single score and
  Low/Medium/High verdict with a transparent, human-readable breakdown.
- **Optional local AI explanation** — if [Ollama](https://ollama.com) is
  running locally, the app asks a local model (e.g. `llama3`) to explain the
  verdict in plain English. 100% optional; the tool works standalone
  without it, and **no data ever leaves your machine**.
- **Sample email library** — three fake phishing samples and one legitimate
  control email included for instant demoing.
- **Tested core logic** — `tests/test_analyzer.py` covers URL, keyword,
  header, and end-to-end pipeline behavior.

## 🧱 Tech Stack

| Layer            | Technology                          |
|-------------------|--------------------------------------|
| UI                | Streamlit                           |
| Detection logic   | Pure Python (stdlib: `re`, `urllib`, `email`) |
| Optional AI       | Ollama (local LLM, e.g. Llama 3)    |
| Tests             | pytest                              |

No API keys, no cloud dependency, no internet connection required for the
core detector — everything runs on one machine.

## 📁 Project Structure

```
phishing-analyzer/
├── app.py                        # Streamlit UI
├── src/
│   ├── analyzer/
│   │   ├── url_extractor.py      # URL extraction + heuristic scoring
│   │   ├── keyword_detector.py   # Weighted phrase matching
│   │   ├── email_parser.py       # Header spoofing checks
│   │   └── risk_scorer.py        # Combines everything into a verdict
│   └── ai/
│       └── ollama_explainer.py   # Optional local-LLM explanation
├── data/
│   ├── keywords.json             # Editable phishing phrase library
│   └── sample_emails/            # 3 fake phishing + 1 legit sample
├── tests/
│   └── test_analyzer.py
├── requirements.txt
└── .streamlit/config.toml        # Dark theme
```

## 🚀 Getting Started

### 1. Install dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Run the app
```bash
streamlit run app.py
```
Open the URL Streamlit prints (typically `http://localhost:8501`).

### 3. (Optional) Enable local AI explanations
```bash
# Install Ollama: https://ollama.com/download
ollama pull llama3
ollama serve
```
Then check "Explain result with local AI (Ollama)" in the app sidebar.

### 4. Run tests
```bash
pytest tests/ -v
```

### 5. (Optional) Run with Docker
```bash
docker compose up --build
```
This starts the app on `http://localhost:8501` plus an Ollama service for
AI explanations. Don't want the AI feature? Comment out the `ollama`
service in `docker-compose.yml` and remove the `depends_on` line — the app
runs fine standalone.

## 🧪 How to Demo It

1. Launch the app.
2. In the sidebar, pick a sample from **"Load a sample"** (e.g. *Bank Account Suspended*).
3. Click **Analyze Email**.
4. Review the risk badge, then explore the **URLs**, **Keywords**, and
   **Headers** tabs to see exactly which signals drove the score.
5. Try the **Legitimate Newsletter** sample to confirm the tool correctly
   scores clean email as Low risk (no false positives on ordinary mail).

## ⚙️ How Scoring Works

Each detector contributes weighted points:

| Signal                                   | Points |
|-------------------------------------------|--------|
| Credential-harvesting phrase               | 5      |
| Financial lure phrase                      | 4      |
| Urgency phrase                             | 3      |
| Authority impersonation phrase             | 3      |
| Generic red flag phrase                    | 2      |
| URL uses raw IP address                    | 4      |
| URL uses `@` trick                         | 5      |
| URL brand mismatch / typosquat             | 5      |
| URL shortener                              | 3      |
| Suspicious TLD                             | 3      |
| Punycode domain                            | 4      |
| Reply-To ≠ From domain                     | 4      |
| Display name impersonates a brand          | 5      |

Total score → **Low** (≤6) / **Medium** (7–15) / **High** (17+). Thresholds
are tunable in `src/analyzer/risk_scorer.py`.

## 🔒 Ethical Note

This project is built for **security-awareness education and portfolio
demonstration**. It only analyzes text a user pastes in — it does not send,
receive, or act on real email, and includes no capability to send phishing
emails, harvest credentials, or evade detection. The included "phishing"
samples are clearly-labeled fictional examples for testing the detector.

## 🛣️ Possible Extensions

- Public Suffix List integration for fully accurate registrable-domain parsing
- Attachment/file-type risk checks (`.exe`, `.scr`, macro-enabled Office docs)
- SPF/DKIM/DMARC header validation when full raw headers are available
- Browser extension front-end
- Export risk report as PDF/CSV for SOC ticketing

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, linting, and testing
instructions.

## 📄 License

MIT — see [LICENSE](LICENSE).
