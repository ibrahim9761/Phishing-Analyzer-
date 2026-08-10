import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.analyzer.email_parser import analyze_headers
from src.analyzer.keyword_detector import detect_keywords
from src.analyzer.risk_scorer import analyze_email
from src.analyzer.url_extractor import analyze_url, extract_urls


def test_extract_urls_finds_http_and_www():
    text = "Visit http://example.com/a and also www.test.org/b now."
    urls = extract_urls(text)
    assert "http://example.com/a" in urls
    assert any("test.org" in u for u in urls)


def test_url_flags_ip_address():
    finding = analyze_url("http://192.168.1.5/login")
    assert finding.risk_points > 0
    assert any("IP address" in f for f in finding.flags)


def test_url_flags_shortener():
    finding = analyze_url("http://bit.ly/abcd123")
    assert any("shortener" in f.lower() for f in finding.flags)


def test_url_flags_brand_mismatch():
    finding = analyze_url("http://paypal-secure-login.xyz/verify")
    assert any("mismatch" in f.lower() or "brand" in f.lower() for f in finding.flags)


def test_keyword_detector_finds_urgency_terms():
    text = "Your account will be suspended, act now to avoid closure."
    matches = detect_keywords(text)
    categories = {m.category for m in matches}
    assert "urgency" in categories


def test_keyword_detector_no_false_positive_on_clean_text():
    text = "Hi Sarah, the meeting notes are attached. Thanks, John."
    matches = detect_keywords(text)
    assert len(matches) == 0


def test_header_analysis_detects_reply_to_mismatch():
    raw = (
        "From: \"PayPal Support\" <support@paypal.com>\n"
        "Reply-To: attacker@totally-different.biz\n"
        "Subject: Test\n\n"
        "body"
    )
    finding = analyze_headers(raw)
    assert finding.has_headers is True
    assert finding.risk_points > 0


def test_header_analysis_skips_when_no_headers_present():
    finding = analyze_headers("Just a plain body with no headers at all.")
    assert finding.has_headers is False


def test_full_pipeline_flags_high_risk_phishing_sample():
    sample = (
        "From: \"Bank of America Security\" <alerts@bofa-secure-verify.top>\n"
        "Reply-To: support@totally-different.xyz\n"
        "Subject: URGENT: verify your account\n\n"
        "Dear customer, your account will be suspended. Act now and click "
        "here to verify your account: http://192.168.1.20/verify"
    )
    report = analyze_email(sample)
    assert report.verdict in ("Medium", "High")
    assert report.score > 6


def test_full_pipeline_low_risk_on_clean_email():
    sample = (
        "From: \"Sarah Chen\" <sarah.chen@acmecorp.com>\n"
        "Subject: Meeting notes\n\n"
        "Hi team, notes from today's sync are attached. Thanks, Sarah."
    )
    report = analyze_email(sample)
    assert report.verdict == "Low"
