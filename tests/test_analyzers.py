from backend.services.url_analyzer import analyze_url
from backend.services.sender_analyzer import analyze_sender
from backend.services.content_analyzer import analyze_email_content
from backend.services.attachment_analyzer import analyze_attachment
from backend.services.risk_engine import calculate_phishing_score

def test_raw_ip_url():
    result = analyze_url("http://198.51.100.10/verify-account")
    assert result["has_ip"] is True
    assert result["risk_score"] >= 20

def test_https_is_not_automatically_safe():
    result = analyze_url("https://example.org/verify")
    assert result["https"] is True
    assert result["risk_score"] > 0

def test_suspicious_sender_pattern():
    result = analyze_sender("user123456@example.org")
    assert "sender_risk_score" in result

def test_content_credential_request():
    result = analyze_email_content(
        "URGENT: Verify account",
        "Verify your password immediately."
    )
    assert result["contains_password_request"] is True

def test_executable_attachment():
    result = analyze_attachment("invoice.pdf.exe")
    assert result["risk_score"] >= 25
    assert result["findings"]

def test_risk_engine_caps_score():
    sender = {"sender_risk_score": 50}
    content = {
        "counts": {
            "urgency": 2, "credential_request": 2,
            "fear": 2, "financial_pressure": 2
        },
        "generic_greeting": True
    }
    urls = [{"risk_score": 100, "findings": ["raw IP"]}]
    attachment = {"risk_score": 100, "findings": ["exe"]}
    result = calculate_phishing_score(sender, content, urls, attachment)
    assert 0 <= result["risk_score"] <= 100
