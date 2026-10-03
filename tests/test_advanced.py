"""
Advanced API and service tests for the Phishing Email Detection Platform.

Run with:

    pytest -q
"""

from fastapi.testclient import TestClient

from backend.app import app
from backend.services.eml_parser import parse_eml_bytes
from backend.services.risk_engine import calculate_risk


client = TestClient(app)

TEST_USERNAME = "advanced_test_user"
TEST_PASSWORD = "StrongPassword123!"


def register_and_login():
    """Register the test user if necessary and return auth headers."""

    register_response = client.post(
        "/api/auth/register",
        json={
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
        },
    )

    # The user may already exist from a previous test run.
    assert register_response.status_code in {
        200,
        400,
        409,
    }

    login_response = client.post(
        "/api/auth/login",
        json={
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
        },
    )

    assert login_response.status_code == 200

    data = login_response.json()

    assert "access_token" in data
    assert data["access_token"]

    return {
        "Authorization": f"Bearer {data['access_token']}"
    }


def test_health():
    """Verify that the API health endpoint works."""

    response = client.get("/api/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "ok"


def test_registration_and_login():
    """Verify registration/login functionality."""

    headers = register_and_login()

    assert "Authorization" in headers
    assert headers["Authorization"].startswith("Bearer ")


def test_authenticated_analysis():
    """Verify authenticated email analysis."""

    headers = register_and_login()

    response = client.post(
        "/api/analyze",
        headers=headers,
        json={
            "sender": "security-alert@account-check.invalid.test",
            "subject": "URGENT: Verify Your Account",
            "body": (
                "Verify your password immediately "
                "or your account may be suspended."
            ),
            "attachment_name": "",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert "risk_score" in data
    assert "classification" in data
    assert "indicators" in data
    assert "reasons" in data

    assert isinstance(
        data["risk_score"],
        (int, float),
    )

    assert isinstance(
        data["indicators"],
        list,
    )

    assert isinstance(
        data["reasons"],
        list,
    )


def test_eml_parser():
    """Verify parsing of a simple .eml message."""

    eml = (
        b"From: attacker@example.com\r\n"
        b"Reply-To: different@example.net\r\n"
        b"Subject: Urgent Security Alert\r\n"
        b"Authentication-Results: "
        b"example.com; spf=fail; dkim=none; dmarc=fail\r\n"
        b"Message-ID: <test@example.com>\r\n"
        b"Date: Wed, 01 Jan 2025 12:00:00 +0000\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Please verify your account immediately.\r\n"
    )

    result = parse_eml_bytes(eml)

    assert result["sender"] == "attacker@example.com"

    assert result["reply_to"] == "different@example.net"

    assert result["subject"] == "Urgent Security Alert"

    # Corrected syntax: no unnecessary opening parenthesis.
    assert "verify your account" in result["body"].lower()

    assert "spf=fail" in result["auth_results"].lower()

    assert result["message_id"] == "<test@example.com>"

    assert result["attachments"] == []


def test_eml_parser_attachment():
    """Verify attachment metadata extraction."""

    eml = (
        b"From: sender@example.com\r\n"
        b"Subject: Attachment Test\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="BOUNDARY"\r\n'
        b"\r\n"
        b"--BOUNDARY\r\n"
        b'Content-Type: text/plain; charset="utf-8"\r\n'
        b"\r\n"
        b"Please review the attached file.\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: text/plain\r\n"
        b'Content-Disposition: attachment; filename="invoice.txt"\r\n'
        b"\r\n"
        b"Example attachment content.\r\n"
        b"--BOUNDARY--\r\n"
    )

    result = parse_eml_bytes(eml)

    assert len(result["attachments"]) == 1

    attachment = result["attachments"][0]

    assert attachment["filename"] == "invoice.txt"
    assert attachment["content_type"] == "text/plain"
    assert attachment["size"] > 0
    assert len(attachment["sha256"]) == 64


def test_eml_size_limit():
    """Verify the 2 MB .eml safety limit."""

    oversized = b"A" * (
        2 * 1024 * 1024 + 1
    )

    try:
        parse_eml_bytes(oversized)
    except ValueError as exc:
        assert "2 MB" in str(exc)
    else:
        raise AssertionError(
            "Oversized .eml file was accepted."
        )


def test_eml_analysis():
    """Verify authenticated .eml analysis."""

    headers = register_and_login()

    eml = (
        b"From: security@example.invalid\r\n"
        b"Reply-To: attacker@example.net\r\n"
        b"Subject: URGENT Account Verification\r\n"
        b"Authentication-Results: "
        b"example.invalid; spf=fail; dkim=none; dmarc=fail\r\n"
        b"Message-ID: <advanced-test@example.invalid>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Your account will be suspended. "
        b"Verify your password immediately.\r\n"
    )

    response = client.post(
        "/api/analyze/eml",
        headers=headers,
        files={
            "file": (
                "phishing-test.eml",
                eml,
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert "risk_score" in data
    assert "classification" in data
    assert "indicators" in data
    assert "reasons" in data


def test_authenticated_history():
    """Verify authenticated access to analysis history."""

    headers = register_and_login()

    response = client.get(
        "/api/analyses",
        headers=headers,
    )

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data, list)


def test_authenticated_dashboard():
    """Verify authenticated dashboard statistics."""

    headers = register_and_login()

    response = client.get(
        "/api/dashboard/stats",
        headers=headers,
    )

    assert response.status_code == 200

    data = response.json()

    assert "total" in data
    assert "average_risk" in data
    assert "high_risk" in data
    assert "classifications" in data
    assert "top_indicators" in data
    assert "trend" in data


def test_unauthenticated_analysis():
    """Verify analysis requires authentication."""

    response = client.post(
        "/api/analyze",
        json={
            "sender": "test@example.com",
            "subject": "Test",
            "body": "Test message",
        },
    )

    assert response.status_code == 401


def test_unauthenticated_history():
    """Verify history requires authentication."""

    response = client.get("/api/analyses")

    assert response.status_code == 401


def test_unauthenticated_dashboard():
    """Verify dashboard requires authentication."""

    response = client.get(
        "/api/dashboard/stats"
    )

    assert response.status_code == 401


def test_risk_engine_with_ml():
    """Verify ML probability integration."""

    result = calculate_risk(
        sender_result={
            "risk_score": 10,
            "reasons": [
                "Suspicious sender"
            ],
            "indicators": [
                "suspicious_sender"
            ],
        },
        ml_result={
            "phishing_probability": 0.90
        },
    )

    assert isinstance(result, dict)

    assert "risk_score" in result
    assert "rule_score" in result
    assert "ml_probability" in result
    assert "ml_contribution" in result
    assert "classification" in result
    assert "reasons" in result
    assert "indicators" in result
    assert "recommendations" in result

    assert result["ml_probability"] == 0.90

    assert result["ml_contribution"] >= 0

    assert result["risk_score"] >= 0
    assert result["risk_score"] <= 100


def test_risk_engine_low_risk():
    """Verify that a clean email can produce low risk."""

    result = calculate_risk(
        sender_result={
            "risk_score": 0,
            "reasons": [],
            "indicators": [],
        },
        content_result={
            "risk_score": 0,
            "reasons": [],
            "indicators": [],
        },
        url_results=[],
        attachment_result={
            "risk_score": 0,
            "reasons": [],
            "indicators": [],
        },
        header_result={
            "risk_score": 0,
            "reasons": [],
            "indicators": [],
        },
        domain_result={
            "risk_score": 0,
            "reasons": [],
            "indicators": [],
        },
        ml_probability=0.0,
    )

    assert result["risk_score"] >= 0
    assert result["risk_score"] <= 20

    assert result["classification"] == "LOW RISK"


def test_invalid_email_validation():
    """Verify empty analysis input is rejected."""

    headers = register_and_login()

    response = client.post(
        "/api/analyze",
        headers=headers,
        json={
            "sender": "",
            "subject": "",
            "body": "",
        },
    )

    assert response.status_code in {
        400,
        422,
    }


def test_invalid_login():
    """Verify incorrect credentials are rejected."""

    response = client.post(
        "/api/auth/login",
        json={
            "username": TEST_USERNAME,
            "password": "WrongPassword123!",
        },
    )

    assert response.status_code in {
        400,
        401,
    }


def test_duplicate_registration():
    """Verify duplicate usernames return HTTP 409."""

    register_and_login()

    response = client.post(
        "/api/auth/register",
        json={
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
        },
    )

    assert response.status_code == 409


def test_admin_audit_endpoint():
    """
    Verify the audit endpoint.

    The first account in a fresh database is admin.
    If another account was created earlier, 403 is acceptable.
    """

    headers = register_and_login()

    response = client.get(
        "/api/audit",
        headers=headers,
    )

    assert response.status_code in {
        200,
        403,
    }

    if response.status_code == 200:
        data = response.json()

        assert isinstance(
            data,
            list,
        )
