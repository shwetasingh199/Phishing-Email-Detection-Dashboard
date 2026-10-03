
from fastapi.testclient import TestClient

from backend.app import app


client = TestClient(app)


def get_auth_headers():
    """
    Register/login a test user and return
    an Authorization header.
    """

    username = "apitestuser"
    password = "StrongPassword123!"

    register_response = client.post(
        "/api/auth/register",
        json={
            "username": username,
            "password": password,
        },
    )

    assert register_response.status_code in (
        200,
        409,
    )

    login_response = client.post(
        "/api/auth/login",
        json={
            "username": username,
            "password": password,
        },
    )

    assert login_response.status_code == 200

    token = login_response.json()[
        "access_token"
    ]

    return {
        "Authorization": (
            f"Bearer {token}"
        )
    }


def test_health():
    response = client.get(
        "/api/health"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "ok"


def test_analyze():
    response = client.post(
        "/api/analyze",
        headers=get_auth_headers(),
        json={
            "sender": (
                "security-alert"
                "@account-check.invalid.test"
            ),
            "subject": (
                "URGENT: Verify Your Account"
            ),
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


def test_validation():
    response = client.post(
        "/api/analyze",
        headers=get_auth_headers(),
        json={
            "sender": "",
            "subject": "",
            "body": "",
        },
    )

    assert response.status_code in (
        400,
        422,
    )


def test_unauthenticated_analysis():
    response = client.post(
        "/api/analyze",
        json={
            "sender": "test@example.com",
            "subject": "Test",
            "body": "Test message",
        },
    )

    assert response.status_code == 401


def test_protected_history():
    response = client.get(
        "/api/analyses"
    )

    assert response.status_code == 401


def test_protected_dashboard():
    response = client.get(
        "/api/dashboard/stats"
    )

    assert response.status_code == 401
