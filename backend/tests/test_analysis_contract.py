from fastapi.testclient import TestClient
from app.main import app
from app.schemas.analysis import RiskCategory

client = TestClient(app)


def test_analysis_endpoint_success_with_findings():
    payload = {
        "sender_email": "security@paypa1.com",
        "subject": "Urgent: Account Verification",
        "body": "Dear customer, please verify your credentials within 24 hours: https://paypal.com.attacker.com/login",
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["risk_score"] is not None
    assert 0 <= data["risk_score"] <= 100
    assert data["risk_category"] in (RiskCategory.SUSPICIOUS.value, RiskCategory.HIGH_RISK.value)
    assert len(data["findings"]) > 0
    assert len(data["recommendations"]) > 0


def test_analysis_endpoint_inconclusive_on_empty_content():
    payload = {
        "sender_email": "user@example.com",
        "subject": "",
        "body": "hi",
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["risk_score"] is None
    assert data["risk_category"] == RiskCategory.INCONCLUSIVE.value
    assert "Insufficient content" in data["summary"]


def test_analysis_endpoint_invalid_email_syntax():
    payload = {
        "sender_email": "not-an-email",
        "subject": "Hello",
        "body": "Test body",
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 422


def test_analysis_endpoint_clean_email_scores_low_risk():
    payload = {
        "sender_email": "colleague@company.com",
        "subject": "Sprint Review Notes",
        "body": "Hi team, please find attached our sprint review agenda for tomorrow morning.",
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["risk_score"] == 0
    assert data["risk_category"] == RiskCategory.LOW_RISK.value
    assert "does not prove an email is completely safe" in data["summary"]


def test_analysis_endpoint_payload_too_large_413():
    huge_body = "x" * (255 * 1024)
    payload = {
        "sender_email": "user@example.com",
        "subject": "Huge Email",
        "body": huge_body,
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 413