from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_ml_health_endpoint_contract():
    response = client.get("/api/v1/health/ml")
    assert response.status_code == 200
    data = response.json()
    assert "available" in data
    assert isinstance(data["available"], bool)
    assert "status" in data
    assert isinstance(data["status"], str)
    if data["available"]:
        assert data["threshold"] is not None
        assert 0.0 < data["threshold"] < 1.0


def test_system_health_remains_unchanged():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}