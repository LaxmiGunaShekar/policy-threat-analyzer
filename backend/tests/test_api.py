from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_analyze_endpoint_empty():
    response = client.post("/analyze", json={"text": ""})
    assert response.status_code == 200
    data = response.json()
    assert data["total_matches"] == 0
    assert data["overall_risk_score"] == 0
    assert data["risk_level"] == "safe"

def test_analyze_endpoint_predatory():
    predatory_text = "We share your personal data with third-party advertisers. Automatic debit from your bank account. We track your continuous location."
    response = client.post("/analyze", json={"text": predatory_text})
    assert response.status_code == 200
    data = response.json()
    assert data["total_matches"] >= 2
    assert data["overall_risk_score"] > 0
    assert data["risk_level"] in ["caution", "dangerous"]
    
def test_analyze_endpoint_invalid_payload():
    response = client.post("/analyze", json={"wrong_key": "some text"})
    assert response.status_code == 422  # Unprocessable Entity
