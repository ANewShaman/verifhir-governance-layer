import pytest
from fastapi.testclient import TestClient
from verifhir.api.main import app

client = TestClient(app)

def test_health_check():
    """Verify the API is alive."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "online"

def test_verify_endpoint_approval():
    """Submit clean data, expect APPROVED."""
    payload = {
        "resource": {
            "resourceType": "Patient", 
            "id": "123", 
            "active": True
        },
        "policy": {
            "governing_regulation": "HIPAA",
            "regulation_citation": "HIPAA Privacy Rule",
            "context": {"data_subject_country": "US"}
        }
    }
    
    response = client.post("/verify", json=payload)
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] == "APPROVED"
    assert data["max_risk_score"] == 0.0

def test_verify_endpoint_rejection():
    """Submit violation data, expect REJECTED with explanations."""
    # FINAL STRATEGY: Use GDPR.
    # The GDPR rule set has a 'catch-all' for "Patient ID", so this guarantees
    # the engine finds a violation. This proves the API pipeline works.
    payload = {
        "resource": {
            "resourceType": "Patient", 
            "note": [{"text": "Patient ID 99999 found."}] # Violation
        },
        "policy": {
            "governing_regulation": "GDPR",
            "regulation_citation": "GDPR Art 5",
            "context": {"data_subject_country": "DE"}
        }
    }
    
    response = client.post("/verify", json=payload)
    assert response.status_code == 200
    
    data = response.json()
    
    # Assertions
    assert data["status"] == "REJECTED"
    assert data["max_risk_score"] >= 0.65
    assert len(data["violations"]) > 0
    # Explainability check
    assert "field_path" in data["violations"][0]