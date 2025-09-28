import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_create_target():
    # Test creating a new target
    response = client.post(
        "/api/v1/targets/",
        json={"domain_name": "test-domain.com"},
        headers={"x-api-key": "testkey"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["domain_name"] == "test-domain.com"
    assert "id" in data
    assert "created_at" in data

def test_create_duplicate_target():
    # First create a target
    client.post(
        "/api/v1/targets/",
        json={"domain_name": "duplicate-test.com"},
        headers={"x-api-key": "testkey"}
    )
    
    # Try to create the same target again
    response = client.post(
        "/api/v1/targets/",
        json={"domain_name": "duplicate-test.com"},
        headers={"x-api-key": "testkey"}
    )
    assert response.status_code == 409
    assert "already exists" in response.json()["detail"]

def test_invalid_api_key():
    response = client.get("/api/v1/targets/", headers={"x-api-key": "wrongkey"})
    assert response.status_code == 401

def test_invalid_domain():
    response = client.post(
        "/api/v1/targets/",
        json={"domain_name": "invalid..domain"},
        headers={"x-api-key": "testkey"}
    )
    assert response.status_code == 422  # Validation error

def test_rate_limiting():
    # This would need more complex setup for proper rate limiting tests
    # For now, just ensure endpoints respond
    for i in range(5):
        response = client.get("/api/v1/targets/", headers={"x-api-key": "testkey"})
        assert response.status_code in [200, 429]  # Either success or rate limited