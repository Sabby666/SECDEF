import pytest
from app.core.logging import censor_sensitive_data
from shared_contracts.schemas import HealthResponse


def test_log_censorship():
    raw_event = {
        "event": "user_login",
        "user_id": "usr_123",
        "password": "SuperSecretPassword123!",
        "session_token": "secret_token_abc_123",
        "normal_field": "public_data"
    }
    censored = censor_sensitive_data(None, None, raw_event.copy())
    
    assert censored["password"] == "[REDACTED]"
    assert censored["session_token"] == "[REDACTED]"
    assert censored["normal_field"] == "public_data"
    assert censored["user_id"] == "usr_123"


def test_shared_contracts_boundary():
    # Verify shared contracts contains only Pydantic schemas, no DB or logic
    response = HealthResponse(status="healthy", version="1.0.0")
    assert response.status == "healthy"
    assert not hasattr(response, "save")
    assert not hasattr(response, "execute")
