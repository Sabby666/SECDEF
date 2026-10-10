import pytest
from unittest.mock import patch
from worker.runner import process_scan_job
from pydantic import ValidationError

@pytest.mark.asyncio
async def test_process_scan_job_valid_payload():
    payload = {
        "schema_version": "1.0",
        "event_id": "evt_123",
        "scan_id": "scan_123",
        "org_id": "org_456",
        "domain_id": "dom_789",
        "domain_name": "example.com",
        "job_nonce": "nonce_123"
    }
    with patch("worker.runner.resolve_and_validate_target", return_value=["93.184.216.34"]):
        with patch("worker.runner.scan_target_ports", return_value=[]):
            result = await process_scan_job({}, payload)
            assert result["status"] == "completed"
            assert result["scan_id"] == "scan_123"
            assert result["org_id"] == "org_456"

@pytest.mark.asyncio
async def test_process_scan_job_missing_domain():
    payload = {
        "schema_version": "1.0",
        "event_id": "evt_123",
        "scan_id": "scan_123",
        "org_id": "org_456",
        "domain_id": "dom_789",
        "domain_name": "",
        "job_nonce": "nonce_123"
    }
    result = await process_scan_job({}, payload)
    assert result["status"] == "failed"
    assert "Invalid or empty target domain" in result["error_message"]

@pytest.mark.asyncio
async def test_process_scan_job_invalid_schema():
    payload = {
        "scan_id": "scan_123",
        # missing required fields
    }
    with pytest.raises(ValidationError):
        await process_scan_job({}, payload)
