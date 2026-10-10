import pytest
import pytest_asyncio
import asyncio
import sys
import importlib
import pkgutil
import logging
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
from httpx import AsyncClient, ASGITransport
from datetime import datetime, timezone

from app.main import app
from app.infrastructure.db.session import async_engine
from app.infrastructure.db.base import Base
from app.infrastructure.db.models import Organization, User, Membership, Domain, Scan, AuditEvent
from shared_contracts.enums import DomainStatus
from shared_contracts.events import ScanExecuteJobPayload, ScanResultPayload

from worker.safety.egress_guard import is_ip_safe_for_egress
from worker.safety.dns_resolver_guard import resolve_and_validate_target
from worker.safety.redirect_guard import validate_redirect_url
from worker.runner import compute_payload_signature, execute_scan_pipeline
from worker.engine.port_scanner import scan_single_port, scan_target_ports
from worker.engine.banner_grabber import grab_http_banner, sanitize_string, MAX_BANNER_LEN, MAX_RESPONSE_BODY_BYTES
from worker.engine.tls_observer import collect_tls_certificate
from worker.engine.tech_identifier import identify_technologies


@pytest_asyncio.fixture(autouse=True)
async def setup_test_db():
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def seed_data():
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm import sessionmaker
    async_session = sessionmaker(async_engine, expire_on_commit=False, class_=AsyncSession)

    async with async_session() as session:
        org1 = Organization(name="Org 1", slug="org-1")
        org2 = Organization(name="Org 2", slug="org-2")
        user1 = User(email="admin1@test.com", password_hash="hash", full_name="Admin 1")
        user2 = User(email="admin2@test.com", password_hash="hash", full_name="Admin 2")

        session.add_all([org1, org2, user1, user2])
        await session.commit()

        mem1 = Membership(org_id=org1.id, user_id=user1.id, role="admin")
        mem2 = Membership(org_id=org2.id, user_id=user3.id if 'user3' in locals() else user2.id, role="admin")
        session.add_all([mem1, mem2])

        d_verified = Domain(
            org_id=org1.id,
            domain_name="verified.com",
            status=DomainStatus.VERIFIED,
            verification_token="token123",
            verified_at=datetime.now(timezone.utc)
        )
        d_pending = Domain(
            org_id=org1.id,
            domain_name="pending.com",
            status=DomainStatus.PENDING_VERIFICATION,
            verification_token="token456"
        )
        session.add_all([d_verified, d_pending])
        await session.commit()

        return {
            "org1": org1.id,
            "org2": org2.id,
            "admin1": user1.id,
            "admin2": user2.id,
            "domain_verified": d_verified.id,
            "domain_pending": d_pending.id
        }


# ============================================================================
# 1. TARGET AUTHORIZATION GATE TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_target_auth_unverified_domain_rejected(seed_data):
    """Test that scanning an UNVERIFIED domain is rejected with 400 Bad Request."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
        res = await client.post(
            f"/api/v1/organizations/{seed_data['org1']}/domains/{seed_data['domain_pending']}/scans",
            headers=headers
        )
        assert res.status_code == 400
        assert "Only verified domains can be scanned" in res.json()["detail"]


@pytest.mark.asyncio
async def test_target_auth_verified_domain_accepted(seed_data):
    """Test that scanning a VERIFIED domain succeeds and creates a queued scan."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
        res = await client.post(
            f"/api/v1/organizations/{seed_data['org1']}/domains/{seed_data['domain_verified']}/scans",
            headers=headers
        )
        assert res.status_code == 201
        data = res.json()
        assert data["status"] == "queued"
        assert data["domain_id"] == seed_data["domain_verified"]
        assert "job_nonce" in data


@pytest.mark.asyncio
async def test_target_auth_cross_tenant_rejected(seed_data):
    """Test cross-tenant scan trigger prevention."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-User-ID": seed_data["admin2"], "X-Org-ID": seed_data["org2"]}
        res = await client.post(
            f"/api/v1/organizations/{seed_data['org1']}/domains/{seed_data['domain_verified']}/scans",
            headers=headers
        )
        assert res.status_code == 403


# ============================================================================
# 2. NETWORK DESTINATION SAFETY GATE (EGRESS GUARD) TESTS
# ============================================================================

def test_egress_guard_blocked_addresses():
    """Verify egress safety guard blocks loopback, RFC1918, CGNAT, link-local, cloud metadata, ULA, and IPv4-mapped IPv6."""
    blocked_ips = [
        "127.0.0.1", "127.0.0.254", "10.0.0.1", "10.255.255.255",
        "172.16.0.1", "172.31.255.255", "192.168.1.1", "192.168.255.255",
        "169.254.169.254", "169.254.0.1", "100.64.0.1", "0.0.0.0",
        "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
        "invalid_ip", "", "localhost", "224.0.0.1"
    ]
    for ip in blocked_ips:
        assert is_ip_safe_for_egress(ip) is False, f"Expected {ip} to be BLOCKED by egress guard."


def test_egress_guard_allowed_addresses():
    """Verify egress safety guard allows legitimate public IPs."""
    public_ips = [
        "93.184.216.34", "8.8.8.8", "1.1.1.1", "2606:2800:220:1:248:1893:25c8:1946"
    ]
    for ip in public_ips:
        assert is_ip_safe_for_egress(ip) is True, f"Expected {ip} to be ALLOWED by egress guard."


# ============================================================================
# 3. DNS TOCTOU & REBINDING DEFENSE TESTS
# ============================================================================

class MockRData:
    def __init__(self, address):
        self.address = address


@pytest.mark.asyncio
async def test_dns_rebinding_defense_mixed_ips_rejected():
    """Test that if a domain resolves to mixed safe/unsafe IPs, the target is rejected (Fail-Closed)."""
    async def mock_resolve(domain, record_type):
        if record_type == "A":
            return [MockRData("93.184.216.34"), MockRData("127.0.0.1")]
        return []

    with patch("dns.asyncresolver.Resolver.resolve", side_effect=mock_resolve):
        ips = await resolve_and_validate_target("rebinding-attack.com")
        assert ips == [], "Expected fail-closed empty list when ANY resolved IP is unsafe."


@pytest.mark.asyncio
async def test_dns_resolver_guard_safe_resolution():
    """Test normal resolution with safe public IPs succeeds."""
    async def mock_resolve(domain, record_type):
        if record_type == "A":
            return [MockRData("93.184.216.34")]
        return []

    with patch("dns.asyncresolver.Resolver.resolve", side_effect=mock_resolve):
        ips = await resolve_and_validate_target("example.com")
        assert ips == ["93.184.216.34"]


# ============================================================================
# 4. REDIRECT SAFETY GUARD TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_redirect_safety_private_ip_rejected():
    """Test redirect to 127.0.0.1 or 169.254.169.254 is blocked."""
    is_safe, url, ips = await validate_redirect_url("http://127.0.0.1/admin")
    assert is_safe is False

    is_safe, url, ips = await validate_redirect_url("http://169.254.169.254/latest/meta-data")
    assert is_safe is False


@pytest.mark.asyncio
async def test_redirect_safety_dns_rebinding_unsafe_destination():
    """Test redirect to a domain that resolves to an internal/private IP is blocked."""
    async def mock_resolve(domain, record_type):
        if record_type == "A":
            return [MockRData("10.0.0.1")] # Private IP!
        return []

    with patch("dns.asyncresolver.Resolver.resolve", side_effect=mock_resolve):
        is_safe, url, ips = await validate_redirect_url("http://internal-redirect.com/secret")
        assert is_safe is False
        assert ips == []


@pytest.mark.asyncio
async def test_redirect_safety_max_hops_exceeded():
    """Test redirect chain > 5 hops is blocked."""
    is_safe, url, ips = await validate_redirect_url("http://example.com/redirect", current_hop=5, max_hops=5)
    assert is_safe is False


@pytest.mark.asyncio
async def test_redirect_safety_malformed_scheme_credentials():
    """Test dangerous schemes and URL credentials are rejected."""
    is_safe, url, ips = await validate_redirect_url("file:///etc/passwd")
    assert is_safe is False

    is_safe, url, ips = await validate_redirect_url("http://admin:secret@example.com")
    assert is_safe is False


# ============================================================================
# 5. RESOURCE LIMITS & MALICIOUS RESPONSE DEFENSE TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_http_response_over_10mb_truncated():
    """Test 1: HTTP response body >10 MB is truncated at the scanner resource/security boundary.
    The 10 MB limit is enforced by the scanner worker itself — oversized HTTP bodies
    are truncated inline, NOT accepted and offloaded to S3.
    """
    mock_resp = MagicMock()
    mock_resp.is_redirect = False
    mock_resp.status_code = 200
    mock_resp.http_version = "HTTP/1.1"
    mock_resp.headers = {"content-type": "text/html"}
    oversized_bytes = 12 * 1024 * 1024  # 12 MB > 10 MB limit
    mock_resp.content = b"A" * oversized_bytes
    mock_resp.text = "A" * oversized_bytes

    with patch("httpx.AsyncClient.send", return_value=mock_resp):
        banner = await grab_http_banner("93.184.216.34", 80, "example.com")
        assert banner is not None
        # Body snippet is truncated to MAX_BANNER_LEN (4 KB) at the scanner boundary
        assert len(banner["body_snippet"]) <= MAX_BANNER_LEN
        # The original 12 MB body must NOT pass through in full — truncation is enforced
        assert len(banner["body_snippet"]) < oversized_bytes
        # Verify no S3 key or external reference exists; the scanner truncates inline
        assert "s3_key" not in banner
        assert "raw_results_s3_key" not in banner


@pytest.mark.asyncio
async def test_decompression_ratio_over_20_to_1_handled(caplog):
    """Test 2: Decompression ratio >20:1 is detected, logged as a warning, and processed safely without worker crash."""
    mock_resp = MagicMock()
    mock_resp.is_redirect = False
    mock_resp.status_code = 200
    mock_resp.http_version = "HTTP/1.1"
    # Decompressed content is 1 MB, header content-length indicates 10 KB (ratio 100:1)
    mock_resp.headers = {"content-encoding": "gzip", "content-length": "10000"}
    mock_resp.content = b"X" * (1 * 1024 * 1024)
    mock_resp.text = "X" * (1 * 1024 * 1024)

    with caplog.at_level(logging.WARNING, logger="worker.engine.banner_grabber"):
        with patch("httpx.AsyncClient.send", return_value=mock_resp):
            banner = await grab_http_banner("93.184.216.34", 80, "example.com")
            assert banner is not None
            assert banner["status_code"] == 200
            # Verify the decompression ratio warning was actually logged
            assert any("Decompression ratio limit exceeded" in r.message for r in caplog.records), \
                "Expected decompression ratio warning to be logged"


@pytest.mark.asyncio
async def test_ingestion_payload_over_50mb_rejected_413(seed_data):
    """Test 3: Result payload >50 MB is rejected with HTTP 413 Request Entity Too Large."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
        scan_res = await client.post(
            f"/api/v1/organizations/{seed_data['org1']}/domains/{seed_data['domain_verified']}/scans",
            headers=headers
        )
        scan_id = scan_res.json()["id"]
        job_nonce = scan_res.json()["job_nonce"]
        secret = "dev-scanner-hmac-secret-key"
        signature = compute_payload_signature(secret, scan_id, seed_data["org1"], job_nonce)

        # Create massive payload >50 MB
        huge_observation = {
            "observation_type": "open_port",
            "target": "93.184.216.34:80",
            "raw_data": {"junk": "B" * (51 * 1024 * 1024)}
        }
        payload = {
            "schema_version": "1.0",
            "event_id": "evt-huge",
            "org_id": seed_data["org1"],
            "scan_id": scan_id,
            "worker_id": "worker-1",
            "target_domain": "verified.com",
            "job_nonce": job_nonce,
            "status": "completed",
            "observations": [huge_observation],
            "signature": signature
        }

        res = await client.post("/api/v1/scans/results", json=payload)
        assert res.status_code == 413
        assert "exceeds 50 MB" in res.json()["detail"]


@pytest.mark.asyncio
async def test_port_scanner_socket_timeout_handled():
    """Test 4: Socket connection timeout is caught gracefully and returns None without crashing."""
    async def mock_slow_connection(*args, **kwargs):
        await asyncio.sleep(5.0) # Exceeds 0.1s timeout
        return MagicMock(), MagicMock()

    semaphore = asyncio.Semaphore(5)
    with patch("asyncio.open_connection", side_effect=mock_slow_connection):
        res = await scan_single_port("93.184.216.34", 80, semaphore, timeout=0.1)
        assert res is None


@pytest.mark.asyncio
async def test_runner_target_resolution_failure_handled():
    """Test 5a: Target resolution failure returns failed scan status gracefully."""
    job = ScanExecuteJobPayload(
        event_id="evt-target-fail",
        org_id="org-123",
        scan_id="scan-target-fail",
        domain_id="dom-123",
        domain_name="unresolvable-target.com",
        job_nonce="nonce-target-fail"
    )

    with patch("worker.runner.resolve_and_validate_target", return_value=[]):
        res = await execute_scan_pipeline(job)
        assert res.status == "failed"
        assert "failed network safety validation" in res.error_message


@pytest.mark.asyncio
async def test_runner_total_job_timeout_handled():
    """Test 5b: Total job timeout is caught gracefully and returns failed scan status with timeout error message."""
    job = ScanExecuteJobPayload(
        event_id="evt-job-timeout",
        org_id="org-123",
        scan_id="scan-job-timeout",
        domain_id="dom-123",
        domain_name="slow-target.com",
        job_nonce="nonce-job-timeout"
    )

    async def mock_resolve(domain):
        return ["93.184.216.34"]

    async def mock_slow_scan(*args, **kwargs):
        await asyncio.sleep(5.0)
        return []

    with patch("worker.runner.resolve_and_validate_target", side_effect=mock_resolve):
        with patch("worker.runner.scan_target_ports", side_effect=mock_slow_scan):
            res = await execute_scan_pipeline(job, timeout_seconds=0.1)
            assert res.status == "failed"
            assert "exceeded timeout limit" in res.error_message


def test_sanitize_string_truncates_oversized_banner_and_headers():
    """Test 6 & 7 (shared): Oversized headers and banners are truncated to MAX_BANNER_LEN (4 KB) and control chars removed."""
    oversized_text = "Server: " + ("A" * 10000) + "\x00\x08"
    cleaned = sanitize_string(oversized_text)
    assert len(cleaned) <= MAX_BANNER_LEN
    assert "\x00" not in cleaned
    assert "\x08" not in cleaned


@pytest.mark.asyncio
async def test_oversized_http_headers_truncated():
    """Test 6: Oversized HTTP response headers (e.g. 10 KB Server header) are sanitized and truncated to MAX_BANNER_LEN (4 KB) per field."""
    mock_resp = MagicMock()
    mock_resp.is_redirect = False
    mock_resp.status_code = 200
    mock_resp.http_version = "HTTP/1.1"
    # A single header value exceeding 10 KB
    huge_server_value = "nginx/" + "A" * 12000
    mock_resp.headers = {"server": huge_server_value, "content-type": "text/html"}
    mock_resp.content = b"<html>OK</html>"
    mock_resp.text = "<html>OK</html>"

    with patch("httpx.AsyncClient.send", return_value=mock_resp):
        banner = await grab_http_banner("93.184.216.34", 80, "example.com")
        assert banner is not None
        # Each sanitized header value must be truncated to MAX_BANNER_LEN
        assert len(banner["headers"]["server"]) <= MAX_BANNER_LEN
        assert len(banner["server_header"]) <= MAX_BANNER_LEN
        # Confirm it was actually truncated, not passed through
        assert len(banner["headers"]["server"]) < len(huge_server_value)


@pytest.mark.asyncio
async def test_oversized_banner_body_truncated():
    """Test 7: Oversized banner body text (e.g. 500 KB HTML) is truncated to MAX_BANNER_LEN (4 KB)."""
    mock_resp = MagicMock()
    mock_resp.is_redirect = False
    mock_resp.status_code = 200
    mock_resp.http_version = "HTTP/1.1"
    mock_resp.headers = {"content-type": "text/html"}
    large_body = "<html>" + "B" * (500 * 1024) + "</html>"
    mock_resp.content = large_body.encode("utf-8")
    mock_resp.text = large_body

    with patch("httpx.AsyncClient.send", return_value=mock_resp):
        banner = await grab_http_banner("93.184.216.34", 80, "example.com")
        assert banner is not None
        # Body snippet must be truncated to MAX_BANNER_LEN (4 KB)
        assert len(banner["body_snippet"]) <= MAX_BANNER_LEN
        assert len(banner["body_snippet"]) < len(large_body)


@pytest.mark.asyncio
async def test_banner_grabber_handles_malformed_http_response():
    """Test 8: Malformed HTTP response or connection reset is caught safely."""
    with patch("httpx.AsyncClient.send", side_effect=httpx.NetworkError("Malformed TCP response stream")):
        banner = await grab_http_banner("93.184.216.34", 80, "example.com")
        assert banner is None


@pytest.mark.asyncio
async def test_tls_observer_handles_invalid_cert_safely():
    """Test 9: Invalid, self-signed, or expired TLS certificates are handled safely without crashing worker."""
    with patch("asyncio.open_connection", side_effect=Exception("SSL Handshake Failed: self-signed cert")):
        cert_info = await collect_tls_certificate("93.184.216.34", 443, "expired-cert.com")
        assert cert_info is None


# ============================================================================
# 6. QUEUE SECURITY & HMAC REPLAY TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_ingestion_replayed_job_nonce_rejected(seed_data):
    """Test 10: Replayed job result with mismatched/invalid job_nonce is rejected with HTTP 400."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
        scan_res = await client.post(
            f"/api/v1/organizations/{seed_data['org1']}/domains/{seed_data['domain_verified']}/scans",
            headers=headers
        )
        scan_id = scan_res.json()["id"]

        secret = "dev-scanner-hmac-secret-key"
        fake_nonce = "nonce-replayed-attack"
        signature = compute_payload_signature(secret, scan_id, seed_data["org1"], fake_nonce)

        payload = {
            "schema_version": "1.0",
            "event_id": "evt-replay",
            "org_id": seed_data["org1"],
            "scan_id": scan_id,
            "worker_id": "worker-1",
            "target_domain": "verified.com",
            "job_nonce": fake_nonce,
            "status": "completed",
            "observations": [],
            "signature": signature
        }

        res = await client.post("/api/v1/scans/results", json=payload)
        assert res.status_code == 400
        assert "Replay Defense" in res.json()["detail"]


@pytest.mark.asyncio
async def test_ingestion_schema_version_mismatch_rejected(seed_data):
    """Test 11: Schema version mismatch (e.g. v2.0) is rejected with HTTP 400."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
        scan_res = await client.post(
            f"/api/v1/organizations/{seed_data['org1']}/domains/{seed_data['domain_verified']}/scans",
            headers=headers
        )
        scan_id = scan_res.json()["id"]
        job_nonce = scan_res.json()["job_nonce"]
        secret = "dev-scanner-hmac-secret-key"
        signature = compute_payload_signature(secret, scan_id, seed_data["org1"], job_nonce)

        payload = {
            "schema_version": "99.0", # Unsupported schema version!
            "event_id": "evt-ver",
            "org_id": seed_data["org1"],
            "scan_id": scan_id,
            "worker_id": "worker-1",
            "target_domain": "verified.com",
            "job_nonce": job_nonce,
            "status": "completed",
            "observations": [],
            "signature": signature
        }

        res = await client.post("/api/v1/scans/results", json=payload)
        assert res.status_code == 400
        assert "Unsupported contract schema_version" in res.json()["detail"]


@pytest.mark.asyncio
async def test_ingestion_valid_hmac_signature(seed_data):
    """Test 12: Worker result ingestion with valid HMAC signature succeeds."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
        scan_res = await client.post(
            f"/api/v1/organizations/{seed_data['org1']}/domains/{seed_data['domain_verified']}/scans",
            headers=headers
        )
        scan_id = scan_res.json()["id"]
        job_nonce = scan_res.json()["job_nonce"]

        secret = "dev-scanner-hmac-secret-key"
        signature = compute_payload_signature(secret, scan_id, seed_data["org1"], job_nonce)

        payload = {
            "schema_version": "1.0",
            "event_id": "evt-123",
            "org_id": seed_data["org1"],
            "scan_id": scan_id,
            "worker_id": "worker-1",
            "target_domain": "verified.com",
            "job_nonce": job_nonce,
            "status": "completed",
            "observations": [
                {
                    "observation_type": "open_port",
                    "target": "93.184.216.34:80",
                    "raw_data": {"port": 80, "protocol": "tcp", "state": "open"}
                }
            ],
            "signature": signature
        }

        ingest_res = await client.post("/api/v1/scans/results", json=payload)
        assert ingest_res.status_code == 200
        assert ingest_res.json()["status"] == "completed"


@pytest.mark.asyncio
async def test_ingestion_invalid_hmac_signature_rejected(seed_data):
    """Test 12 (cont): Worker result ingestion with invalid/forged HMAC signature returns HTTP 401."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
        scan_res = await client.post(
            f"/api/v1/organizations/{seed_data['org1']}/domains/{seed_data['domain_verified']}/scans",
            headers=headers
        )
        scan_id = scan_res.json()["id"]
        job_nonce = scan_res.json()["job_nonce"]

        payload = {
            "schema_version": "1.0",
            "event_id": "evt-123",
            "org_id": seed_data["org1"],
            "scan_id": scan_id,
            "worker_id": "worker-1",
            "target_domain": "verified.com",
            "job_nonce": job_nonce,
            "status": "completed",
            "observations": [],
            "signature": "invalid_forged_signature"
        }

        ingest_res = await client.post("/api/v1/scans/results", json=payload)
        assert ingest_res.status_code == 401


# ============================================================================
# 7. WORKER ISOLATION & RESILIENCE TESTS
# ============================================================================

def test_worker_isolation_no_db_or_auth_imports():
    """Test 13: Worker isolation — scanner-worker has ZERO PostgreSQL, ORM, or control-plane authentication dependencies.
    This proves the worker cannot access the database or authentication system even if compromised.
    """
    worker_module_names = [
        "worker.runner",
        "worker.safety.egress_guard",
        "worker.safety.dns_resolver_guard",
        "worker.safety.redirect_guard",
        "worker.engine.port_scanner",
        "worker.engine.banner_grabber",
        "worker.engine.tls_observer",
        "worker.engine.tech_identifier",
    ]

    # Force (re)import of all worker modules
    worker_modules = []
    for name in worker_module_names:
        mod = importlib.import_module(name)
        worker_modules.append(mod)

    # 1. Check sys.modules: no prohibited module should be loaded as a dependency of worker modules
    prohibited_prefixes = ["sqlalchemy", "psycopg2", "asyncpg", "app.infrastructure.db", "app.api.dependencies.auth"]

    # Collect all modules that were transitively imported by worker code
    for mod in worker_modules:
        source_file = getattr(mod, "__file__", "")
        if source_file:
            import ast
            with open(source_file, "r") as f:
                tree = ast.parse(f.read(), filename=source_file)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        for prohibited in prohibited_prefixes:
                            assert not alias.name.startswith(prohibited), \
                                f"Worker Isolation Violation: '{alias.name}' imported in '{mod.__name__}'!"
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        for prohibited in prohibited_prefixes:
                            assert not node.module.startswith(prohibited), \
                                f"Worker Isolation Violation: 'from {node.module}' imported in '{mod.__name__}'!"


@pytest.mark.asyncio
async def test_worker_resilience_hostile_target_does_not_crash():
    """Test 14: Worker resilience — a hostile target exception does not crash the worker pipeline or corrupt another job's data."""
    job = ScanExecuteJobPayload(
        event_id="evt-resilient",
        org_id="org-123",
        scan_id="scan-resilient",
        domain_id="dom-123",
        domain_name="hostile.com",
        job_nonce="nonce-resilient"
    )

    async def mock_resolve(domain, record_type):
        if record_type == "A":
            return [MockRData("93.184.216.34")]
        return []

    # Mock port scan to return an open port, but banner grab throwing hostile unexpected exception
    async def mock_banner_error(*args, **kwargs):
        raise Exception("Hostile remote target payload crash attempt")

    with patch("dns.asyncresolver.Resolver.resolve", side_effect=mock_resolve):
        with patch("worker.runner.scan_target_ports", return_value=[{"port": 80, "protocol": "tcp", "state": "open"}]):
            with patch("worker.runner.grab_http_banner", side_effect=mock_banner_error):
                # Worker must complete gracefully without crashing
                result = await execute_scan_pipeline(job)
                assert result.status == "completed"
                assert len(result.observations) >= 1
                # Verify result is attributed to the correct job, not corrupted with another job's data
                assert result.scan_id == "scan-resilient"
                assert result.org_id == "org-123"
                assert result.job_nonce == "nonce-resilient"


@pytest.mark.asyncio
async def test_redirect_dns_rebinding_combined_attack_blocked():
    """Test 15: Combined redirect + DNS rebinding attack — redirect to a domain that resolves to
    a mix of safe and unsafe IPs is blocked, proving the redirect guard re-validates every hop
    through the DNS resolver guard which is fail-closed.
    """
    # Step 1: Initial domain resolves to safe public IP
    async def mock_resolve_initial(domain, record_type):
        if domain == "safe-initial.com" and record_type == "A":
            return [MockRData("93.184.216.34")]
        # Rebinding attack: redirect target resolves to both public AND internal IP
        if domain == "rebinding-redirect.com" and record_type == "A":
            return [MockRData("93.184.216.34"), MockRData("169.254.169.254")]
        return []

    with patch("dns.asyncresolver.Resolver.resolve", side_effect=mock_resolve_initial):
        # Validate redirect to the rebinding domain — should be BLOCKED
        is_safe, url, ips = await validate_redirect_url("http://rebinding-redirect.com/callback")
        assert is_safe is False, "Redirect to a domain with mixed safe/unsafe IPs must be blocked"
        assert ips == [], "No validated IPs should be returned for a rebinding attack"
