import pytest
import pytest_asyncio
import asyncio
from httpx import AsyncClient, ASGITransport
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from app.main import app
from app.infrastructure.db.session import async_engine
from app.infrastructure.db.base import Base
from app.infrastructure.db.models import Organization, User, Membership, Domain, AuditEvent
from shared_contracts.enums import DomainStatus
import dns.resolver

class MockRedis:
    def __init__(self):
        self.counts = {}
    async def incr(self, key):
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]
    async def expire(self, key, time):
        pass
    async def ping(self):
        return True
    async def close(self):
        pass

@pytest_asyncio.fixture(autouse=True)
async def setup_test_db():
    mock_redis_inst = MockRedis()
    with patch("app.api.dependencies.rate_limit.get_redis_client", return_value=mock_redis_inst):
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
        user2 = User(email="viewer1@test.com", password_hash="hash", full_name="Viewer 1")
        user3 = User(email="admin2@test.com", password_hash="hash", full_name="Admin 2")
        
        session.add_all([org1, org2, user1, user2, user3])
        await session.commit()
        
        mem1 = Membership(org_id=org1.id, user_id=user1.id, role="admin")
        mem2 = Membership(org_id=org1.id, user_id=user2.id, role="viewer")
        mem3 = Membership(org_id=org2.id, user_id=user3.id, role="admin")
        session.add_all([mem1, mem2, mem3])
        await session.commit()
        
        return {
            "org1": org1.id,
            "org2": org2.id,
            "admin1": user1.id,
            "viewer1": user2.id,
            "admin2": user3.id,
        }

@pytest.mark.asyncio
async def test_cross_tenant_get(seed_data):
    """Test fetching Org 1's domain with Org 2's identity."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create domain in org1
        headers1 = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
        res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains", json={"domain_name": "example1.com"}, headers=headers1)
        domain_id = res.json()["id"]

        # Access with org2 identity
        headers2 = {"X-User-ID": seed_data["admin2"], "X-Org-ID": seed_data["org2"]}
        # Using Org 2 identity but trying to access org1's URL
        res = await client.get(f"/api/v1/organizations/{seed_data['org1']}/domains/{domain_id}", headers=headers2)
        assert res.status_code == 403
        
        # Using Org 2 identity on org2 URL but with org1's domain ID
        res = await client.get(f"/api/v1/organizations/{seed_data['org2']}/domains/{domain_id}", headers=headers2)
        assert res.status_code == 404

@pytest.mark.asyncio
async def test_cross_tenant_verify(seed_data):
    """Test verifying Org 1's domain with Org 2's identity."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers1 = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
        res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains", json={"domain_name": "example2.com"}, headers=headers1)
        domain_id = res.json()["id"]

        headers2 = {"X-User-ID": seed_data["admin2"], "X-Org-ID": seed_data["org2"]}
        # Org 2 identity accessing Org 1 URL
        res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains/{domain_id}/verify", headers=headers2)
        assert res.status_code == 403

@pytest.mark.asyncio
async def test_cross_tenant_delete(seed_data):
    """Test deleting Org 1's domain with Org 2's identity."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers1 = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
        res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains", json={"domain_name": "example3.com"}, headers=headers1)
        domain_id = res.json()["id"]

        headers2 = {"X-User-ID": seed_data["admin2"], "X-Org-ID": seed_data["org2"]}
        res = await client.delete(f"/api/v1/organizations/{seed_data['org1']}/domains/{domain_id}", headers=headers2)
        assert res.status_code == 403

@pytest.mark.asyncio
async def test_rbac_admin_vs_viewer(seed_data):
    """Test RBAC where Viewer gets 403 on POST/DELETE, and Admin succeeds."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers_viewer = {"X-User-ID": seed_data["viewer1"], "X-Org-ID": seed_data["org1"]}
        
        # Viewer POST fails
        res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains", json={"domain_name": "viewer.com"}, headers=headers_viewer)
        assert res.status_code == 403
        
        # Admin POST succeeds
        headers_admin = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
        res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains", json={"domain_name": "admin.com"}, headers=headers_admin)
        assert res.status_code == 201
        domain_id = res.json()["id"]
        
        # Viewer DELETE fails
        res = await client.delete(f"/api/v1/organizations/{seed_data['org1']}/domains/{domain_id}", headers=headers_viewer)
        assert res.status_code == 403
        
        # Admin DELETE succeeds
        res = await client.delete(f"/api/v1/organizations/{seed_data['org1']}/domains/{domain_id}", headers=headers_admin)
        assert res.status_code == 204

@pytest.mark.asyncio
async def test_app_env_production_rejection(seed_data):
    """Test that DevAuthAdapter throws 500 when APP_ENV is production."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("app.api.dependencies.auth.settings.APP_ENV", "production"):
            headers = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
            res = await client.get(f"/api/v1/organizations/{seed_data['org1']}/domains", headers=headers)
            assert res.status_code == 500

@pytest.mark.asyncio
async def test_rate_limit_enforcement(seed_data):
    """Test rate limiting on domain creation (10 max)."""
    transport = ASGITransport(app=app)
    
    # Mock redis client to track count and raise 429
    class MockRedis:
        def __init__(self):
            self.counts = {}
        async def incr(self, key):
            self.counts[key] = self.counts.get(key, 0) + 1
            return self.counts[key]
        async def expire(self, key, time):
            pass
            
    with patch("app.api.dependencies.rate_limit.get_redis_client", return_value=MockRedis()):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
            
            for i in range(10):
                res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains", json={"domain_name": f"rate{i}.com"}, headers=headers)
                assert res.status_code == 201
                
            res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains", json={"domain_name": "rate10.com"}, headers=headers)
            assert res.status_code == 429

@pytest.mark.asyncio
async def test_audit_logging_and_token_leakage(seed_data):
    """Test creation, deletion emit audit logs WITHOUT the token."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
        res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains", json={"domain_name": "audit.com"}, headers=headers)
        domain_id = res.json()["id"]
        token = res.json()["verification_token"]
        
        await client.delete(f"/api/v1/organizations/{seed_data['org1']}/domains/{domain_id}", headers=headers)

    from sqlalchemy.future import select
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm import sessionmaker
    async_session = sessionmaker(async_engine, expire_on_commit=False, class_=AsyncSession)
    
    async with async_session() as session:
        result = await session.execute(select(AuditEvent).order_by(AuditEvent.created_at))
        events = result.scalars().all()
        
        event_types = [e.event_type for e in events]
        assert "domain.created" in event_types
        assert "domain.deleted" in event_types
        
        for event in events:
            # Assert token is strictly absent from the database details
            import json
            details_str = json.dumps(event.details)
            assert token not in details_str

class MockDNSAnswer:
    def __init__(self, strings):
        self.strings = [s.encode('utf-8') for s in strings]

@pytest.mark.asyncio
async def test_dns_wrong_token(seed_data):
    """Test verification fails on wrong token."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
        res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains", json={"domain_name": "wrong.com"}, headers=headers)
        domain_id = res.json()["id"]

        async def mock_resolve(*args, **kwargs):
            return [MockDNSAnswer(["wrong-token"])]
            
        with patch("dns.asyncresolver.resolve", side_effect=mock_resolve):
            res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains/{domain_id}/verify", headers=headers)
            assert res.status_code == 200
            assert res.json()["status"] == "failed"

@pytest.mark.asyncio
async def test_dns_substring_rejection(seed_data):
    """Test verification fails if token is just a substring."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
        res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains", json={"domain_name": "substring.com"}, headers=headers)
        domain_id = res.json()["id"]
        token = res.json()["verification_token"]

        async def mock_resolve(*args, **kwargs):
            return [MockDNSAnswer([f"prefix-{token}-suffix"])]
            
        with patch("dns.asyncresolver.resolve", side_effect=mock_resolve):
            res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains/{domain_id}/verify", headers=headers)
            assert res.status_code == 200
            assert res.json()["status"] == "failed"

@pytest.mark.asyncio
async def test_dns_multiple_txt(seed_data):
    """Test verification succeeds when multiple TXT exist and one is correct."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
        res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains", json={"domain_name": "multi.com"}, headers=headers)
        domain_id = res.json()["id"]
        token = res.json()["verification_token"]

        async def mock_resolve(*args, **kwargs):
            return [MockDNSAnswer(["spf1"]), MockDNSAnswer([token]), MockDNSAnswer(["other"])]
            
        with patch("dns.asyncresolver.resolve", side_effect=mock_resolve):
            res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains/{domain_id}/verify", headers=headers)
            assert res.status_code == 200
            assert res.json()["status"] == "verified"

@pytest.mark.asyncio
async def test_dns_nxdomain(seed_data):
    """Test verification fails on NXDOMAIN."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
        res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains", json={"domain_name": "nx.com"}, headers=headers)
        domain_id = res.json()["id"]

        with patch("dns.asyncresolver.resolve", side_effect=dns.resolver.NXDOMAIN):
            res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains/{domain_id}/verify", headers=headers)
            assert res.status_code == 200
            assert res.json()["status"] == "failed"

@pytest.mark.asyncio
async def test_dns_timeout(seed_data):
    """Test verification fails on Timeout."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
        res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains", json={"domain_name": "timeout.com"}, headers=headers)
        domain_id = res.json()["id"]

        with patch("dns.asyncresolver.resolve", side_effect=dns.exception.Timeout):
            res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains/{domain_id}/verify", headers=headers)
            assert res.status_code == 200
            assert res.json()["status"] == "failed"

@pytest.mark.asyncio
async def test_concurrent_verification(seed_data):
    """Test concurrent verification requests safely resolve."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
        res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains", json={"domain_name": "concurrent.com"}, headers=headers)
        domain_id = res.json()["id"]
        token = res.json()["verification_token"]

        async def mock_resolve(*args, **kwargs):
            return [MockDNSAnswer([token])]
            
        with patch("dns.asyncresolver.resolve", side_effect=mock_resolve):
            reqs = [client.post(f"/api/v1/organizations/{seed_data['org1']}/domains/{domain_id}/verify", headers=headers) for _ in range(3)]
            results = await asyncio.gather(*reqs)
            
            # Since DB lock ensures atomic process, they should all eventually return 200 VERIFIED,
            # or some might get 429 if the rate limit is hit (5 limit > 3 requests, so 200 is fine).
            for r in results:
                assert r.status_code == 200
                assert r.json()["status"] == "verified"

@pytest.mark.asyncio
async def test_expired_domain_rejection(seed_data):
    """Test HTTP 400 is returned when verifying an expired domain."""
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm import sessionmaker
    async_session = sessionmaker(async_engine, expire_on_commit=False, class_=AsyncSession)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
        res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains", json={"domain_name": "expired.com"}, headers=headers)
        domain_id = res.json()["id"]

        # Time travel DB to 73 hours ago
        async with async_session() as session:
            domain = await session.get(Domain, domain_id)
            domain.created_at = datetime.now(timezone.utc) - timedelta(hours=73)
            await session.commit()
            
        res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains/{domain_id}/verify", headers=headers)
        assert res.status_code == 400
        assert res.json()["detail"] == "Verification token has expired"

@pytest.mark.asyncio
async def test_replay_verification(seed_data):
    """Test verifying an already verified domain is safe/idempotent."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-User-ID": seed_data["admin1"], "X-Org-ID": seed_data["org1"]}
        res = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains", json={"domain_name": "replay.com"}, headers=headers)
        domain_id = res.json()["id"]
        token = res.json()["verification_token"]

        async def mock_resolve(*args, **kwargs):
            return [MockDNSAnswer([token])]
            
        with patch("dns.asyncresolver.resolve", side_effect=mock_resolve):
            # First verify
            res1 = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains/{domain_id}/verify", headers=headers)
            assert res1.json()["status"] == "verified"
            
            # Second verify (replay)
            res2 = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains/{domain_id}/verify", headers=headers)
            assert res2.json()["status"] == "verified"
