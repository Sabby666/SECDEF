import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.infrastructure.db.session import async_engine
from app.infrastructure.db.base import Base
from app.infrastructure.db.models import Organization, User, Membership

@pytest_asyncio.fixture(autouse=True)
async def setup_test_db():
    # Setup tables
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
        
    yield
    
    # Teardown
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
        user1 = User(email="u1@test.com", password_hash="hash", full_name="U1")
        user2 = User(email="u2@test.com", password_hash="hash", full_name="U2")
        
        session.add_all([org1, org2, user1, user2])
        await session.commit()
        
        mem1 = Membership(org_id=org1.id, user_id=user1.id, role="admin")
        mem2 = Membership(org_id=org2.id, user_id=user2.id, role="admin")
        session.add_all([mem1, mem2])
        await session.commit()
        
        return {
            "org1": org1.id,
            "org2": org2.id,
            "user1": user1.id,
            "user2": user2.id
        }

@pytest.mark.asyncio
async def test_create_domain_success(seed_data):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {
            "X-User-ID": seed_data["user1"],
            "X-Org-ID": seed_data["org1"]
        }
        payload = {"domain_name": "example.com"}
        response = await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains", json=payload, headers=headers)
        
        assert response.status_code == 201
        data = response.json()
        assert data["domain_name"] == "example.com"
        assert data["status"] == "pending_verification"
        assert "verification_token" in data

@pytest.mark.asyncio
async def test_create_domain_idor_prevention(seed_data):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # User 1 tries to create domain in Org 2
        headers = {
            "X-User-ID": seed_data["user1"],
            "X-Org-ID": seed_data["org1"] # their context org
        }
        payload = {"domain_name": "hacked.com"}
        # But target URL is org2
        response = await client.post(f"/api/v1/organizations/{seed_data['org2']}/domains", json=payload, headers=headers)
        
        assert response.status_code == 403
        assert response.json()["detail"] == "Cross-tenant access denied"

@pytest.mark.asyncio
async def test_list_domains(seed_data):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {
            "X-User-ID": seed_data["user1"],
            "X-Org-ID": seed_data["org1"]
        }
        # Create
        await client.post(f"/api/v1/organizations/{seed_data['org1']}/domains", json={"domain_name": "example1.com"}, headers=headers)
        
        # List
        response = await client.get(f"/api/v1/organizations/{seed_data['org1']}/domains", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["domain_name"] == "example1.com"
