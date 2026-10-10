import uuid
import os
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select

from app.infrastructure.db.base import Base
from app.infrastructure.db.models import Organization, Domain, Scan, Observation, Asset, AssetRelationship
from app.application.ingestion_service import IngestionService
from shared_contracts.events import ScanResultPayload
from worker.runner import compute_payload_signature

TEST_HMAC_SECRET = "test-hmac-secret-12345"


@pytest_asyncio.fixture
async def test_db():

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with async_session() as session:
        yield session

    await engine.dispose()


@pytest.mark.asyncio
async def test_asset_resolution_pipeline_end_to_end(test_db: AsyncSession):
    # Setup test org and domain
    org = Organization(id=str(uuid.uuid4()), name="Test Corp", slug="test-corp")
    test_db.add(org)
    await test_db.flush()

    domain = Domain(
        id=str(uuid.uuid4()),
        org_id=org.id,
        domain_name="example.com",
        status="verified",
        verification_token="token123"
    )
    test_db.add(domain)

    scan_id = str(uuid.uuid4())
    job_nonce = str(uuid.uuid4())
    scan = Scan(
        id=scan_id,
        org_id=org.id,
        domain_id=domain.id,
        status="running",
        job_nonce=job_nonce
    )
    test_db.add(scan)
    await test_db.commit()

    # Construct scan result with observations
    observations_data = [
        {
            "observation_type": "dns_record",
            "target": "example.com",
            "raw_data": {
                "domain_name": "example.com",
                "resolved_ips": ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]
            }
        },
        {
            "observation_type": "open_port",
            "target": "93.184.216.34:443",
            "raw_data": {"port": 443, "state": "open", "service": "https"}
        },
        {
            "observation_type": "http_banner",
            "target": "93.184.216.34:443",
            "raw_data": {"status_code": 200, "headers": {"server": "nginx"}}
        },
        {
            "observation_type": "tls_cert",
            "target": "93.184.216.34:443",
            "raw_data": {
                "fingerprint_sha256": "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
                "san": ["example.com", "www.example.com", "api.example.com"]
            }
        }
    ]

    signature = compute_payload_signature(TEST_HMAC_SECRET, scan_id, org.id, job_nonce)
    payload = ScanResultPayload(
        event_id=str(uuid.uuid4()),
        org_id=org.id,
        scan_id=scan_id,
        worker_id="test-worker-1",
        target_domain="example.com",
        job_nonce=job_nonce,
        status="completed",
        observations=observations_data,
        signature=signature
    )

    ingestion_service = IngestionService(test_db)
    completed_scan = await ingestion_service.ingest_scan_result(
        payload=payload,
        client_ip="127.0.0.1",
        hmac_secret=TEST_HMAC_SECRET
    )

    assert completed_scan.status == "completed"

    # Verify Assets Created
    assets_res = await test_db.execute(select(Asset).where(Asset.org_id == org.id))
    assets = assets_res.scalars().all()
    asset_map = {f"{a.asset_type}:{a.identifier}": a for a in assets}

    # Expected assets:
    # subdomain:example.com
    # ip_address:93.184.216.34
    # ip_address:2606:2800:220:1:248:1893:25c8:1946
    # service:93.184.216.34:443
    # certificate:sha256:a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0
    # subdomain:www.example.com (from SAN)
    # subdomain:api.example.com (from SAN)

    assert "subdomain:example.com" in asset_map
    assert "ip_address:93.184.216.34" in asset_map
    assert "ip_address:2606:2800:220:1:248:1893:25c8:1946" in asset_map
    assert "service:93.184.216.34:443" in asset_map
    assert "certificate:sha256:a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0" in asset_map
    assert "subdomain:www.example.com" in asset_map
    assert "subdomain:api.example.com" in asset_map

    # Verify Observations asset_id linkage
    obs_res = await test_db.execute(select(Observation).where(Observation.scan_id == scan_id))
    observations = obs_res.scalars().all()
    for obs in observations:
        assert obs.asset_id is not None, f"Observation {obs.observation_type} missing asset_id"

    # Verify Relationships
    rels_res = await test_db.execute(select(AssetRelationship).where(AssetRelationship.org_id == org.id))
    rels = rels_res.scalars().all()
    rel_types = set(r.relationship_type for r in rels)

    assert "resolves_to" in rel_types
    assert "runs_service" in rel_types
    assert "presents_cert" in rel_types
    assert "associated_with" in rel_types

    # Verify Relationship Provenance
    for r in rels:
        assert r.org_id == org.id
        assert r.evidence is not None
        assert r.evidence.get("scan_id") == scan_id
        assert "reason" in r.evidence

    # --- IDEMPOTENCY CHECK ---
    # Re-ingest the exact same payload
    completed_scan_2 = await ingestion_service.ingest_scan_result(
        payload=payload,
        client_ip="127.0.0.1",
        hmac_secret=TEST_HMAC_SECRET
    )
    assert completed_scan_2.status == "completed"

    # Count total assets & relationships after idempotent run
    assets_res_2 = await test_db.execute(select(Asset).where(Asset.org_id == org.id))
    assets_2 = assets_res_2.scalars().all()
    assert len(assets_2) == len(assets)

    rels_res_2 = await test_db.execute(select(AssetRelationship).where(AssetRelationship.org_id == org.id))
    rels_2 = rels_res_2.scalars().all()
    assert len(rels_2) == len(rels)


@pytest.mark.asyncio
async def test_certificate_san_does_not_authorize_scans(test_db: AsyncSession):
    """
    TLS SAN discovery creates domain asset in tenant inventory,
    but domain status MUST NOT be 'verified' (remains unverified / not scan-authorized).
    """
    org = Organization(id=str(uuid.uuid4()), name="Corp B", slug="corp-b")
    test_db.add(org)

    domain = Domain(
        id=str(uuid.uuid4()),
        org_id=org.id,
        domain_name="authorized-target.com",
        status="verified",
        verification_token="token456"
    )
    test_db.add(domain)

    scan_id = str(uuid.uuid4())
    job_nonce = str(uuid.uuid4())
    scan = Scan(
        id=scan_id,
        org_id=org.id,
        domain_id=domain.id,
        status="running",
        job_nonce=job_nonce
    )
    test_db.add(scan)
    await test_db.commit()

    # Observation contains a TLS cert with SAN 'unauthorized-san-target.com'
    observations_data = [
        {
            "observation_type": "tls_cert",
            "target": "192.0.2.1:443",
            "raw_data": {
                "fingerprint_sha256": "1111222233334444555566667777888899990000111122223333444455556666",
                "san": ["unauthorized-san-target.com"]
            }
        }
    ]

    signature = compute_payload_signature(TEST_HMAC_SECRET, scan_id, org.id, job_nonce)
    payload = ScanResultPayload(
        event_id=str(uuid.uuid4()),
        org_id=org.id,
        scan_id=scan_id,
        worker_id="test-worker-2",
        target_domain="authorized-target.com",
        job_nonce=job_nonce,
        status="completed",
        observations=observations_data,
        signature=signature
    )

    ingestion_service = IngestionService(test_db)
    await ingestion_service.ingest_scan_result(
        payload=payload,
        client_ip="127.0.0.1",
        hmac_secret=TEST_HMAC_SECRET
    )

    # Asset for unauthorized-san-target.com should exist as an Asset node
    san_asset_res = await test_db.execute(
        select(Asset).where(Asset.org_id == org.id, Asset.identifier == "unauthorized-san-target.com")
    )
    san_asset = san_asset_res.scalars().first()
    assert san_asset is not None
    assert san_asset.asset_type == "subdomain"

    # BUT no verified Domain record exists for 'unauthorized-san-target.com'
    domains_res = await test_db.execute(
        select(Domain).where(Domain.org_id == org.id, Domain.domain_name == "unauthorized-san-target.com")
    )
    san_domain = domains_res.scalars().first()
    assert san_domain is None  # SAN observation MUST NOT automatically create verified Domain targets!
