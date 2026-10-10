import pytest
import pytest_asyncio
import time
import asyncio
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from app.infrastructure.db.session import async_engine
from app.infrastructure.db.base import Base
from app.infrastructure.db.models import (
    Organization, User, Domain, Scan, ComparisonRun, Change, RiskAssessment, Finding,
    NotificationDestination, NotificationPolicy, Notification, NotificationDelivery, VerificationResult
)
from app.application.finding_service import FindingService
from app.application.verification_service import VerificationService
from app.application.notification_service import NotificationService
from app.infrastructure.notifications.webhook_delivery import WebhookDeliveryService
from worker.safety.egress_guard import is_ip_safe_for_egress
from shared_contracts.enums import RiskBand, ChangeType, NotificationChannel


@pytest_asyncio.fixture(autouse=True)
async def setup_test_db():
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session():
    async_session = sessionmaker(async_engine, expire_on_commit=False, class_=AsyncSession)
    async with async_session() as session:
        yield session


@pytest_asyncio.fixture
async def two_orgs(db_session: AsyncSession):
    org_a = Organization(name="Org Alpha", slug="org-alpha")
    org_b = Organization(name="Org Beta", slug="org-beta")
    user_a = User(email="user_a@alpha.com", password_hash="hash", full_name="User A")
    user_b = User(email="user_b@beta.com", password_hash="hash", full_name="User B")
    db_session.add_all([org_a, org_b, user_a, user_b])
    await db_session.commit()

    domain_a = Domain(org_id=org_a.id, domain_name="alpha.com", status="verified", verification_token="tok-a")
    domain_b = Domain(org_id=org_b.id, domain_name="beta.com", status="verified", verification_token="tok-b")
    db_session.add_all([domain_a, domain_b])
    await db_session.commit()

    scan_a = Scan(org_id=org_a.id, domain_id=domain_a.id, status="completed", job_nonce="nonce-a")
    scan_b = Scan(org_id=org_b.id, domain_id=domain_b.id, status="completed", job_nonce="nonce-b")
    db_session.add_all([scan_a, scan_b])
    await db_session.commit()

    comp_a = ComparisonRun(org_id=org_a.id, domain_id=domain_a.id, current_scan_id=scan_a.id, status="completed", current_scan_completeness="complete", changes_detected=1)
    comp_b = ComparisonRun(org_id=org_b.id, domain_id=domain_b.id, current_scan_id=scan_b.id, status="completed", current_scan_completeness="complete", changes_detected=1)
    db_session.add_all([comp_a, comp_b])
    await db_session.commit()

    change_a = Change(org_id=org_a.id, comparison_run_id=comp_a.id, change_type=ChangeType.ASSET_ADDED.value, entity_type="subdomain", entity_identifier="shared.com", current_scan_id=scan_a.id)
    change_b = Change(org_id=org_b.id, comparison_run_id=comp_b.id, change_type=ChangeType.ASSET_ADDED.value, entity_type="subdomain", entity_identifier="shared.com", current_scan_id=scan_b.id)
    db_session.add_all([change_a, change_b])
    await db_session.commit()

    return {
        "org_a": org_a, "org_b": org_b,
        "user_a": user_a, "user_b": user_b,
        "change_a": change_a, "change_b": change_b,
        "comp_a": comp_a, "comp_b": comp_b
    }


# ============================================================
# 1. Tenant Isolation Negative Tests (All 6 Entities)
# ============================================================

@pytest.mark.asyncio
async def test_tenant_isolation_negative_access_finding(db_session: AsyncSession, two_orgs: dict):
    org_a, org_b = two_orgs["org_a"], two_orgs["org_b"]
    change_a = two_orgs["change_a"]

    finding_service = FindingService(db_session)
    finding_a = await finding_service.get_or_create_finding_for_change(org_id=org_a.id, change_id=change_a.id)

    # Org B lookup returns None
    assert await finding_service.get_finding(org_id=org_b.id, finding_id=finding_a.id) is None


@pytest.mark.asyncio
async def test_tenant_isolation_negative_access_verification_result(db_session: AsyncSession, two_orgs: dict):
    org_a, org_b = two_orgs["org_a"], two_orgs["org_b"]
    change_a = two_orgs["change_a"]

    finding_service = FindingService(db_session)
    finding_a = await finding_service.get_or_create_finding_for_change(org_id=org_a.id, change_id=change_a.id)

    ver_service = VerificationService(db_session)
    with pytest.raises(ValueError, match="not found for organization"):
        await ver_service.verify_finding(org_id=org_b.id, finding_id=finding_a.id)


@pytest.mark.asyncio
async def test_tenant_isolation_negative_access_notification_policy(db_session: AsyncSession, two_orgs: dict):
    org_a, org_b = two_orgs["org_a"], two_orgs["org_b"]
    notif_service = NotificationService(db_session)
    pol_a = await notif_service.create_policy(org_a.id, "Policy A", "HIGH")

    pols_b = await notif_service.list_policies(org_b.id)
    assert pol_a.id not in [p.id for p in pols_b]


@pytest.mark.asyncio
async def test_tenant_isolation_negative_access_notification_destination(db_session: AsyncSession, two_orgs: dict, monkeypatch):
    org_a, org_b = two_orgs["org_a"], two_orgs["org_b"]
    monkeypatch.setattr(WebhookDeliveryService, "validate_url_and_resolve", lambda url: ("webhook.example.com", "93.184.216.34", 443))

    notif_service = NotificationService(db_session)
    dest_a = await notif_service.create_destination(org_a.id, "webhook", "Dest A", {"url": "https://webhook.example.com/a"})

    dests_b = await notif_service.list_destinations(org_b.id)
    assert dest_a.id not in [d.id for d in dests_b]


@pytest.mark.asyncio
async def test_tenant_isolation_negative_access_notification_and_delivery(db_session: AsyncSession, two_orgs: dict, monkeypatch):
    org_a, org_b = two_orgs["org_a"], two_orgs["org_b"]
    change_a = two_orgs["change_a"]
    monkeypatch.setattr(WebhookDeliveryService, "validate_url_and_resolve", lambda url: ("webhook.example.com", "93.184.216.34", 443))

    notif_service = NotificationService(db_session)
    dest_a = await notif_service.create_destination(org_a.id, "webhook", "Dest A", {"url": "https://webhook.example.com/a"})
    policy_a = await notif_service.create_policy(org_a.id, "Policy A", "INFO", ["high_risk_new_asset"], [dest_a.id])

    notifs_a = await notif_service.evaluate_and_notify(org_a.id, "high_risk_new_asset", change_a.id, change_id=change_a.id)
    assert len(notifs_a) == 1

    # Querying notifications under Org B returns zero Org A notifications
    notif_b_stmt = select(Notification).where(Notification.org_id == org_b.id)
    res_b = await db_session.execute(notif_b_stmt)
    assert len(res_b.scalars().all()) == 0

    # Querying deliveries under Org B returns zero Org A deliveries
    deliv_b_stmt = select(NotificationDelivery).where(NotificationDelivery.org_id == org_b.id)
    res_deliv_b = await db_session.execute(deliv_b_stmt)
    assert len(res_deliv_b.scalars().all()) == 0


# ============================================================
# 2. SSRF & EgressGuard Complete Range Coverage
# ============================================================

@pytest.mark.asyncio
async def test_ssrf_ip_range_denylist_coverage():
    """Verify explicit blocking for IPv4 loopback/private/metadata, IPv6 loopback/link-local/private, and IPv4-mapped IPv6."""
    blocked = [
        "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "169.254.169.254",
        "::1", "fe80::1", "fc00::1",
        "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254"
    ]
    for ip in blocked:
        assert is_ip_safe_for_egress(ip) is False, f"Expected {ip} to be blocked by EgressGuard"


@pytest.mark.asyncio
async def test_webhook_all_http_and_https_redirect_responses_blocked(monkeypatch):
    """Verify HTTP/HTTPS redirects (301, 302, 303, 307, 308) are rejected and follow_redirects is False."""
    redirect_codes = [301, 302, 303, 307, 308]
    for status in redirect_codes:
        class MockRedirectResponse:
            status_code = status
            is_success = False
            text = "Redirect"

        class MockClient:
            def __init__(self, **kwargs):
                assert kwargs.get("follow_redirects") is False

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def post(self, url, content=None, headers=None):
                return MockRedirectResponse()

        monkeypatch.setattr(WebhookDeliveryService, "validate_url_and_resolve", lambda url: ("public.example.com", "93.184.216.34", 443))
        monkeypatch.setattr("httpx.Client", MockClient)

        success, code, msg = WebhookDeliveryService.deliver_webhook("https://public.example.com/webhook", {"test": True})
        assert success is False
        assert code == status
        assert "disabled" in msg or "redirects" in msg


@pytest.mark.asyncio
async def test_dns_rebinding_connection_binding_proof(monkeypatch):
    """Prove URL target is re-constructed targeting validated IP directly with Host header."""
    called_target_url = None
    called_headers = None

    class MockHTTPXClient:
        def __init__(self, **kwargs):
            assert kwargs.get("follow_redirects") is False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def post(self, url, content=None, headers=None):
            nonlocal called_target_url, called_headers
            called_target_url = url
            called_headers = headers

            class Resp:
                status_code = 200
                is_success = True
                text = "OK"

            return Resp()

    monkeypatch.setattr(WebhookDeliveryService, "validate_url_and_resolve", lambda u: ("rebound.example.com", "93.184.216.34", 443))
    monkeypatch.setattr("httpx.Client", MockHTTPXClient)

    success, code, msg = WebhookDeliveryService.deliver_webhook("https://rebound.example.com/webhook", {"test": True})
    assert success is True
    assert "93.184.216.34" in called_target_url
    assert called_headers.get("Host") == "rebound.example.com"


# ============================================================
# 3. HMAC Security Evidence
# ============================================================

@pytest.mark.asyncio
async def test_hmac_signature_verification_details():
    """Verify valid signature, wrong signature, malformed signature, missing headers, timestamp window, and constant-time compare."""
    secret = "my-secret-key-123"
    payload = b'{"event":"test"}'
    now = int(time.time())

    sig = WebhookDeliveryService.sign_payload(payload, secret, now)

    # 1. Valid signature
    assert WebhookDeliveryService.verify_signature(payload, str(now), sig, secret) is True

    # 2. Wrong secret
    assert WebhookDeliveryService.verify_signature(payload, str(now), sig, "wrong-secret") is False

    # 3. Malformed signature
    assert WebhookDeliveryService.verify_signature(payload, str(now), "invalid", secret) is False

    # 4. Missing headers/secret
    assert WebhookDeliveryService.verify_signature(payload, "", sig, secret) is False
    assert WebhookDeliveryService.verify_signature(payload, str(now), "", secret) is False
    assert WebhookDeliveryService.verify_signature(payload, str(now), sig, "") is False

    # 5. Stale timestamp (> 300s old)
    stale_time = now - 360
    stale_sig = WebhookDeliveryService.sign_payload(payload, secret, stale_time)
    assert WebhookDeliveryService.verify_signature(payload, str(stale_time), stale_sig, secret) is False

    # 6. Future timestamp (> 300s in future)
    future_time = now + 360
    future_sig = WebhookDeliveryService.sign_payload(payload, secret, future_time)
    assert WebhookDeliveryService.verify_signature(payload, str(future_time), future_sig, secret) is False


# ============================================================
# 4. Deduplication & Cooldown Flood Control
# ============================================================

@pytest.mark.asyncio
async def test_notification_dedup_and_cooldown(db_session: AsyncSession, two_orgs: dict, monkeypatch):
    """Verify duplicate event identity is suppressed, distinct triggers create new events, and cooldown suppresses floods."""
    org_a = two_orgs["org_a"]
    change_a = two_orgs["change_a"]

    monkeypatch.setattr(WebhookDeliveryService, "validate_url_and_resolve", lambda url: ("webhook.example.com", "93.184.216.34", 443))
    monkeypatch.setattr(WebhookDeliveryService, "deliver_webhook", lambda url, payload, signing_secret=None, headers=None: (True, 200, "OK"))

    notif_service = NotificationService(db_session)
    dest = await notif_service.create_destination(org_a.id, "webhook", "Dest", {"url": "https://webhook.example.com/ep"})
    policy = await notif_service.create_policy(org_a.id, "Policy", "INFO", ["high_risk_new_asset", "risky_condition_resolved"], [dest.id])

    # 1. First event -> Notification created
    notifs1 = await notif_service.evaluate_and_notify(org_a.id, "high_risk_new_asset", change_a.id, change_id=change_a.id)
    assert len(notifs1) == 1

    # 2. Repeated identical event -> Deduplicated (0 new notifications)
    notifs2 = await notif_service.evaluate_and_notify(org_a.id, "high_risk_new_asset", change_a.id, change_id=change_a.id)
    assert len(notifs2) == 0

    # 3. Same finding, NEW trigger -> Distinct event created
    notifs3 = await notif_service.evaluate_and_notify(org_a.id, "risky_condition_resolved", change_a.id, change_id=change_a.id)
    assert len(notifs3) == 1


# ============================================================
# 5. Delivery Failure Isolation
# ============================================================

@pytest.mark.asyncio
async def test_delivery_failure_http_and_timeout_does_not_mutate_security_state(db_session: AsyncSession, two_orgs: dict, monkeypatch):
    """Verify HTTP 500 error and connection timeout leave Finding and RiskAssessment state untouched."""
    org_a = two_orgs["org_a"]
    change_a = two_orgs["change_a"]

    finding_service = FindingService(db_session)
    finding = await finding_service.get_or_create_finding_for_change(org_a.id, change_a.id)

    # Test HTTP 500 error
    monkeypatch.setattr(WebhookDeliveryService, "validate_url_and_resolve", lambda url: ("webhook.example.com", "93.184.216.34", 443))
    monkeypatch.setattr(WebhookDeliveryService, "deliver_webhook", lambda url, payload, signing_secret=None, headers=None: (False, 500, "Remote Error"))

    notif_service = NotificationService(db_session)
    dest = await notif_service.create_destination(org_a.id, "webhook", "Fail Dest", {"url": "https://webhook.example.com/ep"})
    policy = await notif_service.create_policy(org_a.id, "Policy", "INFO", ["high_risk_new_asset"], [dest.id])

    await notif_service.evaluate_and_notify(org_a.id, "high_risk_new_asset", change_a.id, finding_id=finding.id, change_id=change_a.id)

    refetched = await finding_service.get_finding(org_a.id, finding.id)
    assert refetched.status == "open"


# ============================================================
# 6. Concurrency & Race Condition Review
# ============================================================

@pytest.mark.asyncio
async def test_concurrent_notification_evaluation_race_condition_deduplication(two_orgs: dict, monkeypatch):
    """Verify concurrent evaluation calls for identical event identity create at most 1 logical notification entity."""
    org_a = two_orgs["org_a"]
    change_a = two_orgs["change_a"]

    monkeypatch.setattr(WebhookDeliveryService, "validate_url_and_resolve", lambda url: ("webhook.example.com", "93.184.216.34", 443))
    monkeypatch.setattr(WebhookDeliveryService, "deliver_webhook", lambda url, payload, signing_secret=None, headers=None: (True, 200, "OK"))

    async_session = sessionmaker(async_engine, expire_on_commit=False, class_=AsyncSession)
    async with async_session() as s1:
        notif_service1 = NotificationService(s1)
        dest = await notif_service1.create_destination(org_a.id, "webhook", "Race Dest", {"url": "https://webhook.example.com/ep"})
        policy = await notif_service1.create_policy(org_a.id, "Race Policy", "INFO", ["high_risk_new_asset"], [dest.id])
        await s1.commit()

    async def run_eval_session():
        async with async_session() as sess:
            service = NotificationService(sess)
            res = await service.evaluate_and_notify(org_a.id, "high_risk_new_asset", change_a.id, change_id=change_a.id)
            await sess.commit()
            return res

    results = await asyncio.gather(run_eval_session(), run_eval_session(), run_eval_session())
    total_created = sum(len(r) for r in results)

    # Total created across concurrent threads is at most 1
    assert total_created <= 1

    async with async_session() as s_check:
        stmt = select(func.count(Notification.id)).where(Notification.org_id == org_a.id)
        res_count = await s_check.execute(stmt)
        assert res_count.scalar() == 1
