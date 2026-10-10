import asyncio
import hmac
import hashlib
import logging
import os
import uuid
from typing import Any, Dict, List
from shared_contracts.events import ScanExecuteJobPayload, ScanResultPayload
from worker.safety.dns_resolver_guard import resolve_and_validate_target
from worker.engine.port_scanner import scan_target_ports
from worker.engine.banner_grabber import grab_http_banner
from worker.engine.tls_observer import collect_tls_certificate
from worker.engine.tech_identifier import identify_technologies

logger = logging.getLogger(__name__)

SCANNER_HMAC_SECRET = os.getenv("SCANNER_HMAC_SECRET", "dev-scanner-hmac-secret-key")
WORKER_ID = os.getenv("WORKER_ID", f"worker-{uuid.uuid4().hex[:8]}")


def compute_payload_signature(secret: str, scan_id: str, org_id: str, job_nonce: str) -> str:
    """Computes HMAC-SHA256 signature for payload verification."""
    message = f"{scan_id}:{org_id}:{job_nonce}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


async def execute_scan_pipeline(
    job: ScanExecuteJobPayload,
    hmac_secret: str = SCANNER_HMAC_SECRET,
    worker_id: str = WORKER_ID,
    timeout_seconds: float = 300.0
) -> ScanResultPayload:
    """
    Main isolated scanner worker execution pipeline:
    1. Target Authorization Check.
    2. DNS TOCTOU & Rebinding Guard (Resolve and validate all IPs).
    3. Safe network observation (Port scan, HTTP banner, TLS cert, Tech ID).
    4. Observation aggregation.
    5. HMAC-SHA256 payload signing.
    """
    logger.info(f"Starting scan execution job {job.scan_id} for domain {job.domain_name} (org: {job.org_id})")

    # 1. Target Validation
    if not job.domain_name or not job.domain_name.strip():
        signature = compute_payload_signature(hmac_secret, job.scan_id, job.org_id, job.job_nonce)
        return ScanResultPayload(
            event_id=str(uuid.uuid4()),
            org_id=job.org_id,
            scan_id=job.scan_id,
            worker_id=worker_id,
            target_domain=job.domain_name or "unknown",
            job_nonce=job.job_nonce,
            status="failed",
            error_message="Invalid or empty target domain name in scan job payload",
            signature=signature
        )

    # 2. DNS TOCTOU & Rebinding Guard
    validated_ips = await resolve_and_validate_target(job.domain_name)
    if not validated_ips:
        logger.warning(f"Destination Safety Abort: Target '{job.domain_name}' resolved to zero safe IPs or violated policy.")
        signature = compute_payload_signature(hmac_secret, job.scan_id, job.org_id, job.job_nonce)
        return ScanResultPayload(
            event_id=str(uuid.uuid4()),
            org_id=job.org_id,
            scan_id=job.scan_id,
            worker_id=worker_id,
            target_domain=job.domain_name,
            job_nonce=job.job_nonce,
            status="failed",
            error_message="Target destination failed network safety validation or resolved to prohibited network",
            signature=signature
        )

    observations: List[Dict[str, Any]] = []

    # Record DNS observation
    observations.append({
        "observation_type": "dns_record",
        "target": job.domain_name,
        "raw_data": {
            "domain_name": job.domain_name,
            "resolved_ips": validated_ips
        }
    })

    # 3. Discovery Pipeline Execution per pre-validated IP
    async def _run_observations() -> List[Dict[str, Any]]:
        obs_list: List[Dict[str, Any]] = []
        for target_ip in validated_ips:
            try:
                open_ports = await scan_target_ports(target_ip, target_ports=job.target_ports)
            except Exception as e:
                logger.warning(f"Port scanner exception for target IP {target_ip}: {e}")
                continue

            for port_info in open_ports:
                port = port_info["port"]

                # Record open port observation
                obs_list.append({
                    "observation_type": "open_port",
                    "target": f"{target_ip}:{port}",
                    "raw_data": port_info
                })

                # Web service discovery (HTTP/HTTPS ports)
                if port in (80, 443, 8080, 8443, 8000, 8888):
                    use_tls = port in (443, 8443)

                    # HTTP Banner Grab
                    try:
                        banner = await grab_http_banner(target_ip, port, job.domain_name, use_tls=use_tls)
                        if banner:
                            obs_list.append({
                                "observation_type": "http_banner",
                                "target": f"{target_ip}:{port}",
                                "raw_data": banner
                            })

                            # Tech ID
                            techs = identify_technologies(banner.get("headers", {}), banner.get("body_snippet"))
                            if techs:
                                obs_list.append({
                                    "observation_type": "tech_stack",
                                    "target": f"{target_ip}:{port}",
                                    "raw_data": {"technologies": techs}
                                })
                    except Exception as e:
                        logger.warning(f"HTTP banner grab error for {target_ip}:{port}: {e}")

                    # TLS Certificate Observation
                    if use_tls:
                        try:
                            tls_cert = await collect_tls_certificate(target_ip, port, job.domain_name)
                            if tls_cert:
                                obs_list.append({
                                    "observation_type": "tls_cert",
                                    "target": f"{target_ip}:{port}",
                                    "raw_data": tls_cert
                                })
                        except Exception as e:
                            logger.warning(f"TLS certificate collection error for {target_ip}:{port}: {e}")
        return obs_list

    try:
        scanned_obs = await asyncio.wait_for(_run_observations(), timeout=timeout_seconds)
        observations.extend(scanned_obs)
    except asyncio.TimeoutError:
        logger.error(f"Scan job {job.scan_id} exceeded total job timeout limit of {timeout_seconds}s.")
        signature = compute_payload_signature(hmac_secret, job.scan_id, job.org_id, job.job_nonce)
        return ScanResultPayload(
            event_id=str(uuid.uuid4()),
            org_id=job.org_id,
            scan_id=job.scan_id,
            worker_id=worker_id,
            target_domain=job.domain_name,
            job_nonce=job.job_nonce,
            status="failed",
            error_message=f"Total job execution exceeded timeout limit of {timeout_seconds}s",
            signature=signature
        )

    # Compute HMAC payload signature
    signature = compute_payload_signature(hmac_secret, job.scan_id, job.org_id, job.job_nonce)

    logger.info(f"Scan job {job.scan_id} completed successfully with {len(observations)} observations.")

    return ScanResultPayload(
        event_id=str(uuid.uuid4()),
        org_id=job.org_id,
        scan_id=job.scan_id,
        worker_id=worker_id,
        target_domain=job.domain_name,
        job_nonce=job.job_nonce,
        status="completed",
        observations=observations,
        signature=signature
    )


async def process_scan_job(ctx: dict, job_payload_dict: dict) -> dict:
    """arq worker job processing wrapper."""
    job = ScanExecuteJobPayload(**job_payload_dict)
    result = await execute_scan_pipeline(job)
    return result.model_dump(mode="json")


class WorkerSettings:
    functions = [process_scan_job]
    redis_settings = None


if __name__ == "__main__":
    print("Scanner Worker Pipeline ready.")
