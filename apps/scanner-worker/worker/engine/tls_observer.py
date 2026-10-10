import asyncio
import hashlib
import logging
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from worker.safety.egress_guard import is_ip_safe_for_egress

logger = logging.getLogger(__name__)


async def collect_tls_certificate(
    target_ip: str,
    port: int,
    hostname: str,
    timeout: float = 5.0
) -> Optional[Dict[str, Any]]:
    """
    Collects TLS certificate metadata directly from target endpoint.
    Connects directly to pre-validated target_ip with SNI server_hostname.
    Certificate claims are raw OBSERVATION evidence only.
    """
    if not is_ip_safe_for_egress(target_ip):
        logger.error(f"Egress Safety Gate Abort: TLS cert collection on unsafe IP '{target_ip}'")
        return None

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    try:
        connect_coro = asyncio.open_connection(target_ip, port, ssl=ssl_context, server_hostname=hostname)
        reader, writer = await asyncio.wait_for(connect_coro, timeout=timeout)

        ssl_object = writer.get_extra_info("ssl_object")
        if not ssl_object:
            writer.close()
            await writer.wait_closed()
            return None

        cert_dict = ssl_object.getpeercert(binary_form=False)
        der_bytes = ssl_object.getpeercert(binary_form=True)
        cipher = ssl_object.cipher()
        tls_version = ssl_object.version()

        writer.close()
        await writer.wait_closed()

        sha256_fingerprint = hashlib.sha256(der_bytes).hexdigest() if der_bytes else None

        # Parse subject & issuer
        subject_str = _format_cert_name(cert_dict.get("subject", ()))
        issuer_str = _format_cert_name(cert_dict.get("issuer", ()))

        # Parse SANs
        sans: List[str] = []
        for san_type, san_value in cert_dict.get("subjectAltName", ()):
            if san_type in ("DNS", "IP Address"):
                sans.append(san_value)

        return {
            "port": port,
            "target_ip": target_ip,
            "hostname": hostname,
            "subject": subject_str,
            "issuer": issuer_str,
            "sans": sans,
            "not_before": cert_dict.get("notBefore"),
            "not_after": cert_dict.get("notAfter"),
            "serial_number": str(cert_dict.get("serialNumber", "")),
            "fingerprint_sha256": sha256_fingerprint,
            "tls_version": tls_version,
            "cipher": cipher[0] if cipher else None,
            "observed_at": datetime.now(timezone.utc).isoformat()
        }

    except (asyncio.TimeoutError, OSError, ssl.SSLError, Exception) as e:
        logger.debug(f"TLS cert collection error for {target_ip}:{port}: {e}")
        return None


def _format_cert_name(name_tuple: tuple) -> str:
    """Format certificate subject/issuer tuple into readable string."""
    parts = []
    for rdn in name_tuple:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)
