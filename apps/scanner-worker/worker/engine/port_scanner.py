import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from worker.safety.egress_guard import is_ip_safe_for_egress

logger = logging.getLogger(__name__)

# Approved Phase 1B Port Scope (Top common services)
DEFAULT_APPROVED_PORTS = [
    21, 22, 25, 53, 80, 110, 143, 445, 465, 587, 993, 995,
    1433, 1521, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 8888
]


async def scan_single_port(
    target_ip: str,
    port: int,
    semaphore: asyncio.Semaphore,
    timeout: float = 2.0
) -> Optional[Dict[str, Any]]:
    """
    Scans a single TCP port on a pre-validated target IP.
    Uses socket level connect to prevent DNS TOCTOU.
    """
    async with semaphore:
        try:
            connect_coro = asyncio.open_connection(target_ip, port)
            reader, writer = await asyncio.wait_for(connect_coro, timeout=timeout)
            writer.close()
            await writer.wait_closed()

            return {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "target_ip": target_ip,
                "observed_at": datetime.now(timezone.utc).isoformat()
            }
        except (asyncio.TimeoutError, OSError):
            return None
        except Exception as e:
            logger.debug(f"Port scan exception for {target_ip}:{port}: {e}")
            return None


async def scan_target_ports(
    target_ip: str,
    target_ports: Optional[List[int]] = None,
    timeout: float = 2.0,
    max_concurrency: int = 20
) -> List[Dict[str, Any]]:
    """
    Executes TCP port scan across approved target ports.
    Strictly validates egress safety before connecting.
    """
    if not is_ip_safe_for_egress(target_ip):
        logger.error(f"Egress Safety Gate Abort: Attempted port scan on unsafe IP '{target_ip}'")
        return []

    ports_to_scan = target_ports if target_ports else DEFAULT_APPROVED_PORTS

    # Enforce approved ports scope (prevent arbitrary port ranges)
    ports_to_scan = [p for p in ports_to_scan if p in DEFAULT_APPROVED_PORTS]

    semaphore = asyncio.Semaphore(max_concurrency)
    tasks = [
        scan_single_port(target_ip, port, semaphore, timeout=timeout)
        for port in ports_to_scan
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)
    open_ports = [r for r in results if isinstance(r, dict) and r is not None]

    return open_ports
