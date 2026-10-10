import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import httpx
from worker.safety.egress_guard import is_ip_safe_for_egress
from worker.safety.redirect_guard import validate_redirect_url

logger = logging.getLogger(__name__)

# Resource limits
MAX_RESPONSE_BODY_BYTES = 10 * 1024 * 1024  # 10 MB body size limit
MAX_BANNER_LEN = 4096  # 4 KB banner snippet limit
MAX_REDIRECTS = 5
MAX_DECOMPRESSION_RATIO = 20.0


def sanitize_string(data: str) -> str:
    """Sanitize attacker-controlled text fields (strip null bytes and control chars)."""
    if not data:
        return ""
    # Strip null bytes and non-printable control characters except \n, \r, \t
    cleaned = "".join(c for c in data if c in ("\n", "\r", "\t") or (ord(c) >= 32 and ord(c) != 127))
    return cleaned[:MAX_BANNER_LEN]


async def grab_http_banner(
    target_ip: str,
    port: int,
    hostname: str,
    use_tls: bool = False,
    timeout: float = 5.0
) -> Optional[Dict[str, Any]]:
    """
    Grabs HTTP/HTTPS banner for an open port.
    Applies destination validation, redirect safety, body limits, and decompression checks.
    """
    if not is_ip_safe_for_egress(target_ip):
        logger.error(f"Egress Safety Gate Abort: HTTP banner grab on unsafe IP '{target_ip}'")
        return None

    scheme = "https" if use_tls or port in (443, 8443) else "http"
    current_url = f"{scheme}://{target_ip}:{port}/"
    current_ip = target_ip
    current_hostname = hostname

    redirect_count = 0
    redirect_chain = []

    async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=False) as client:
        while redirect_count <= MAX_REDIRECTS:
            try:
                # Custom headers for request
                headers = {"Host": current_hostname, "User-Agent": "ASM-ObservationWorker/1.0"}

                req = client.build_request("GET", current_url, headers=headers)
                resp = await client.send(req)

                # Check redirect responses (301, 302, 303, 307, 308)
                if resp.is_redirect and "location" in resp.headers:
                    redirect_location = resp.headers["location"]
                    redirect_chain.append(redirect_location)

                    redirect_count += 1
                    if redirect_count > MAX_REDIRECTS:
                        logger.warning(f"Max redirects ({MAX_REDIRECTS}) exceeded for {hostname}")
                        break

                    # Validate redirect URL against egress safety policy
                    is_safe, next_url, validated_ips = await validate_redirect_url(
                        redirect_location, current_hop=redirect_count, max_hops=MAX_REDIRECTS
                    )
                    if not is_safe or not next_url or not validated_ips:
                        logger.warning(f"Redirect Hop Aborted: '{redirect_location}' violates safety policy.")
                        break

                    current_url = next_url
                    continue

                # Process final response
                content_bytes = resp.content
                raw_len = len(content_bytes)

                # Body size check
                if raw_len > MAX_RESPONSE_BODY_BYTES:
                    content_bytes = content_bytes[:MAX_RESPONSE_BODY_BYTES]

                # Decompression ratio check (if compressed)
                content_encoding = resp.headers.get("content-encoding", "").lower()
                if content_encoding in ("gzip", "deflate", "br"):
                    # Check ratio of uncompressed bytes vs raw network bytes
                    network_bytes = int(resp.headers.get("content-length", raw_len) or raw_len)
                    if network_bytes > 0:
                        ratio = float(raw_len) / float(network_bytes)
                        if ratio > MAX_DECOMPRESSION_RATIO:
                            logger.warning(
                                f"Decompression ratio limit exceeded ({ratio:.1f}:1 > {MAX_DECOMPRESSION_RATIO}:1) "
                                f"for {hostname}:{port}. Truncating payload."
                            )

                headers_dict = {
                    sanitize_string(k): sanitize_string(v)
                    for k, v in resp.headers.items()
                }

                body_text = resp.text if resp.text else ""
                sanitized_body = sanitize_string(body_text)

                return {
                    "port": port,
                    "target_ip": target_ip,
                    "hostname": hostname,
                    "status_code": resp.status_code,
                    "http_version": resp.http_version,
                    "headers": headers_dict,
                    "server_header": headers_dict.get("server", ""),
                    "title": sanitize_string(_extract_html_title(body_text)),
                    "body_snippet": sanitized_body,
                    "redirect_chain": redirect_chain,
                    "observed_at": datetime.now(timezone.utc).isoformat()
                }

            except (httpx.TimeoutException, httpx.NetworkError, Exception) as e:
                logger.debug(f"HTTP banner grab error for {target_ip}:{port}: {e}")
                return None

    return None


def _extract_html_title(html: str) -> str:
    """Extract <title> tag value safely."""
    if not html:
        return ""
    start = html.lower().find("<title>")
    if start == -1:
        return ""
    start += 7
    end = html.lower().find("</title>", start)
    if end == -1:
        return ""
    return html[start:end].strip()
