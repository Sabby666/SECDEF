import hmac
import hashlib
import json
import socket
import time
import urllib.parse
import httpx
from typing import Dict, Any, Tuple, Optional
from worker.safety.egress_guard import is_ip_safe_for_egress


class WebhookDeliveryService:
    """Phase 1G: Secure Webhook Delivery Engine with SSRF, Redirect Blocking, DNS Rebinding, and HMAC Replay protections."""

    MAX_PAYLOAD_SIZE_BYTES = 1 * 1024 * 1024  # 1MB max payload size
    REQUEST_TIMEOUT_SECONDS = 5.0
    MAX_TIMESTAMP_AGE_SECONDS = 300  # 5 minutes replay window

    @staticmethod
    def validate_url_and_resolve(url: str) -> Tuple[str, str, int]:
        """
        Validate URL syntax, resolve destination hostname to IP address,
        and check egress safety.

        Returns (host, resolved_ip, port).
        Raises ValueError if URL is invalid or target IP is restricted.
        """
        if not url or not isinstance(url, str):
            raise ValueError("Invalid URL: must be a non-empty string")

        parsed = urllib.parse.urlparse(url.strip())
        if parsed.scheme not in ["http", "https"]:
            raise ValueError(f"Invalid URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are allowed.")

        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Invalid URL: missing hostname")

        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # DNS Resolution prior to connection
        try:
            addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise ValueError(f"Failed to resolve Webhook destination host '{hostname}': {e}")

        if not addr_info:
            raise ValueError(f"Could not resolve host '{hostname}'")

        # Verify all resolved IPs against Egress Guard (prevent DNS rebinding with mixed safe/unsafe IPs)
        resolved_ips = list(set([info[4][0] for info in addr_info]))
        for resolved_ip in resolved_ips:
            if not is_ip_safe_for_egress(resolved_ip):
                raise ValueError(
                    f"Destination Webhook URL resolves to restricted IP address '{resolved_ip}'. "
                    f"Access to private/internal networks is strictly prohibited."
                )

        # Primary resolved IP
        primary_ip = resolved_ips[0]
        return hostname, primary_ip, port

    @classmethod
    def sign_payload(cls, payload_bytes: bytes, secret: str, timestamp: int) -> str:
        """Compute HMAC-SHA256 signature over 'timestamp.payload_bytes' for payload verification."""
        signed_data = f"{timestamp}.".encode('utf-8') + payload_bytes
        digest = hmac.new(secret.encode('utf-8'), signed_data, hashlib.sha256).hexdigest()
        return f"sha256={digest}"

    @classmethod
    def verify_signature(
        cls,
        payload_bytes: bytes,
        timestamp_str: str,
        signature_header: str,
        secret: str,
        max_age_seconds: int = MAX_TIMESTAMP_AGE_SECONDS
    ) -> bool:
        """
        Constant-time HMAC verification with timestamp replay protection.
        Returns True if signature matches and timestamp is within max_age_seconds.
        """
        if not timestamp_str or not signature_header or not secret:
            return False

        try:
            timestamp = int(timestamp_str)
        except ValueError:
            return False

        current_time = int(time.time())
        # Replay window check
        if abs(current_time - timestamp) > max_age_seconds:
            return False

        expected_sig = cls.sign_payload(payload_bytes, secret, timestamp)
        # Constant-time comparison to mitigate timing attacks
        return hmac.compare_digest(expected_sig, signature_header)

    @classmethod
    def deliver_webhook(
        cls,
        url: str,
        payload: Dict[str, Any],
        signing_secret: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Tuple[bool, int, str]:
        """
        Deliver a webhook payload securely with redirect blocking and DNS rebinding defense.

        Returns (success: bool, response_code: int, message_or_error: str).
        Delivery failure will NEVER raise an unhandled exception or alter security state.
        """
        try:
            hostname, primary_ip, port = cls.validate_url_and_resolve(url)

            payload_bytes = json.dumps(payload, default=str).encode('utf-8')
            if len(payload_bytes) > cls.MAX_PAYLOAD_SIZE_BYTES:
                return False, 413, f"Payload size ({len(payload_bytes)} bytes) exceeds maximum limit of 1MB."

            current_timestamp = int(time.time())
            req_headers = {
                "Content-Type": "application/json",
                "User-Agent": "ASM-Webhook-Notifier/1.0",
                "Host": hostname,
                "X-ASM-Timestamp": str(current_timestamp)
            }
            if headers:
                req_headers.update(headers)

            if signing_secret:
                req_headers["X-ASM-Signature"] = cls.sign_payload(payload_bytes, signing_secret, current_timestamp)

            parsed = urllib.parse.urlparse(url)
            # Re-construct URL targeting validated IP to prevent TOCTOU DNS rebinding
            target_url = urllib.parse.urlunparse((
                parsed.scheme,
                f"{primary_ip}:{port}",
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))

            # CRITICAL: follow_redirects=False to prevent HTTP Redirect SSRF attacks
            with httpx.Client(timeout=cls.REQUEST_TIMEOUT_SECONDS, follow_redirects=False, verify=True) as client:
                response = client.post(target_url, content=payload_bytes, headers=req_headers)

                # Explicitly detect and reject HTTP Redirect attempts (301, 302, 303, 307, 308)
                if response.status_code in [301, 302, 303, 307, 308]:
                    return False, response.status_code, (
                        f"Webhook delivery failed: HTTP redirects ({response.status_code}) are strictly "
                        f"disabled to prevent SSRF bypass attacks."
                    )

                if response.is_success:
                    return True, response.status_code, "Delivered successfully"
                else:
                    return False, response.status_code, f"HTTP Error {response.status_code}: {response.text[:200]}"

        except ValueError as ve:
            return False, 400, str(ve)
        except httpx.TimeoutException:
            return False, 408, "Webhook connection timed out after 5.0s"
        except Exception as ex:
            return False, 500, f"Webhook delivery failure: {str(ex)[:200]}"
