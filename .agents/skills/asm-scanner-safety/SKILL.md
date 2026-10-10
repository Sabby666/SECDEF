---
name: asm-scanner-safety
description: ASM Scanner Safety & Worker Isolation Guardrails. Enforces egress guard IP blocking, DNS TOCTOU rebinding defense, redirect hop limits, response body limits, worker process isolation, and HMAC job verification for Attack Surface Monitor.
---

# ASM Scanner Safety & Worker Isolation Guardrails (`asm-scanner-safety`)

## Purpose
This skill enforces network safety, SSRF protection, resource exhaustion limits, and process isolation for the Attack Surface Monitor (ASM) scanner worker framework (`apps/scanner-worker`).

## Mandatory Scanner Safety Invariants

### 1. Egress Guard & IP Address Blocking (`egress_guard.py`)
The scanner MUST validate all target IP addresses prior to initiating socket connections. The following IP space is STRICTLY BLOCKED:
- **Private IPv4**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- **Loopback**: `127.0.0.0/8`
- **Link-Local / Cloud Metadata**: `169.254.0.0/16` (including `169.254.169.254`)
- **IPv4-Mapped IPv6**: `::ffff:0:0/96`
- **Broadcast & Documentation**: `0.0.0.0/8`, `240.0.0.0/4`, `192.0.2.0/24`, `198.51.100.0/24`

### 2. DNS Rebinding / TOCTOU Protection (`dns_resolver.py`)
- **Resolve → Validate → Connect**: The scanner MUST resolve the target domain name to IP addresses, validate that EVERY resolved IP address is safe according to the egress guard, and connect directly to the validated IP address using the resolved IP as the socket target.
- **Mixed IP Rejection**: If a target domain resolves to a mix of public and private/internal IP addresses, the scan job MUST be aborted immediately.

### 3. Redirect Safety & Resource Limits
- **Redirect Hop Limits**: HTTP probe requests MUST follow a maximum of 5 redirects. Destination IPs MUST be re-validated through `egress_guard` on EVERY redirect hop.
- **Response Body Limit**: Max HTTP response body size is **10MB**. Oversized responses MUST be truncated.
- **Decompression Limit**: Max decompression ratio is **20:1** (zip bomb guard).
- **Socket & Execution Timeouts**: Individual socket connection timeout is **5s**; total job execution timeout is strictly bounded.
- **Ingestion Payload Limit**: Max scan ingestion payload size is **50MB**.

### 4. Worker Process Isolation & HMAC Provenance
- **Zero Database / Auth Imports**: Scanner worker code (`apps/scanner-worker`) MUST run in process isolation with ZERO imports from control-plane database models (`app.infrastructure.db`) or auth modules (`app.core.security`).
- **Signed ARQ Worker Results**: Worker job payloads and results MUST be verified using HMAC-SHA256 nonces to prevent replay attacks and unauthenticated job injection.
- **Untrusted Input**: All scanner outputs, HTTP headers, banners, and DNS responses MUST be treated as untrusted data and sanitized prior to control-plane ingestion.
- **NO Autonomous Exploitation**: The scanner is an exposure intelligence probe. Active vulnerability exploitation, fuzzing, or destructive payload injection is STRICTLY PROHIBITED.
