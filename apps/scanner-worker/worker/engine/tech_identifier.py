import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Rule-based technology signature definitions
TECH_SIGNATURES = [
    {"name": "Nginx", "category": "Web Server", "header": "server", "pattern": "nginx"},
    {"name": "Apache", "category": "Web Server", "header": "server", "pattern": "apache"},
    {"name": "Cloudflare", "category": "CDN / WAF", "header": "server", "pattern": "cloudflare"},
    {"name": "IIS", "category": "Web Server", "header": "server", "pattern": "microsoft-iis"},
    {"name": "Express", "category": "Web Framework", "header": "x-powered-by", "pattern": "express"},
    {"name": "PHP", "category": "Programming Language", "header": "x-powered-by", "pattern": "php"},
    {"name": "ASP.NET", "category": "Web Framework", "header": "x-powered-by", "pattern": "asp.net"},
    {"name": "Next.js", "category": "Web Framework", "body": "__next"},
    {"name": "React", "category": "Frontend Framework", "body": "react"},
    {"name": "WordPress", "category": "CMS", "body": "wp-content"},
    {"name": "Drupal", "category": "CMS", "body": "drupal"},
]


def identify_technologies(
    headers: Dict[str, str],
    body_snippet: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Rule-based, deterministic technology identification.
    Pure pattern matching over HTTP headers and body snippet.
    Non-executing, zero remote code execution.
    """
    detected = []

    headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
    body_lower = (body_snippet or "").lower()

    for sig in TECH_SIGNATURES:
        name = sig["name"]
        category = sig["category"]
        match_found = False

        if "header" in sig:
            header_key = sig["header"]
            pattern = sig["pattern"]
            if header_key in headers_lower and pattern in headers_lower[header_key]:
                match_found = True

        if not match_found and "body" in sig:
            pattern = sig["body"]
            if pattern in body_lower:
                match_found = True

        if match_found:
            detected.append({
                "name": name,
                "category": category,
                "confidence": 1.0,
                "evidence_type": "rule_pattern"
            })

    return detected
