"""Phase 5 AI Provider Base Abstraction and Security Controls."""
import logging
import re
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def redact_secrets(text: Optional[str]) -> str:
    """Sanitize secrets, API keys, tokens, and credentials from AI requests/context."""
    if not text:
        return ""
    # Redact Authorization headers, bearer tokens, API keys, password hashes, secrets
    patterns = [
        (r'(?i)(bearer\s+)[a-zA-Z0-9_\-\.]{10,}', r'\1[REDACTED]'),
        (r'(?i)(api[_\-]?key["\']?\s*[:=]\s*["\']?)[a-zA-Z0-9_\-\.]{10,}', r'\1[REDACTED]'),
        (r'(?i)(secret["\']?\s*[:=]\s*["\']?)[a-zA-Z0-9_\-\.]{10,}', r'\1[REDACTED]'),
        (r'(?i)(password[_\-]?hash["\']?\s*[:=]\s*["\']?)[^\s,}"\']+', r'\1[REDACTED]'),
        (r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', ''),  # Control characters
    ]
    cleaned = str(text)
    for pattern, repl in patterns:
        cleaned = re.sub(pattern, repl, cleaned)
    return cleaned


class AIProviderError(Exception):
    """Raised when an AI provider request fails."""
    pass


class BaseAIProvider:
    """Abstract Base Class for Phase 5 Model/Provider Adapters."""

    MAX_INPUT_CHARS: int = 50000  # Cap input context size (~12k tokens)
    MAX_OUTPUT_CHARS: int = 10000

    def __init__(self, name: str = "base_ai_provider", model_version: str = "v1", config: Optional[Dict[str, Any]] = None):
        self.name = name
        self.model_version = model_version
        self.config = config or {}

    def sanitize_input(self, text: str) -> str:
        """Redact secrets and truncate oversized input strings."""
        redacted = redact_secrets(text)
        return redacted[:self.MAX_INPUT_CHARS]

    async def generate_completion(
        self,
        query: str,
        context_text: str,
        conversation_history: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Generate structured AI assistance response. Must be overridden by subclasses."""
        raise NotImplementedError("Subclasses must implement generate_completion")

    async def generate_completion_with_retry(
        self,
        query: str,
        context_text: str,
        conversation_history: Optional[List[Dict[str, Any]]] = None,
        max_retries: int = 3
    ) -> Dict[str, Any]:
        """Attempt completion with bounded retry backoff up to max_retries."""
        last_exc: Optional[Exception] = None
        for attempt in range(max_retries + 1):
            try:
                return await self.generate_completion(
                    query=query,
                    context_text=context_text,
                    conversation_history=conversation_history
                )
            except Exception as exc:
                last_exc = exc
                logger.warning(
                    "AI provider %s completion attempt %d/%d failed: %s",
                    self.name, attempt + 1, max_retries + 1, str(exc)
                )
        raise AIProviderError(f"AI provider {self.name} failed after {max_retries + 1} attempts: {str(last_exc)}")

