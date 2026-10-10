"""Phase 5 AI Assistance Service.

Coordinates secure context assembly, read-only tool execution, model provider invocation,
structured output validation, conversation persistence, tenant isolation, and audit logging.
"""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update

from app.infrastructure.db.models import (
    generate_uuid, Organization, User, AIConversation, AIMessage
)
from app.application.secure_context_builder import SecureContextBuilder
from app.application.ai_tools import AIToolRegistry, AIToolExecutionError
from app.application.ai_providers.base_provider import BaseAIProvider, redact_secrets
from app.application.ai_providers.mock_provider import MockAIProvider
from app.application.audit_service import AuditService
from shared_contracts.enums import AIMessageSender, AIResponseClassification

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AIService:
    """Core application service managing AI-assisted security investigation."""

    def __init__(self, db: AsyncSession, provider: Optional[BaseAIProvider] = None):
        self.db = db
        self.provider = provider or MockAIProvider()
        self.context_builder = SecureContextBuilder(db)
        self.tool_registry = AIToolRegistry(db)

    async def create_conversation(self, org_id: str, user_id: str, title: Optional[str] = None) -> AIConversation:
        """Create a tenant-isolated AI conversation session."""
        conv = AIConversation(
            id=generate_uuid(),
            org_id=org_id,
            user_id=user_id,
            title=title or "Security Investigation",
            created_at=utc_now(),
            updated_at=utc_now()
        )
        self.db.add(conv)
        await self.db.flush()
        await self.db.commit()
        return conv

    async def list_conversations(self, org_id: str, user_id: Optional[str] = None, limit: int = 50, offset: int = 0) -> List[AIConversation]:
        """Fetch tenant-scoped conversation threads."""
        stmt = select(AIConversation).where(AIConversation.org_id == org_id)
        if user_id:
            stmt = stmt.where(AIConversation.user_id == user_id)
        stmt = stmt.order_by(AIConversation.updated_at.desc()).limit(limit).offset(offset)
        res = await self.db.execute(stmt)
        return res.scalars().all()

    async def get_conversation(self, org_id: str, conversation_id: str) -> Optional[AIConversation]:
        """Fetch tenant-scoped conversation thread by ID."""
        stmt = select(AIConversation).where(
            AIConversation.id == conversation_id,
            AIConversation.org_id == org_id
        )
        res = await self.db.execute(stmt)
        return res.scalars().first()

    async def get_conversation_messages(self, org_id: str, conversation_id: str) -> List[AIMessage]:
        """Fetch messages within a tenant conversation thread."""
        stmt = select(AIMessage).where(
            AIMessage.conversation_id == conversation_id,
            AIMessage.org_id == org_id
        ).order_by(AIMessage.created_at.asc())
        res = await self.db.execute(stmt)
        return res.scalars().all()

    async def process_query(
        self,
        org_id: str,
        user_id: str,
        query: str,
        conversation_id: Optional[str] = None,
        target_asset_id: Optional[str] = None,
        target_exposure_id: Optional[str] = None,
        target_finding_id: Optional[str] = None,
        target_correlation_id: Optional[str] = None,
        actor_ip: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """Process natural language security investigation query with secure context assembly."""
        # 1. Fetch or create conversation
        conv: Optional[AIConversation] = None
        if conversation_id:
            conv = await self.get_conversation(org_id, conversation_id)
            if not conv:
                raise ValueError(f"Conversation {conversation_id} not found under tenant {org_id}")
        else:
            conv = await self.create_conversation(org_id, user_id, title=f"Query: {query[:30]}")

        # 2. Build secure context with prompt injection defenses
        context_text = await self.context_builder.build_context_for_query(
            org_id=org_id,
            user_id=user_id,
            query=query,
            target_asset_id=target_asset_id,
            target_exposure_id=target_exposure_id,
            target_finding_id=target_finding_id,
            target_correlation_id=target_correlation_id
        )

        # 3. Store user message in conversation
        user_msg = AIMessage(
            id=generate_uuid(),
            org_id=org_id,
            conversation_id=conv.id,
            sender_type=AIMessageSender.USER.value,
            content=query,
            provenance={"user_id": user_id, "timestamp": utc_now().isoformat()},
            created_at=utc_now()
        )
        self.db.add(user_msg)

        # 4. Generate AI response via Provider adapter
        try:
            raw_response = await self.provider.generate_completion_with_retry(
                query=query,
                context_text=context_text,
                conversation_history=[]
            )
        except Exception as exc:
            logger.exception("AI provider request failed for tenant %s: %s", org_id, str(exc))
            # Fallback fail-closed response
            raw_response = {
                "answer": f"AI_REQUEST_FAILED: The AI assistance layer is currently unavailable ({str(exc)}). Core ASM security operations remain fully operational.",
                "facts": [],
                "inferences": [],
                "uncertainties": ["AI provider processing failed."],
                "recommendations": ["Review authoritative ASM records directly in the dashboard."],
                "evidence_references": [],
                "action_proposals": [],
                "classification": AIResponseClassification.AI_GENERATED_ASSISTANCE.value,
                "model_metadata": {"error": str(exc), "provider": self.provider.name}
            }

        # 5. Schema validation & mandatory classification enforcement
        classification = raw_response.get("classification", AIResponseClassification.AI_GENERATED_ASSISTANCE.value)
        if classification != AIResponseClassification.AI_GENERATED_ASSISTANCE.value:
            classification = AIResponseClassification.AI_GENERATED_ASSISTANCE.value

        # Filter and validate evidence references to enforce tenant isolation & integrity
        raw_evidence = raw_response.get("evidence_references", [])
        validated_evidence: List[Dict[str, Any]] = []
        for ref in raw_evidence:
            if isinstance(ref, dict):
                ref_org = ref.get("org") or ref.get("org_id")
                # Exclude evidence references explicitly belonging to another tenant
                if ref_org and ref_org != org_id:
                    logger.warning("Excluded cross-tenant evidence reference from AI output for org %s: %s", org_id, ref)
                    continue
                validated_evidence.append(ref)

        structured_output = {
            "answer": raw_response.get("answer", ""),
            "facts": raw_response.get("facts", []),
            "inferences": raw_response.get("inferences", []),
            "uncertainties": raw_response.get("uncertainties", []),
            "recommendations": raw_response.get("recommendations", []),
            "evidence_references": validated_evidence,
            "action_proposals": raw_response.get("action_proposals", []),
            "classification": classification,
            "model_metadata": raw_response.get("model_metadata", {})
        }

        # 6. Store assistant message in conversation
        assistant_msg = AIMessage(
            id=generate_uuid(),
            org_id=org_id,
            conversation_id=conv.id,
            sender_type=AIMessageSender.ASSISTANT.value,
            content=structured_output["answer"],
            structured_data=structured_output,
            provenance={
                "org_id": org_id,
                "user_id": user_id,
                "conversation_id": conv.id,
                "provider": self.provider.name,
                "model_version": self.provider.model_version,
                "timestamp": utc_now().isoformat()
            },
            created_at=utc_now()
        )
        self.db.add(assistant_msg)

        conv.updated_at = utc_now()
        await self.db.commit()

        # 7. Audit log event
        AuditService.log_event(
            db_session=self.db,
            event_type="ai_request_completed",
            resource_type="ai_conversation",
            ip_address=actor_ip,
            org_id=org_id,
            actor_id=user_id,
            resource_id=conv.id,
            details={
                "conversation_id": conv.id,
                "provider_name": self.provider.name,
                "classification": classification,
                "facts_count": len(structured_output["facts"])
            }
        )

        return {
            "conversation_id": conv.id,
            "message_id": assistant_msg.id,
            "response": structured_output
        }
