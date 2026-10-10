"""Phase 5 Mock AI Provider Adapter.

Provides deterministic, evidence-grounded AI assistance without requiring external LLM API keys.
Constructs structured responses categorized into facts, inferences, uncertainties, recommendations, and evidence references.
"""
import logging
import re
from typing import Dict, Any, List, Optional
from app.application.ai_providers.base_provider import BaseAIProvider, redact_secrets, utc_now
from shared_contracts.enums import AIResponseClassification

logger = logging.getLogger(__name__)


class MockAIProvider(BaseAIProvider):
    """Deterministic, evidence-grounded local AI provider adapter for Phase 5."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(
            name="mock_asm_ai_provider",
            model_version="asm-reasoner-v1",
            config=config
        )

    async def generate_completion(
        self,
        query: str,
        context_text: str,
        conversation_history: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Parse query and authoritative context, producing structured evidence-grounded assistance."""
        sanitized_query = self.sanitize_input(query)
        sanitized_context = self.sanitize_input(context_text)

        # Extract facts from authoritative context lines
        facts: List[str] = []
        evidence_references: List[Dict[str, Any]] = []

        # Parse context lines starting with [FACT], [RISK], [EXPOSURE], [INTELLIGENCE], [FINDING], [CHANGE]
        for line in sanitized_context.split("\n"):
            line_str = line.strip()
            if line_str.startswith("[FACT]") or line_str.startswith("[RISK]") or line_str.startswith("[EXPOSURE]") or line_str.startswith("[INTELLIGENCE]") or line_str.startswith("[FINDING]") or line_str.startswith("[CHANGE]"):
                facts.append(line_str)
            elif line_str.startswith("[SOURCE]"):
                # Extract source ID / reference details
                parts = line_str.split("|")
                ref_dict = {"source": line_str}
                for p in parts:
                    if ":" in p:
                        k, v = p.split(":", 1)
                        ref_dict[k.strip().lower().replace(" ", "_")] = v.strip()
                evidence_references.append(ref_dict)

        inferences: List[str] = []
        uncertainties: List[str] = []
        recommendations: List[str] = []
        action_proposals: List[Dict[str, Any]] = []

        q_lower = sanitized_query.lower()

        if "asset" in q_lower or "ip" in q_lower or "domain" in q_lower or "server" in q_lower or "host" in q_lower or "ubuntu" in q_lower:
            if facts:
                inferences.append("Observed asset assets are configured within active organizational boundaries.")
            else:
                uncertainties.append("ASM currently has no authoritative observation for the requested asset.")
            recommendations.append("Verify asset ownership and environment criticality with the asset owner.")

        elif "risk" in q_lower:
            inferences.append("Contextual risk scores are calculated by Phase 1F RiskEngineService based on asset criticality and active exposures.")
            uncertainties.append("No active exploit validation has been executed against these assets.")
            recommendations.append("Prioritize remediation for internet-facing critical environment assets.")

        elif "exposure" in q_lower or "port" in q_lower:
            inferences.append("Exposure conditions represent verified internet-reachable services.")
            uncertainties.append("Port reachability does not automatically imply vulnerability exploitation.")
            recommendations.append("Review whether exposed admin interfaces or non-standard ports should be restricted.")

        elif "vulnerability" in q_lower or "cve" in q_lower or "intelligence" in q_lower:
            inferences.append("Vulnerability correlations match observed service banners against published CVE affected version ranges.")
            uncertainties.append("Observed version banners may be backported or patched by Linux distribution vendors.")
            recommendations.append("Verify installed package version via package manager or internal audit before declaring confirmed vulnerability.")

        else:
            inferences.append("General security investigation query evaluated over tenant-scoped authoritative ASM context.")
            uncertainties.append("Detailed investigation requires specifying target asset or finding identifiers.")
            recommendations.append("Query specific asset, exposure, or finding details for deeper analysis.")

        # If facts list is empty
        if not facts:
            facts.append("No specific matching facts were found in authoritative ASM storage for this query.")
            uncertainties.append("ASM does not currently have sufficient evidence to establish additional conclusions.")

        answer_summary = (
            f"Based on authoritative ASM context ({len(facts)} facts retrieved):\n"
            f"- Primary Inferences: {inferences[0] if inferences else 'None'}\n"
            f"- Caveats: {uncertainties[0] if uncertainties else 'None'}\n"
            f"- Recommended Action: {recommendations[0] if recommendations else 'None'}"
        )

        return {
            "answer": answer_summary,
            "facts": facts,
            "inferences": inferences,
            "uncertainties": uncertainties,
            "recommendations": recommendations,
            "evidence_references": evidence_references[:20],
            "action_proposals": action_proposals,
            "classification": AIResponseClassification.AI_GENERATED_ASSISTANCE.value,
            "model_metadata": {
                "provider_name": self.name,
                "model_version": self.model_version,
                "generated_at": utc_now().isoformat(),
                "facts_count": len(facts),
                "evidence_count": len(evidence_references)
            }
        }
