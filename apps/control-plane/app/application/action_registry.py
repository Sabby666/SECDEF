"""Phase 6 Action Registry & Allowlist Specification.

Defines allowable action types, risk classifications, approval requirements,
reversibility policies, parameter validation schemas, and state transitions.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional, List


class ActionRiskClass(str, Enum):
    CLASS_A_READ_ONLY = "CLASS_A_READ_ONLY"
    CLASS_B_LOW_RISK_REVERSIBLE = "CLASS_B_LOW_RISK_REVERSIBLE"
    CLASS_C_STATE_CHANGING = "CLASS_C_STATE_CHANGING"
    CLASS_D_EXTERNAL_SIDE_EFFECT = "CLASS_D_EXTERNAL_SIDE_EFFECT"
    CLASS_E_HIGH_RISK = "CLASS_E_HIGH_RISK"


class ActionExecutionState(str, Enum):
    PROPOSED = "PROPOSED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    ROLLBACK_PENDING = "ROLLBACK_PENDING"
    ROLLED_BACK = "ROLLED_BACK"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"


VALID_STATE_TRANSITIONS = {
    ActionExecutionState.PROPOSED: {
        ActionExecutionState.PENDING_APPROVAL,
        ActionExecutionState.APPROVED,
        ActionExecutionState.REJECTED,
        ActionExecutionState.CANCELLED,
        ActionExecutionState.EXPIRED
    },
    ActionExecutionState.PENDING_APPROVAL: {
        ActionExecutionState.APPROVED,
        ActionExecutionState.REJECTED,
        ActionExecutionState.CANCELLED,
        ActionExecutionState.EXPIRED
    },
    ActionExecutionState.APPROVED: {
        ActionExecutionState.QUEUED,
        ActionExecutionState.RUNNING,
        ActionExecutionState.CANCELLED
    },
    ActionExecutionState.QUEUED: {
        ActionExecutionState.RUNNING,
        ActionExecutionState.FAILED,
        ActionExecutionState.CANCELLED
    },
    ActionExecutionState.RUNNING: {
        ActionExecutionState.SUCCEEDED,
        ActionExecutionState.FAILED,
        ActionExecutionState.CANCELLED
    },
    ActionExecutionState.SUCCEEDED: {
        ActionExecutionState.VERIFYING,
        ActionExecutionState.VERIFIED,
        ActionExecutionState.ROLLBACK_PENDING
    },
    ActionExecutionState.VERIFYING: {
        ActionExecutionState.VERIFIED,
        ActionExecutionState.VERIFICATION_FAILED
    },
    ActionExecutionState.VERIFICATION_FAILED: {
        ActionExecutionState.ROLLBACK_PENDING,
        ActionExecutionState.FAILED
    },
    ActionExecutionState.ROLLBACK_PENDING: {
        ActionExecutionState.ROLLED_BACK,
        ActionExecutionState.ROLLBACK_FAILED
    },
    ActionExecutionState.REJECTED: set(),
    ActionExecutionState.FAILED: set(),
    ActionExecutionState.CANCELLED: set(),
    ActionExecutionState.EXPIRED: set(),
    ActionExecutionState.VERIFIED: {
        ActionExecutionState.ROLLBACK_PENDING
    },
    ActionExecutionState.ROLLED_BACK: set(),
    ActionExecutionState.ROLLBACK_FAILED: set(),
}


class RollbackSemantics(str, Enum):
    REVERSIBLE = "REVERSIBLE"
    PARTIALLY_REVERSIBLE = "PARTIALLY_REVERSIBLE"
    IRREVERSIBLE = "IRREVERSIBLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class ActionDefinition:
    action_type: str
    version: str
    target_type: str
    risk_class: ActionRiskClass
    requires_approval: bool
    is_reversible: bool
    rollback_action_type: Optional[str]
    verification_method: Optional[str]
    rollback_semantics: RollbackSemantics = RollbackSemantics.IRREVERSIBLE
    timeout_seconds: int = 30
    required_parameters: List[str] = field(default_factory=list)


ACTION_REGISTRY: Dict[str, ActionDefinition] = {
    # CLASS A — READ-ONLY
    "VERIFY_HTTP_ENDPOINT": ActionDefinition(
        action_type="VERIFY_HTTP_ENDPOINT",
        version="v1",
        target_type="SERVICE",
        risk_class=ActionRiskClass.CLASS_A_READ_ONLY,
        requires_approval=False,
        is_reversible=False,
        rollback_action_type=None,
        verification_method="HTTP_PROBE",
        rollback_semantics=RollbackSemantics.NOT_APPLICABLE,
        timeout_seconds=15,
        required_parameters=["url", "expected_status"]
    ),
    "VERIFY_DNS_RECORD": ActionDefinition(
        action_type="VERIFY_DNS_RECORD",
        version="v1",
        target_type="DOMAIN",
        risk_class=ActionRiskClass.CLASS_A_READ_ONLY,
        requires_approval=False,
        is_reversible=False,
        rollback_action_type=None,
        verification_method="DNS_LOOKUP",
        rollback_semantics=RollbackSemantics.NOT_APPLICABLE,
        timeout_seconds=10,
        required_parameters=["domain", "record_type"]
    ),
    "RECALCULATE_RISK": ActionDefinition(
        action_type="RECALCULATE_RISK",
        version="v1",
        target_type="ASSET",
        risk_class=ActionRiskClass.CLASS_A_READ_ONLY,
        requires_approval=False,
        is_reversible=False,
        rollback_action_type=None,
        verification_method="RISK_ENGINE_CHECK",
        rollback_semantics=RollbackSemantics.NOT_APPLICABLE,
        timeout_seconds=30,
        required_parameters=["asset_id"]
    ),

    # CLASS B — LOW-RISK REVERSIBLE
    "ACKNOWLEDGE_FINDING": ActionDefinition(
        action_type="ACKNOWLEDGE_FINDING",
        version="v1",
        target_type="FINDING",
        risk_class=ActionRiskClass.CLASS_B_LOW_RISK_REVERSIBLE,
        requires_approval=False,
        is_reversible=True,
        rollback_action_type="UNACKNOWLEDGE_FINDING",
        verification_method="FINDING_STATE_CHECK",
        rollback_semantics=RollbackSemantics.REVERSIBLE,
        timeout_seconds=10,
        required_parameters=["finding_id"]
    ),
    "UNACKNOWLEDGE_FINDING": ActionDefinition(
        action_type="UNACKNOWLEDGE_FINDING",
        version="v1",
        target_type="FINDING",
        risk_class=ActionRiskClass.CLASS_B_LOW_RISK_REVERSIBLE,
        requires_approval=False,
        is_reversible=True,
        rollback_action_type="ACKNOWLEDGE_FINDING",
        verification_method="FINDING_STATE_CHECK",
        rollback_semantics=RollbackSemantics.REVERSIBLE,
        timeout_seconds=10,
        required_parameters=["finding_id"]
    ),
    "CREATE_REMEDIATION_TASK": ActionDefinition(
        action_type="CREATE_REMEDIATION_TASK",
        version="v1",
        target_type="FINDING",
        risk_class=ActionRiskClass.CLASS_B_LOW_RISK_REVERSIBLE,
        requires_approval=False,
        is_reversible=True,
        rollback_action_type="DELETE_REMEDIATION_TASK",
        verification_method="TASK_EXISTS_CHECK",
        rollback_semantics=RollbackSemantics.REVERSIBLE,
        timeout_seconds=15,
        required_parameters=["finding_id", "title"]
    ),
    "DELETE_REMEDIATION_TASK": ActionDefinition(
        action_type="DELETE_REMEDIATION_TASK",
        version="v1",
        target_type="FINDING",
        risk_class=ActionRiskClass.CLASS_B_LOW_RISK_REVERSIBLE,
        requires_approval=False,
        is_reversible=False,
        rollback_action_type=None,
        verification_method="TASK_EXISTS_CHECK",
        rollback_semantics=RollbackSemantics.IRREVERSIBLE,
        timeout_seconds=15,
        required_parameters=["task_id"]
    ),
    "MARK_EXPECTED_STATE": ActionDefinition(
        action_type="MARK_EXPECTED_STATE",
        version="v1",
        target_type="SERVICE",
        risk_class=ActionRiskClass.CLASS_C_STATE_CHANGING,
        requires_approval=True,
        is_reversible=True,
        rollback_action_type="UNMARK_EXPECTED_STATE",
        verification_method="EXPECTED_STATE_CHECK",
        rollback_semantics=RollbackSemantics.REVERSIBLE,
        timeout_seconds=10,
        required_parameters=["asset_id", "reason"]
    ),
    "UNMARK_EXPECTED_STATE": ActionDefinition(
        action_type="UNMARK_EXPECTED_STATE",
        version="v1",
        target_type="SERVICE",
        risk_class=ActionRiskClass.CLASS_C_STATE_CHANGING,
        requires_approval=True,
        is_reversible=True,
        rollback_action_type="MARK_EXPECTED_STATE",
        verification_method="EXPECTED_STATE_CHECK",
        rollback_semantics=RollbackSemantics.REVERSIBLE,
        timeout_seconds=10,
        required_parameters=["asset_id"]
    ),

    # CLASS C — STATE-CHANGING
    "RESOLVE_FINDING": ActionDefinition(
        action_type="RESOLVE_FINDING",
        version="v1",
        target_type="FINDING",
        risk_class=ActionRiskClass.CLASS_C_STATE_CHANGING,
        requires_approval=True,
        is_reversible=True,
        rollback_action_type="REOPEN_FINDING",
        verification_method="SCAN_VERIFICATION_PROBE",
        rollback_semantics=RollbackSemantics.REVERSIBLE,
        timeout_seconds=20,
        required_parameters=["finding_id", "resolution_reason"]
    ),
    "REOPEN_FINDING": ActionDefinition(
        action_type="REOPEN_FINDING",
        version="v1",
        target_type="FINDING",
        risk_class=ActionRiskClass.CLASS_C_STATE_CHANGING,
        requires_approval=False,
        is_reversible=True,
        rollback_action_type="RESOLVE_FINDING",
        verification_method="FINDING_STATE_CHECK",
        rollback_semantics=RollbackSemantics.REVERSIBLE,
        timeout_seconds=10,
        required_parameters=["finding_id", "reopen_reason"]
    ),

    # CLASS D — EXTERNAL SIDE EFFECT
    "SEND_WEBHOOK": ActionDefinition(
        action_type="SEND_WEBHOOK",
        version="v1",
        target_type="INTEGRATION",
        risk_class=ActionRiskClass.CLASS_D_EXTERNAL_SIDE_EFFECT,
        requires_approval=True,
        is_reversible=False,
        rollback_action_type=None,
        verification_method="WEBHOOK_HTTP_RESPONSE",
        rollback_semantics=RollbackSemantics.IRREVERSIBLE,
        timeout_seconds=10,
        required_parameters=["webhook_url", "payload"]
    ),
    "CREATE_JIRA_TICKET": ActionDefinition(
        action_type="CREATE_JIRA_TICKET",
        version="v1",
        target_type="INTEGRATION",
        risk_class=ActionRiskClass.CLASS_D_EXTERNAL_SIDE_EFFECT,
        requires_approval=True,
        is_reversible=False,
        rollback_action_type=None,
        verification_method="JIRA_API_RESPONSE",
        rollback_semantics=RollbackSemantics.PARTIALLY_REVERSIBLE,
        timeout_seconds=15,
        required_parameters=["project_key", "summary", "description"]
    ),

    # CLASS E — HIGH-RISK (Requires mandatory explicit human approval)
    "TRIGGER_BOUNDED_VERIFICATION_SCAN": ActionDefinition(
        action_type="TRIGGER_BOUNDED_VERIFICATION_SCAN",
        version="v1",
        target_type="ASSET",
        risk_class=ActionRiskClass.CLASS_E_HIGH_RISK,
        requires_approval=True,
        is_reversible=False,
        rollback_action_type=None,
        verification_method="SCAN_JOB_COMPLETION",
        rollback_semantics=RollbackSemantics.NOT_APPLICABLE,
        timeout_seconds=120,
        required_parameters=["asset_id", "target_host", "port_list"]
    ),
}


def get_action_definition(action_type: str) -> Optional[ActionDefinition]:
    return ACTION_REGISTRY.get(action_type)
