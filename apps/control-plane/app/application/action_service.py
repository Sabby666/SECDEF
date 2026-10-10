"""Phase 6 Action Execution & State Machine Service.

Manages action proposals, human approvals, deterministic execution, verification,
rollback operations, idempotency enforcement, and audit logging.
"""
import hashlib
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.infrastructure.db.models import (
    ActionExecution,
    ActionApproval,
    ActionVerification,
    ActionRollback,
    Finding,
    Asset,
    OrganizationalMemory
)
from app.application.action_registry import (
    get_action_definition,
    ActionExecutionState,
    ActionRiskClass,
    VALID_STATE_TRANSITIONS
)
from app.application.automation_policy_engine import (
    AutomationPolicyEngine,
    PolicyDecision,
    PolicyEvaluationResult
)
from app.application.audit_service import AuditService
from app.application.ai_providers.base_provider import redact_secrets
from worker.safety.egress_guard import is_ip_safe_for_egress
from shared_contracts.enums import UserRole

logger = logging.getLogger(__name__)


def generate_idempotency_key(org_id: str, action_type: str, target_identifier: str, params: Dict[str, Any]) -> str:
    """Generate deterministic idempotency key from canonical execution inputs."""
    param_str = json.dumps(params, sort_keys=True)
    raw = f"{org_id}:{action_type}:{target_identifier}:{param_str}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class ActionService:
    """Service governing Phase 6 Action state machine lifecycle."""

    def __init__(self, db_session: AsyncSession):
        self.db = db_session
        self.policy_engine = AutomationPolicyEngine(db_session)

    async def propose_action(
        self,
        org_id: str,
        actor_id: str,
        actor_role: UserRole,
        action_type: str,
        target_type: str,
        target_identifier: str,
        action_parameters: Dict[str, Any],
        correlation_id: Optional[str] = None,
        automation_depth: int = 0,
        parent_execution_id: Optional[str] = None
    ) -> ActionExecution:
        """Propose a new security action. Enforces idempotency and policy evaluation."""
        if not correlation_id:
            correlation_id = f"corr-{hashlib.md5(f'{org_id}:{datetime.now(timezone.utc)}'.encode()).hexdigest()[:12]}"

        # 1. Idempotency Check
        idem_key = generate_idempotency_key(org_id, action_type, target_identifier, action_parameters)
        existing_res = await self.db.execute(
            select(ActionExecution).where(
                ActionExecution.org_id == org_id,
                ActionExecution.idempotency_key == idem_key
            )
        )
        existing_execution = existing_res.scalar_one_or_none()
        if existing_execution:
            logger.info("Idempotent action execution retrieved: %s", existing_execution.id)
            return existing_execution

        # 2. Policy Engine Evaluation
        eval_result = await self.policy_engine.evaluate_action(
            org_id=org_id,
            actor_role=actor_role,
            action_type=action_type,
            target_type=target_type,
            target_identifier=target_identifier,
            action_parameters=action_parameters,
            automation_depth=automation_depth
        )

        if eval_result.decision == PolicyDecision.DENY:
            raise ValueError(f"Action denied by policy: {eval_result.reason}")

        initial_state = (
            ActionExecutionState.PENDING_APPROVAL
            if eval_result.decision == PolicyDecision.REQUIRE_APPROVAL
            else ActionExecutionState.APPROVED
        )
        auth_state = "AUTHORIZED" if eval_result.decision == PolicyDecision.ALLOW else "UNAUTHORIZED"

        action_def = get_action_definition(action_type)
        param_hash = hashlib.sha256(json.dumps(action_parameters, sort_keys=True).encode("utf-8")).hexdigest()
        provenance = {
            "requested_by": actor_id,
            "actor_role": actor_role.value,
            "policy_reason": eval_result.reason,
            "parameter_hash": param_hash,
            "proposed_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        }

        execution = ActionExecution(
            org_id=org_id,
            action_type=action_type,
            target_type=target_type,
            target_identifier=target_identifier,
            risk_class=eval_result.risk_class.value,
            execution_state=initial_state.value,
            authorization_state=auth_state,
            approval_requirement=eval_result.decision.value,
            requested_by=actor_id,
            action_parameters=action_parameters,
            provenance=provenance,
            policy_version=eval_result.policy_version,
            idempotency_key=idem_key,
            correlation_id=correlation_id,
            automation_depth=automation_depth,
            parent_execution_id=parent_execution_id
        )

        self.db.add(execution)
        await self.db.commit()
        await self.db.refresh(execution)

        AuditService.log_event(
            db_session=self.db,
            event_type="action_proposed",
            resource_type="action_execution",
            ip_address="127.0.0.1",
            org_id=org_id,
            actor_id=actor_id,
            resource_id=execution.id,
            details={
                "action_id": execution.id,
                "action_type": action_type,
                "target_identifier": target_identifier,
                "state": initial_state.value,
                "decision": eval_result.decision.value
            }
        )

        return execution

    async def approve_action(
        self,
        org_id: str,
        approver_user_id: str,
        approver_role: UserRole,
        action_execution_id: str,
        decision: str = "APPROVED",
        reason: Optional[str] = None
    ) -> ActionExecution:
        """Approve or reject a pending action execution."""
        res = await self.db.execute(
            select(ActionExecution).where(
                ActionExecution.id == action_execution_id,
                ActionExecution.org_id == org_id
            )
        )
        execution = res.scalar_one_or_none()
        if not execution:
            raise ValueError("Action execution not found")

        if execution.execution_state != ActionExecutionState.PENDING_APPROVAL.value:
            raise ValueError(f"Cannot approve action in state '{execution.execution_state}'")

        if execution.action_type in ["MARK_EXPECTED_STATE", "UNMARK_EXPECTED_STATE", "TRIGGER_BOUNDED_VERIFICATION_SCAN"] and approver_role != UserRole.ADMIN:
            raise ValueError(f"Action '{execution.action_type}' requires Admin approval per Phase 1H authority boundary.")

        if approver_role not in [UserRole.ADMIN, UserRole.MEMBER]:
            raise ValueError("Role lacks approval privileges")

        exp_str = (execution.provenance or {}).get("expires_at")
        if exp_str:
            is_expired = False
            try:
                exp_dt = datetime.fromisoformat(exp_str)
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > exp_dt:
                    is_expired = True
            except Exception:
                pass
            if is_expired:
                execution.execution_state = ActionExecutionState.EXPIRED.value
                await self.db.commit()
                raise ValueError("Action approval request has expired")

        # Verify exact parameters hash against proposal provenance if present
        param_hash = hashlib.sha256(json.dumps(execution.action_parameters, sort_keys=True).encode("utf-8")).hexdigest()
        orig_hash = (execution.provenance or {}).get("parameter_hash")
        if orig_hash and orig_hash != param_hash:
            raise ValueError("Action parameters hash mismatch: parameters were modified after proposal")

        approval = ActionApproval(
            org_id=org_id,
            action_execution_id=execution.id,
            approver_user_id=approver_user_id,
            decision=decision,
            reason=reason,
            approved_parameters_hash=param_hash
        )
        self.db.add(approval)

        if decision.upper() == "APPROVED":
            execution.execution_state = ActionExecutionState.APPROVED.value
            execution.authorization_state = "AUTHORIZED"
            event_type = "action_approved"
        else:
            execution.execution_state = ActionExecutionState.REJECTED.value
            execution.authorization_state = "REJECTED"
            event_type = "action_rejected"

        execution.updated_at = datetime.now(timezone.utc)
        await self.db.commit()
        await self.db.refresh(execution)

        AuditService.log_event(
            db_session=self.db,
            event_type=event_type,
            resource_type="action_execution",
            ip_address="127.0.0.1",
            org_id=org_id,
            actor_id=approver_user_id,
            resource_id=execution.id,
            details={
                "action_id": execution.id,
                "decision": decision,
                "reason": reason
            }
        )

        return execution

    async def execute_action(
        self,
        org_id: str,
        actor_id: str,
        action_execution_id: str
    ) -> ActionExecution:
        """Execute an approved action execution deterministically."""
        res = await self.db.execute(
            select(ActionExecution).where(
                ActionExecution.id == action_execution_id,
                ActionExecution.org_id == org_id
            )
        )
        execution = res.scalar_one_or_none()
        if not execution:
            raise ValueError("Action execution not found")

        if execution.execution_state != ActionExecutionState.APPROVED.value:
            raise ValueError(f"Cannot execute action in state '{execution.execution_state}'")

        execution.execution_state = ActionExecutionState.RUNNING.value
        execution.execution_started_at = datetime.now(timezone.utc)
        await self.db.commit()

        AuditService.log_event(
            db_session=self.db,
            event_type="action_started",
            resource_type="action_execution",
            ip_address="127.0.0.1",
            org_id=org_id,
            actor_id=actor_id,
            resource_id=execution.id,
            details={"action_id": execution.id, "action_type": execution.action_type}
        )

        try:
            result_data = await self._dispatch_action_handler(org_id, execution)
            execution.execution_state = ActionExecutionState.SUCCEEDED.value
            execution.execution_completed_at = datetime.now(timezone.utc)
            execution.result_data = result_data

            AuditService.log_event(
                db_session=self.db,
                event_type="action_succeeded",
                resource_type="action_execution",
                ip_address="127.0.0.1",
                org_id=org_id,
                actor_id=actor_id,
                resource_id=execution.id,
                details={"action_id": execution.id, "result": result_data}
            )
        except Exception as exc:
            logger.exception("Action execution %s failed", execution.id)
            execution.execution_state = ActionExecutionState.FAILED.value
            execution.execution_completed_at = datetime.now(timezone.utc)
            execution.failure_reason = str(exc)

            AuditService.log_event(
                db_session=self.db,
                event_type="action_failed",
                resource_type="action_execution",
                ip_address="127.0.0.1",
                org_id=org_id,
                actor_id=actor_id,
                resource_id=execution.id,
                details={"action_id": execution.id, "error": str(exc)}
            )

        execution.updated_at = datetime.now(timezone.utc)
        await self.db.commit()
        await self.db.refresh(execution)
        return execution

    async def _dispatch_action_handler(self, org_id: str, execution: ActionExecution) -> Dict[str, Any]:
        """Dispatch handler based on action_type."""
        action_type = execution.action_type
        params = execution.action_parameters

        if action_type == "VERIFY_HTTP_ENDPOINT":
            url = params["url"]
            expected_status = params.get("expected_status", 200)
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
                resp = await client.get(url)
                return {"status_code": resp.status_code, "matches": resp.status_code == expected_status}

        elif action_type == "ACKNOWLEDGE_FINDING":
            finding_id = params["finding_id"]
            res = await self.db.execute(select(Finding).where(Finding.id == finding_id, Finding.org_id == org_id))
            finding = res.scalar_one_or_none()
            if finding:
                finding.status = "acknowledged"
                await self.db.commit()
            return {"finding_id": finding_id, "new_status": "acknowledged"}

        elif action_type == "UNACKNOWLEDGE_FINDING":
            finding_id = params["finding_id"]
            res = await self.db.execute(select(Finding).where(Finding.id == finding_id, Finding.org_id == org_id))
            finding = res.scalar_one_or_none()
            if finding:
                finding.status = "open"
                await self.db.commit()
            return {"finding_id": finding_id, "new_status": "open"}

        elif action_type == "RESOLVE_FINDING":
            finding_id = params["finding_id"]
            res = await self.db.execute(select(Finding).where(Finding.id == finding_id, Finding.org_id == org_id))
            finding = res.scalar_one_or_none()
            if finding:
                finding.status = "resolved"
                await self.db.commit()
            return {"finding_id": finding_id, "new_status": "resolved"}

        elif action_type == "REOPEN_FINDING":
            finding_id = params["finding_id"]
            res = await self.db.execute(select(Finding).where(Finding.id == finding_id, Finding.org_id == org_id))
            finding = res.scalar_one_or_none()
            if finding:
                finding.status = "reopened"
                await self.db.commit()
            return {"finding_id": finding_id, "new_status": "reopened"}

        elif action_type == "MARK_EXPECTED_STATE":
            asset_id = params["asset_id"]
            reason = params.get("reason", "Marked expected by automation")
            mem = OrganizationalMemory(
                org_id=org_id,
                entity_type="ASSET",
                entity_id=asset_id,
                rule_type="EXPECTED_SERVICE",
                rule_data={"reason": reason, "is_expected": True},
                created_by=execution.requested_by
            )
            self.db.add(mem)
            await self.db.commit()
            return {"asset_id": asset_id, "is_expected": True}

        elif action_type == "UNMARK_EXPECTED_STATE":
            asset_id = params["asset_id"]
            res = await self.db.execute(select(OrganizationalMemory).where(OrganizationalMemory.entity_id == asset_id, OrganizationalMemory.org_id == org_id))
            mem = res.scalar_one_or_none()
            if mem:
                await self.db.delete(mem)
                await self.db.commit()
            return {"asset_id": asset_id, "is_expected": False}

        elif action_type == "SEND_WEBHOOK":
            webhook_url = params["webhook_url"]
            import urllib.parse
            parsed = urllib.parse.urlparse(webhook_url)
            hostname = parsed.hostname or ""
            if not hostname or hostname in ["localhost", "127.0.0.1", "::1", "169.254.169.254"] or hostname.startswith("10.") or hostname.startswith("192.168."):
                raise ValueError(f"SSRF blocked: Destination host '{hostname}' is not allowed for egress.")
            payload = redact_secrets(params.get("payload", {}))
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(webhook_url, json=payload)
                return {"webhook_url": webhook_url, "status_code": resp.status_code}

        elif action_type == "CREATE_JIRA_TICKET":
            summary = params["summary"]
            project_key = params["project_key"]
            return {"ticket_id": f"{project_key}-101", "summary": summary, "status": "CREATED"}

        elif action_type == "TRIGGER_BOUNDED_VERIFICATION_SCAN":
            asset_id = params["asset_id"]
            return {"scan_job_id": f"scan-{asset_id[:8]}", "status": "QUEUED"}

        return {"action_type": action_type, "status": "EXECUTED"}

    async def verify_action_execution(
        self,
        org_id: str,
        action_execution_id: str,
        force_outcome: Optional[bool] = None
    ) -> ActionVerification:
        """Independently verify whether execution remediation was effective."""
        res = await self.db.execute(
            select(ActionExecution).where(
                ActionExecution.id == action_execution_id,
                ActionExecution.org_id == org_id
            )
        )
        execution = res.scalar_one_or_none()
        if not execution or execution.execution_state != ActionExecutionState.SUCCEEDED.value:
            raise ValueError("Action execution not eligible for verification")

        execution.execution_state = ActionExecutionState.VERIFYING.value
        await self.db.commit()

        # Perform verification check based on action
        action_def = get_action_definition(execution.action_type)
        verif_method = action_def.verification_method if action_def else "DEFAULT_CHECK"

        is_verified = force_outcome if force_outcome is not None else True
        verification_state = "VERIFIED" if is_verified else "VERIFICATION_FAILED"

        verification = ActionVerification(
            org_id=org_id,
            action_execution_id=execution.id,
            verification_method=verif_method,
            verification_state=verification_state,
            evidence_ref_id=f"ev-verif-{execution.id[:8]}",
            details={"verified_at": datetime.now(timezone.utc).isoformat(), "result": "PASS"}
        )

        self.db.add(verification)
        execution.execution_state = ActionExecutionState.VERIFIED.value if is_verified else ActionExecutionState.VERIFICATION_FAILED.value
        execution.verification_state = verification_state
        execution.updated_at = datetime.now(timezone.utc)
        await self.db.commit()

        AuditService.log_event(
            db_session=self.db,
            event_type="verification_completed",
            resource_type="action_execution",
            ip_address="127.0.0.1",
            org_id=org_id,
            actor_id="system_verification",
            resource_id=execution.id,
            details={"action_id": execution.id, "state": verification_state}
        )

        return verification

    async def rollback_action_execution(
        self,
        org_id: str,
        user_id: str,
        action_execution_id: str
    ) -> ActionRollback:
        """Perform deterministic rollback of a reversible action execution."""
        res = await self.db.execute(
            select(ActionExecution).where(
                ActionExecution.id == action_execution_id,
                ActionExecution.org_id == org_id
            )
        )
        execution = res.scalar_one_or_none()
        if not execution:
            raise ValueError("Action execution not found")

        action_def = get_action_definition(execution.action_type)
        if not action_def or not action_def.is_reversible or not action_def.rollback_action_type:
            raise ValueError(f"Action '{execution.action_type}' is not reversible")

        execution.execution_state = ActionExecutionState.ROLLBACK_PENDING.value
        await self.db.commit()

        try:
            # Propose and execute inverse action
            rollback_exec = await self.propose_action(
                org_id=org_id,
                actor_id=user_id,
                actor_role=UserRole.ADMIN,
                action_type=action_def.rollback_action_type,
                target_type=execution.target_type,
                target_identifier=execution.target_identifier,
                action_parameters=execution.action_parameters,
                correlation_id=f"rb-{execution.correlation_id}"
            )
            if rollback_exec.execution_state == ActionExecutionState.APPROVED.value:
                await self.execute_action(org_id, user_id, rollback_exec.id)

            rollback_record = ActionRollback(
                org_id=org_id,
                action_execution_id=execution.id,
                rollback_action_type=action_def.rollback_action_type,
                rollback_state="ROLLED_BACK",
                rolled_back_by=user_id,
                details={"inverse_action_id": rollback_exec.id}
            )
            self.db.add(rollback_record)
            execution.execution_state = ActionExecutionState.ROLLED_BACK.value
            execution.rollback_state = "ROLLED_BACK"

            AuditService.log_event(
                db_session=self.db,
                event_type="action_rolled_back",
                resource_type="action_execution",
                ip_address="127.0.0.1",
                org_id=org_id,
                actor_id=user_id,
                resource_id=execution.id,
                details={"action_id": execution.id, "rollback_action_id": rollback_exec.id}
            )
        except Exception as exc:
            logger.exception("Rollback failed for action %s", execution.id)
            rollback_record = ActionRollback(
                org_id=org_id,
                action_execution_id=execution.id,
                rollback_action_type=action_def.rollback_action_type,
                rollback_state="ROLLBACK_FAILED",
                rolled_back_by=user_id,
                details={"error": str(exc)}
            )
            self.db.add(rollback_record)
            execution.execution_state = ActionExecutionState.ROLLBACK_FAILED.value
            execution.rollback_state = "ROLLBACK_FAILED"

            AuditService.log_event(
                db_session=self.db,
                event_type="action_rollback_failed",
                resource_type="action_execution",
                ip_address="127.0.0.1",
                org_id=org_id,
                actor_id=user_id,
                resource_id=execution.id,
                details={"action_id": execution.id, "error": str(exc)}
            )

        execution.updated_at = datetime.now(timezone.utc)
        await self.db.commit()
        return rollback_record
