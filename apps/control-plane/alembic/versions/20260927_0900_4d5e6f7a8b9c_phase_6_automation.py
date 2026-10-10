"""Phase 6 Intelligent Automation & Security Orchestration migration

Revision ID: 4d5e6f7a8b9c
Revises: 3c4d5e6f7a8b
Create Date: 2026-09-27 09:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '4d5e6f7a8b9c'
down_revision: Union[str, None] = '3c4d5e6f7a8b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. automation_policies
    op.create_table(
        'automation_policies',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('allow_auto_approval', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('max_risk_class', sa.String(length=50), nullable=False, server_default='CLASS_B_LOW_RISK_REVERSIBLE'),
        sa.Column('allowed_action_types', sa.JSON(), nullable=False),
        sa.Column('target_environment_constraints', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('automation_policies') as batch_op:
        batch_op.create_index('idx_auto_policy_org', ['org_id'])
        batch_op.create_index('idx_auto_policy_enabled', ['org_id', 'is_enabled'])

    # 2. automation_rules
    op.create_table(
        'automation_rules',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('policy_id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('trigger_event', sa.String(length=100), nullable=False),
        sa.Column('trigger_conditions', sa.JSON(), nullable=False),
        sa.Column('action_type', sa.String(length=100), nullable=False),
        sa.Column('action_parameters_template', sa.JSON(), nullable=False),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['policy_id'], ['automation_policies.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('automation_rules') as batch_op:
        batch_op.create_index('idx_auto_rule_org_trigger', ['org_id', 'trigger_event'])
        batch_op.create_index('idx_auto_rule_policy', ['policy_id'])

    # 3. action_executions
    op.create_table(
        'action_executions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('action_type', sa.String(length=100), nullable=False),
        sa.Column('target_type', sa.String(length=50), nullable=False),
        sa.Column('target_identifier', sa.String(length=255), nullable=False),
        sa.Column('risk_class', sa.String(length=50), nullable=False),
        sa.Column('execution_state', sa.String(length=50), nullable=False, server_default='PROPOSED'),
        sa.Column('authorization_state', sa.String(length=50), nullable=False, server_default='UNAUTHORIZED'),
        sa.Column('approval_requirement', sa.String(length=50), nullable=False, server_default='REQUIRE_APPROVAL'),
        sa.Column('requested_by', sa.String(length=36), nullable=False),
        sa.Column('requested_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('action_parameters', sa.JSON(), nullable=False),
        sa.Column('execution_started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('execution_completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('verification_state', sa.String(length=50), nullable=False, server_default='UNVERIFIED'),
        sa.Column('result_data', sa.JSON(), nullable=True),
        sa.Column('failure_reason', sa.Text(), nullable=True),
        sa.Column('rollback_state', sa.String(length=50), nullable=False, server_default='NOT_APPLICABLE'),
        sa.Column('provenance', sa.JSON(), nullable=False),
        sa.Column('policy_version', sa.String(length=50), nullable=False, server_default='v1'),
        sa.Column('idempotency_key', sa.String(length=255), nullable=False),
        sa.Column('correlation_id', sa.String(length=255), nullable=False),
        sa.Column('automation_depth', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('parent_execution_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('action_executions') as batch_op:
        batch_op.create_index('uix_action_exec_org_idem', ['org_id', 'idempotency_key'], unique=True)
        batch_op.create_index('idx_action_exec_org_state', ['org_id', 'execution_state'])
        batch_op.create_index('idx_action_exec_org_target', ['org_id', 'target_identifier'])
        batch_op.create_index('idx_action_exec_corr', ['correlation_id'])

    # 4. action_approvals
    op.create_table(
        'action_approvals',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('action_execution_id', sa.String(length=36), nullable=False),
        sa.Column('approver_user_id', sa.String(length=36), nullable=False),
        sa.Column('decision', sa.String(length=50), nullable=False),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('approved_parameters_hash', sa.String(length=64), nullable=False),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['action_execution_id'], ['action_executions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['approver_user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('action_approvals') as batch_op:
        batch_op.create_index('idx_action_appr_org_exec', ['org_id', 'action_execution_id'])
        batch_op.create_index('idx_action_appr_approver', ['approver_user_id'])

    # 5. action_verifications
    op.create_table(
        'action_verifications',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('action_execution_id', sa.String(length=36), nullable=False),
        sa.Column('verification_method', sa.String(length=100), nullable=False),
        sa.Column('verification_state', sa.String(length=50), nullable=False),
        sa.Column('evidence_ref_id', sa.String(length=255), nullable=True),
        sa.Column('details', sa.JSON(), nullable=False),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['action_execution_id'], ['action_executions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('action_verifications') as batch_op:
        batch_op.create_index('idx_action_verif_org_exec', ['org_id', 'action_execution_id'])

    # 6. action_rollbacks
    op.create_table(
        'action_rollbacks',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('action_execution_id', sa.String(length=36), nullable=False),
        sa.Column('rollback_action_type', sa.String(length=100), nullable=False),
        sa.Column('rollback_state', sa.String(length=50), nullable=False),
        sa.Column('rolled_back_by', sa.String(length=36), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('details', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['action_execution_id'], ['action_executions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('action_rollbacks') as batch_op:
        batch_op.create_index('idx_action_roll_org_exec', ['org_id', 'action_execution_id'])


def downgrade() -> None:
    op.drop_table('action_rollbacks')
    op.drop_table('action_verifications')
    op.drop_table('action_approvals')
    op.drop_table('action_executions')
    op.drop_table('automation_rules')
    op.drop_table('automation_policies')
