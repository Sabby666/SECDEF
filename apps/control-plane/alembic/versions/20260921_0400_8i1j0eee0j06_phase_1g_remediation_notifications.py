"""Phase 1G remediation verification and notification tables

Revision ID: 8i1j0eee0j06
Revises: 7h0i9ddd9i05
Create Date: 2026-09-21 04:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '8i1j0eee0j06'
down_revision: Union[str, None] = '7h0i9ddd9i05'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Findings table
    op.create_table(
        'findings',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('change_id', sa.String(length=36), nullable=False),
        sa.Column('asset_id', sa.String(length=36), nullable=True),
        sa.Column('risk_assessment_id', sa.String(length=36), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='open'),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('acknowledged_by', sa.String(length=36), nullable=True),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('reopened_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['change_id'], ['changes.id']),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id']),
        sa.ForeignKeyConstraint(['risk_assessment_id'], ['risk_assessments.id']),
        sa.ForeignKeyConstraint(['acknowledged_by'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('uix_finding_org_change', 'findings', ['org_id', 'change_id'], unique=True)
    op.create_index('idx_finding_org_status', 'findings', ['org_id', 'status'])
    op.create_index('idx_finding_org_asset', 'findings', ['org_id', 'asset_id'])
    op.create_index('idx_finding_created', 'findings', ['created_at'])

    # 2. Finding State Transitions
    op.create_table(
        'finding_state_transitions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('finding_id', sa.String(length=36), nullable=False),
        sa.Column('actor_id', sa.String(length=36), nullable=True),
        sa.Column('from_status', sa.String(length=50), nullable=False),
        sa.Column('to_status', sa.String(length=50), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('evidence_snapshot', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id']),
        sa.ForeignKeyConstraint(['actor_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_finding_trans_org_finding', 'finding_state_transitions', ['org_id', 'finding_id'])
    op.create_index('idx_finding_trans_created', 'finding_state_transitions', ['created_at'])

    # 3. Verification Results
    op.create_table(
        'verification_results',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('finding_id', sa.String(length=36), nullable=False),
        sa.Column('comparison_run_id', sa.String(length=36), nullable=False),
        sa.Column('current_scan_id', sa.String(length=36), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('method', sa.String(length=50), nullable=False, server_default='scan_observation_comparison'),
        sa.Column('previous_observed_state', sa.JSON(), nullable=True),
        sa.Column('current_observed_state', sa.JSON(), nullable=True),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id']),
        sa.ForeignKeyConstraint(['comparison_run_id'], ['comparison_runs.id']),
        sa.ForeignKeyConstraint(['current_scan_id'], ['scans.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('uix_verification_org_finding_comp', 'verification_results', ['org_id', 'finding_id', 'comparison_run_id'], unique=True)
    op.create_index('idx_verification_org_status', 'verification_results', ['org_id', 'status'])
    op.create_index('idx_verification_verified_at', 'verification_results', ['verified_at'])

    # 4. Notification Destinations
    op.create_table(
        'notification_destinations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('channel', sa.String(length=50), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('config', sa.JSON(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_dest_org_channel', 'notification_destinations', ['org_id', 'channel'])
    op.create_index('idx_dest_org_active', 'notification_destinations', ['org_id', 'is_active'])

    # 5. Notification Policies
    op.create_table(
        'notification_policies',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('policy_version', sa.String(length=20), nullable=False, server_default='v1'),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('min_risk_band', sa.String(length=20), nullable=False, server_default='HIGH'),
        sa.Column('trigger_types', sa.JSON(), nullable=False),
        sa.Column('destination_ids', sa.JSON(), nullable=False),
        sa.Column('cooldown_minutes', sa.Integer(), nullable=False, server_default='60'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_policy_org_active', 'notification_policies', ['org_id', 'is_active'])
    op.create_index('idx_policy_org_version', 'notification_policies', ['org_id', 'policy_version'])

    # 6. Notifications
    op.create_table(
        'notifications',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('finding_id', sa.String(length=36), nullable=True),
        sa.Column('risk_assessment_id', sa.String(length=36), nullable=True),
        sa.Column('change_id', sa.String(length=36), nullable=True),
        sa.Column('verification_result_id', sa.String(length=36), nullable=True),
        sa.Column('trigger_type', sa.String(length=50), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('content_payload', sa.JSON(), nullable=False),
        sa.Column('event_identity', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id']),
        sa.ForeignKeyConstraint(['risk_assessment_id'], ['risk_assessments.id']),
        sa.ForeignKeyConstraint(['change_id'], ['changes.id']),
        sa.ForeignKeyConstraint(['verification_result_id'], ['verification_results.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('uix_notification_event_identity', 'notifications', ['org_id', 'event_identity'], unique=True)
    op.create_index('idx_notification_org_created', 'notifications', ['org_id', 'created_at'])
    op.create_index('idx_notification_trigger', 'notifications', ['org_id', 'trigger_type'])

    # 7. Notification Deliveries
    op.create_table(
        'notification_deliveries',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('notification_id', sa.String(length=36), nullable=False),
        sa.Column('destination_id', sa.String(length=36), nullable=False),
        sa.Column('channel', sa.String(length=50), nullable=False),
        sa.Column('attempt_number', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='pending'),
        sa.Column('response_code', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('delivered_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['notification_id'], ['notifications.id']),
        sa.ForeignKeyConstraint(['destination_id'], ['notification_destinations.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_delivery_org_notification', 'notification_deliveries', ['org_id', 'notification_id'])
    op.create_index('idx_delivery_org_status', 'notification_deliveries', ['org_id', 'status'])
    op.create_index('idx_delivery_created', 'notification_deliveries', ['created_at'])


def downgrade() -> None:
    op.drop_table('notification_deliveries')
    op.drop_table('notifications')
    op.drop_table('notification_policies')
    op.drop_table('notification_destinations')
    op.drop_table('verification_results')
    op.drop_table('finding_state_transitions')
    op.drop_table('findings')
