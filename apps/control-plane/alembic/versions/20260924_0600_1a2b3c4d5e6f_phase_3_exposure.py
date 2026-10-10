"""Phase 3 Exposure Intelligence & Attack Surface Correlation migration

Revision ID: 1a2b3c4d5e6f
Revises: 9j2k1fff1k07
Create Date: 2026-09-24 06:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '1a2b3c4d5e6f'
down_revision: Union[str, None] = '9j2k1fff1k07'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. exposure_correlation_runs table
    op.create_table(
        'exposure_correlation_runs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('rule_version', sa.String(length=20), nullable=False, server_default='v1'),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='queued'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('conditions_detected', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('paths_detected', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('run_metadata', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_exp_run_org_status', 'exposure_correlation_runs', ['org_id', 'status'])
    op.create_index('idx_exp_run_created', 'exposure_correlation_runs', ['created_at'])

    # 2. exposure_conditions table
    op.create_table(
        'exposure_conditions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('condition_type', sa.String(length=100), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='active'),
        sa.Column('priority_band', sa.String(length=50), nullable=False, server_default='MEDIUM_EXPOSURE'),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('explanation', sa.Text(), nullable=False),
        sa.Column('primary_asset_id', sa.String(length=36), nullable=False),
        sa.Column('risk_assessment_id', sa.String(length=36), nullable=True),
        sa.Column('finding_id', sa.String(length=36), nullable=True),
        sa.Column('change_id', sa.String(length=36), nullable=True),
        sa.Column('rule_version', sa.String(length=20), nullable=False, server_default='v1'),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('reopened_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('provenance', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['primary_asset_id'], ['assets.id']),
        sa.ForeignKeyConstraint(['risk_assessment_id'], ['risk_assessments.id']),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id']),
        sa.ForeignKeyConstraint(['change_id'], ['changes.id']),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('exposure_conditions') as batch_op:
        batch_op.create_index('uix_exp_cond_org_type_asset', ['org_id', 'condition_type', 'primary_asset_id'], unique=True)
        batch_op.create_index('idx_exp_cond_org_status', ['org_id', 'status'])
        batch_op.create_index('idx_exp_cond_org_priority', ['org_id', 'priority_band'])
        batch_op.create_index('idx_exp_cond_org_asset', ['org_id', 'primary_asset_id'])

    # 3. exposure_condition_evidence table
    op.create_table(
        'exposure_condition_evidence',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('condition_id', sa.String(length=36), nullable=False),
        sa.Column('evidence_type', sa.String(length=50), nullable=False),
        sa.Column('evidence_ref_id', sa.String(length=255), nullable=False),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['condition_id'], ['exposure_conditions.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_exp_ev_org_cond', 'exposure_condition_evidence', ['org_id', 'condition_id'])
    op.create_index('idx_exp_ev_ref', 'exposure_condition_evidence', ['evidence_type', 'evidence_ref_id'])

    # 4. exposure_paths table
    op.create_table(
        'exposure_paths',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('condition_id', sa.String(length=36), nullable=False),
        sa.Column('start_asset_id', sa.String(length=36), nullable=False),
        sa.Column('end_asset_id', sa.String(length=36), nullable=False),
        sa.Column('path_length', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('nodes_snapshot', sa.JSON(), nullable=False),
        sa.Column('edges_snapshot', sa.JSON(), nullable=False),
        sa.Column('explanation', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['condition_id'], ['exposure_conditions.id']),
        sa.ForeignKeyConstraint(['start_asset_id'], ['assets.id']),
        sa.ForeignKeyConstraint(['end_asset_id'], ['assets.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_exp_path_org_cond', 'exposure_paths', ['org_id', 'condition_id'])
    op.create_index('idx_exp_path_start_end', 'exposure_paths', ['start_asset_id', 'end_asset_id'])


def downgrade() -> None:
    op.drop_table('exposure_paths')
    op.drop_table('exposure_condition_evidence')
    op.drop_table('exposure_conditions')
    op.drop_table('exposure_correlation_runs')
