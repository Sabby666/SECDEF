"""Phase 4 Threat & Vulnerability Intelligence Correlation migration

Revision ID: 2b3c4d5e6f7a
Revises: 1a2b3c4d5e6f
Create Date: 2026-09-25 07:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '2b3c4d5e6f7a'
down_revision: Union[str, None] = '1a2b3c4d5e6f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. intelligence_sources table
    op.create_table(
        'intelligence_sources',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('source_name', sa.String(length=100), nullable=False),
        sa.Column('source_type', sa.String(length=50), nullable=False),
        sa.Column('config', sa.JSON(), nullable=True),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('last_retrieved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('intelligence_sources') as batch_op:
        batch_op.create_index('uix_intel_source_org_name', ['org_id', 'source_name'], unique=True)
        batch_op.create_index('idx_intel_source_org_type', ['org_id', 'source_type'])

    # 2. intelligence_runs table
    op.create_table(
        'intelligence_runs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('source_id', sa.String(length=36), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='queued'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('records_ingested', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('records_updated', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('run_metadata', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['source_id'], ['intelligence_sources.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_intel_run_org_status', 'intelligence_runs', ['org_id', 'status'])
    op.create_index('idx_intel_run_created', 'intelligence_runs', ['created_at'])

    # 3. intelligence_records table
    op.create_table(
        'intelligence_records',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('source_id', sa.String(length=36), nullable=False),
        sa.Column('external_id', sa.String(length=255), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=50), nullable=False, server_default='medium'),
        sa.Column('cvss_v3_score', sa.Float(), nullable=True),
        sa.Column('cvss_vector', sa.String(length=255), nullable=True),
        sa.Column('cwe_ids', sa.JSON(), nullable=True),
        sa.Column('affected_product', sa.String(length=255), nullable=False),
        sa.Column('affected_vendor', sa.String(length=255), nullable=False),
        sa.Column('affected_cpe', sa.String(length=255), nullable=True),
        sa.Column('affected_version_range', sa.String(length=255), nullable=True),
        sa.Column('epss_score', sa.Float(), nullable=True),
        sa.Column('epss_percentile', sa.Float(), nullable=True),
        sa.Column('is_cisa_kev', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('exploit_availability', sa.String(length=50), nullable=False, server_default='none'),
        sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('retrieved_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('freshness_status', sa.String(length=50), nullable=False, server_default='CURRENT'),
        sa.Column('raw_data', sa.JSON(), nullable=False),
        sa.Column('provenance', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['source_id'], ['intelligence_sources.id']),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('intelligence_records') as batch_op:
        batch_op.create_index('uix_intel_rec_org_source_ext', ['org_id', 'source_id', 'external_id'], unique=True)
        batch_op.create_index('idx_intel_rec_org_prod', ['org_id', 'affected_vendor', 'affected_product'])
        batch_op.create_index('idx_intel_rec_org_ext', ['org_id', 'external_id'])

    # 4. intelligence_correlations table
    op.create_table(
        'intelligence_correlations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('intelligence_record_id', sa.String(length=36), nullable=False),
        sa.Column('asset_id', sa.String(length=36), nullable=False),
        sa.Column('exposure_condition_id', sa.String(length=36), nullable=True),
        sa.Column('correlation_state', sa.String(length=50), nullable=False, server_default='POTENTIAL_MATCH'),
        sa.Column('confidence_score', sa.Float(), nullable=False, server_default='0.5'),
        sa.Column('confidence_band', sa.String(length=50), nullable=False, server_default='MEDIUM'),
        sa.Column('confidence_breakdown', sa.JSON(), nullable=False),
        sa.Column('match_reason', sa.Text(), nullable=False),
        sa.Column('rule_version', sa.String(length=20), nullable=False, server_default='v1'),
        sa.Column('observed_technology', sa.String(length=255), nullable=False),
        sa.Column('observed_version', sa.String(length=255), nullable=True),
        sa.Column('conflict_status', sa.String(length=50), nullable=False, server_default='NO_CONFLICT'),
        sa.Column('conflict_details', sa.JSON(), nullable=True),
        sa.Column('first_correlated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_correlated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('provenance', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['intelligence_record_id'], ['intelligence_records.id']),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id']),
        sa.ForeignKeyConstraint(['exposure_condition_id'], ['exposure_conditions.id']),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('intelligence_correlations') as batch_op:
        batch_op.create_index('uix_intel_corr_org_rec_asset', ['org_id', 'intelligence_record_id', 'asset_id'], unique=True)
        batch_op.create_index('idx_intel_corr_org_state', ['org_id', 'correlation_state'])
        batch_op.create_index('idx_intel_corr_org_asset', ['org_id', 'asset_id'])

    # 5. intelligence_evidence table
    op.create_table(
        'intelligence_evidence',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('correlation_id', sa.String(length=36), nullable=False),
        sa.Column('evidence_type', sa.String(length=50), nullable=False),
        sa.Column('evidence_ref_id', sa.String(length=255), nullable=False),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['correlation_id'], ['intelligence_correlations.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_intel_ev_org_corr', 'intelligence_evidence', ['org_id', 'correlation_id'])
    op.create_index('idx_intel_ev_ref', 'intelligence_evidence', ['evidence_type', 'evidence_ref_id'])


def downgrade() -> None:
    op.drop_table('intelligence_evidence')
    op.drop_table('intelligence_correlations')
    op.drop_table('intelligence_records')
    op.drop_table('intelligence_runs')
    op.drop_table('intelligence_sources')
