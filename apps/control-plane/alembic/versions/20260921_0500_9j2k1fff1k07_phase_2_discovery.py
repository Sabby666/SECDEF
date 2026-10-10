"""Phase 2 expanded discovery and candidate schema migration

Revision ID: 9j2k1fff1k07
Revises: 8i1j0eee0j06
Create Date: 2026-09-21 05:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '9j2k1fff1k07'
down_revision: Union[str, None] = '8i1j0eee0j06'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. discovery_sources table
    op.create_table(
        'discovery_sources',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('source_type', sa.String(length=50), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('config', sa.JSON(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_disc_source_org_type', 'discovery_sources', ['org_id', 'source_type'])
    op.create_index('idx_disc_source_active', 'discovery_sources', ['org_id', 'is_active'])

    # 2. discovery_runs table
    op.create_table(
        'discovery_runs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('source_id', sa.String(length=36), nullable=False),
        sa.Column('domain_id', sa.String(length=36), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='queued'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('candidates_discovered', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('candidates_validated', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('candidates_rejected', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('run_metadata', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['domain_id'], ['domains.id']),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['source_id'], ['discovery_sources.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_disc_run_org_source', 'discovery_runs', ['org_id', 'source_id'])
    op.create_index('idx_disc_run_org_status', 'discovery_runs', ['org_id', 'status'])
    op.create_index('idx_disc_run_created', 'discovery_runs', ['created_at'])

    # 3. discovery_candidates table
    op.create_table(
        'discovery_candidates',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('discovery_run_id', sa.String(length=36), nullable=False),
        sa.Column('canonical_identifier', sa.Text(), nullable=False),
        sa.Column('candidate_type', sa.String(length=50), nullable=False),
        sa.Column('source_type', sa.String(length=50), nullable=False),
        sa.Column('validation_state', sa.String(length=50), nullable=False, server_default='unvalidated'),
        sa.Column('confidence', sa.String(length=20), nullable=False, server_default='UNVERIFIED'),
        sa.Column('exposure_state', sa.String(length=20), nullable=False, server_default='UNKNOWN'),
        sa.Column('promoted_asset_id', sa.String(length=36), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('candidate_metadata', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['discovery_run_id'], ['discovery_runs.id']),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.ForeignKeyConstraint(['promoted_asset_id'], ['assets.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('uix_candidate_org_ident', 'discovery_candidates', ['org_id', 'candidate_type', 'canonical_identifier'], unique=True)
    op.create_index('idx_candidate_org_state', 'discovery_candidates', ['org_id', 'validation_state'])
    op.create_index('idx_candidate_org_type', 'discovery_candidates', ['org_id', 'candidate_type'])

    # 4. discovery_evidence table
    op.create_table(
        'discovery_evidence',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('candidate_id', sa.String(length=36), nullable=False),
        sa.Column('source_type', sa.String(length=50), nullable=False),
        sa.Column('raw_data', sa.JSON(), nullable=False),
        sa.Column('provenance', sa.JSON(), nullable=False),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['candidate_id'], ['discovery_candidates.id']),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_evidence_org_candidate', 'discovery_evidence', ['org_id', 'candidate_id'])
    op.create_index('idx_evidence_observed', 'discovery_evidence', ['observed_at'])


def downgrade() -> None:
    op.drop_table('discovery_evidence')
    op.drop_table('discovery_candidates')
    op.drop_table('discovery_runs')
    op.drop_table('discovery_sources')
