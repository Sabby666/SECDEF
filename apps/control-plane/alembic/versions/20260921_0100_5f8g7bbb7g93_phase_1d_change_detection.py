"""Phase 1D change detection tables

Revision ID: 5f8g7bbb7g93
Revises: 4e7f6aaa6f92
Create Date: 2026-09-21 01:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5f8g7bbb7g93'
down_revision: Union[str, None] = '4e7f6aaa6f92'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ComparisonRun table — tracks each scan-over-scan comparison execution
    op.create_table('comparison_runs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('domain_id', sa.String(length=36), nullable=False),
        sa.Column('current_scan_id', sa.String(length=36), nullable=False),
        sa.Column('previous_scan_id', sa.String(length=36), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('current_scan_completeness', sa.String(length=50), nullable=False, server_default='unknown'),
        sa.Column('completeness_details', sa.JSON(), nullable=True),
        sa.Column('changes_detected', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('comparison_metadata', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], ),
        sa.ForeignKeyConstraint(['current_scan_id'], ['scans.id'], ),
        sa.ForeignKeyConstraint(['previous_scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('uix_comparison_org_domain_scan', 'comparison_runs',
                    ['org_id', 'domain_id', 'current_scan_id'], unique=True)
    op.create_index('idx_comparison_org_created', 'comparison_runs',
                    ['org_id', 'created_at'], unique=False)
    op.create_index('idx_comparison_domain', 'comparison_runs',
                    ['domain_id'], unique=False)

    # Changes table — individual detected changes from comparison runs
    op.create_table('changes',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('comparison_run_id', sa.String(length=36), nullable=False),
        sa.Column('asset_id', sa.String(length=36), nullable=True),
        sa.Column('change_type', sa.String(length=50), nullable=False),
        sa.Column('entity_type', sa.String(length=50), nullable=False),
        sa.Column('entity_identifier', sa.Text(), nullable=False),
        sa.Column('previous_state', sa.JSON(), nullable=True),
        sa.Column('current_state', sa.JSON(), nullable=True),
        sa.Column('previous_scan_id', sa.String(length=36), nullable=True),
        sa.Column('current_scan_id', sa.String(length=36), nullable=False),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['comparison_run_id'], ['comparison_runs.id'], ),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
        sa.ForeignKeyConstraint(['previous_scan_id'], ['scans.id'], ),
        sa.ForeignKeyConstraint(['current_scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('uix_change_identity', 'changes',
                    ['org_id', 'comparison_run_id', 'change_type', 'entity_type', 'entity_identifier'],
                    unique=True)
    op.create_index('idx_changes_org_detected', 'changes',
                    ['org_id', 'detected_at'], unique=False)
    op.create_index('idx_changes_org_type', 'changes',
                    ['org_id', 'change_type'], unique=False)
    op.create_index('idx_changes_comparison', 'changes',
                    ['comparison_run_id'], unique=False)


def downgrade() -> None:
    op.drop_index('idx_changes_comparison', table_name='changes')
    op.drop_index('idx_changes_org_type', table_name='changes')
    op.drop_index('idx_changes_org_detected', table_name='changes')
    op.drop_index('uix_change_identity', table_name='changes')
    op.drop_table('changes')

    op.drop_index('idx_comparison_domain', table_name='comparison_runs')
    op.drop_index('idx_comparison_org_created', table_name='comparison_runs')
    op.drop_index('uix_comparison_org_domain_scan', table_name='comparison_runs')
    op.drop_table('comparison_runs')
