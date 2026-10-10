"""Phase 1b scans and observations

Revision ID: 3d6e5fff5f91
Revises: 2c5e4ddd4f90
Create Date: 2026-09-02 19:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3d6e5fff5f91'
down_revision: Union[str, None] = '2c5e4ddd4f90'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('scans',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('domain_id', sa.String(length=36), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('job_nonce', sa.String(length=128), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('scan_metadata', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], ),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('job_nonce')
    )
    op.create_index('idx_scans_domain_created', 'scans', ['domain_id', 'created_at'], unique=False)
    op.create_index('idx_scans_org_status', 'scans', ['org_id', 'status'], unique=False)

    op.create_table('observations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('scan_id', sa.String(length=36), nullable=False),
        sa.Column('observation_type', sa.String(length=50), nullable=False),
        sa.Column('target', sa.Text(), nullable=False),
        sa.Column('raw_data', sa.JSON(), nullable=False),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_obs_org_target_time', 'observations', ['org_id', 'target', 'observed_at'], unique=False)
    op.create_index('idx_obs_scan_type', 'observations', ['scan_id', 'observation_type'], unique=False)


def downgrade() -> None:
    op.drop_index('idx_obs_scan_type', table_name='observations')
    op.drop_index('idx_obs_org_target_time', table_name='observations')
    op.drop_table('observations')
    op.drop_index('idx_scans_org_status', table_name='scans')
    op.drop_index('idx_scans_domain_created', table_name='scans')
    op.drop_table('scans')
