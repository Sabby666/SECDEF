"""Phase 1c assets and relationships

Revision ID: 4e7f6aaa6f92
Revises: 3d6e5fff5f91
Create Date: 2026-09-06 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4e7f6aaa6f92'
down_revision: Union[str, None] = '3d6e5fff5f91'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('assets',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('domain_id', sa.String(length=36), nullable=True),
        sa.Column('asset_type', sa.String(length=50), nullable=False),
        sa.Column('identifier', sa.Text(), nullable=False),
        sa.Column('environment', sa.String(length=50), nullable=False, server_default='unknown'),
        sa.Column('criticality', sa.String(length=50), nullable=False, server_default='medium'),
        sa.Column('owner_id', sa.String(length=36), nullable=True),
        sa.Column('owner_team', sa.String(length=255), nullable=True),
        sa.Column('expected_state', sa.JSON(), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='active'),
        sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], ),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('uix_assets_org_type_ident', 'assets', ['org_id', 'asset_type', 'identifier'], unique=True)
    op.create_index('idx_assets_org_env', 'assets', ['org_id', 'environment'], unique=False)
    op.create_index('idx_assets_org_owner', 'assets', ['org_id', 'owner_id'], unique=False)
    op.create_index('idx_assets_org_type', 'assets', ['org_id', 'asset_type'], unique=False)

    op.create_table('asset_relationships',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('source_asset_id', sa.String(length=36), nullable=False),
        sa.Column('target_asset_id', sa.String(length=36), nullable=False),
        sa.Column('relationship_type', sa.String(length=50), nullable=False),
        sa.Column('confidence', sa.String(length=20), nullable=False, server_default='HIGH'),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='active'),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['source_asset_id'], ['assets.id'], ),
        sa.ForeignKeyConstraint(['target_asset_id'], ['assets.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('uix_rel_org_src_tgt_type', 'asset_relationships', ['org_id', 'source_asset_id', 'target_asset_id', 'relationship_type'], unique=True)
    op.create_index('idx_rel_source', 'asset_relationships', ['source_asset_id'], unique=False)
    op.create_index('idx_rel_target', 'asset_relationships', ['target_asset_id'], unique=False)
    op.create_index('idx_rel_org_status', 'asset_relationships', ['org_id', 'status'], unique=False)

    op.add_column('observations', sa.Column('asset_id', sa.String(length=36), nullable=True))
    with op.batch_alter_table('observations') as batch_op:
        batch_op.create_foreign_key('fk_obs_asset_id', 'assets', ['asset_id'], ['id'])
    op.create_index('idx_obs_asset_id', 'observations', ['asset_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('observations') as batch_op:
        batch_op.drop_constraint('fk_obs_asset_id', type_='foreignkey')
    op.drop_index('idx_obs_asset_id', table_name='observations')
    op.drop_column('observations', 'asset_id')


    op.drop_index('idx_rel_org_status', table_name='asset_relationships')
    op.drop_index('idx_rel_target', table_name='asset_relationships')
    op.drop_index('idx_rel_source', table_name='asset_relationships')
    op.drop_index('uix_rel_org_src_tgt_type', table_name='asset_relationships')
    op.drop_table('asset_relationships')

    op.drop_index('idx_assets_org_type', table_name='assets')
    op.drop_index('idx_assets_org_owner', table_name='assets')
    op.drop_index('idx_assets_org_env', table_name='assets')
    op.drop_index('uix_assets_org_type_ident', table_name='assets')
    op.drop_table('assets')
