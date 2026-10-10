"""Phase 1E context and memory tables

Revision ID: 6g9h8ccc8h04
Revises: 5f8g7bbb7g93
Create Date: 2026-09-21 02:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6g9h8ccc8h04'
down_revision: Union[str, None] = '5f8g7bbb7g93'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. AssetContext table
    op.create_table('asset_contexts',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('asset_id', sa.String(length=36), nullable=False),
        sa.Column('owner_id', sa.String(length=36), nullable=True),
        sa.Column('owner_team', sa.String(length=255), nullable=True),
        sa.Column('environment', sa.String(length=50), nullable=False, server_default='unknown'),
        sa.Column('criticality', sa.String(length=50), nullable=False, server_default='medium'),
        sa.Column('business_purpose', sa.Text(), nullable=True),
        sa.Column('expected_exposure', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('uix_asset_context_org_asset', 'asset_contexts', ['org_id', 'asset_id'], unique=True)
    op.create_index('idx_asset_context_org_env', 'asset_contexts', ['org_id', 'environment'], unique=False)
    op.create_index('idx_asset_context_org_criticality', 'asset_contexts', ['org_id', 'criticality'], unique=False)

    # 2. OrganizationalDecision table
    op.create_table('organizational_decisions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('actor_id', sa.String(length=36), nullable=False),
        sa.Column('subject_type', sa.String(length=50), nullable=False),
        sa.Column('subject_identifier', sa.Text(), nullable=False),
        sa.Column('decision_type', sa.String(length=50), nullable=False),
        sa.Column('scope_level', sa.String(length=50), nullable=False),
        sa.Column('previous_state', sa.JSON(), nullable=True),
        sa.Column('new_state', sa.JSON(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('valid_from', sa.DateTime(timezone=True), nullable=False),
        sa.Column('valid_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('review_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='active'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_decision_org_subject', 'organizational_decisions', ['org_id', 'subject_identifier'], unique=False)
    op.create_index('idx_decision_org_status', 'organizational_decisions', ['org_id', 'status'], unique=False)
    op.create_index('idx_decision_org_created', 'organizational_decisions', ['org_id', 'created_at'], unique=False)

    # 3. OrganizationalMemory table
    op.create_table('organizational_memories',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('decision_id', sa.String(length=36), nullable=True),
        sa.Column('category', sa.String(length=50), nullable=False),
        sa.Column('scope_level', sa.String(length=50), nullable=False),
        sa.Column('scope_identifier', sa.Text(), nullable=False),
        sa.Column('memory_key', sa.String(length=100), nullable=False),
        sa.Column('memory_value', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('source', sa.String(length=100), nullable=False),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('valid_from', sa.DateTime(timezone=True), nullable=False),
        sa.Column('valid_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='active'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['decision_id'], ['organizational_decisions.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_memory_org_scope', 'organizational_memories', ['org_id', 'scope_level', 'scope_identifier'], unique=False)
    op.create_index('idx_memory_org_key', 'organizational_memories', ['org_id', 'memory_key'], unique=False)
    op.create_index('idx_memory_org_status', 'organizational_memories', ['org_id', 'status'], unique=False)

    # 4. DecisionTransitionHistory table
    op.create_table('decision_transition_histories',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('decision_id', sa.String(length=36), nullable=False),
        sa.Column('actor_id', sa.String(length=36), nullable=False),
        sa.Column('from_status', sa.String(length=50), nullable=False),
        sa.Column('to_status', sa.String(length=50), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['decision_id'], ['organizational_decisions.id'], ),
        sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_transition_org_decision', 'decision_transition_histories', ['org_id', 'decision_id'], unique=False)
    op.create_index('idx_transition_created', 'decision_transition_histories', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index('idx_transition_created', table_name='decision_transition_histories')
    op.drop_index('idx_transition_org_decision', table_name='decision_transition_histories')
    op.drop_table('decision_transition_histories')

    op.drop_index('idx_memory_org_status', table_name='organizational_memories')
    op.drop_index('idx_memory_org_key', table_name='organizational_memories')
    op.drop_index('idx_memory_org_scope', table_name='organizational_memories')
    op.drop_table('organizational_memories')

    op.drop_index('idx_decision_org_created', table_name='organizational_decisions')
    op.drop_index('idx_decision_org_status', table_name='organizational_decisions')
    op.drop_index('idx_decision_org_subject', table_name='organizational_decisions')
    op.drop_table('organizational_decisions')

    op.drop_index('idx_asset_context_org_criticality', table_name='asset_contexts')
    op.drop_index('idx_asset_context_org_env', table_name='asset_contexts')
    op.drop_index('uix_asset_context_org_asset', table_name='asset_contexts')
    op.drop_table('asset_contexts')
