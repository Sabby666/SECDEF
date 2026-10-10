"""Phase 1F contextual risk assessment table

Revision ID: 7h0i9ddd9i05
Revises: 6g9h8ccc8h04
Create Date: 2026-09-21 03:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7h0i9ddd9i05'
down_revision: Union[str, None] = '6g9h8ccc8h04'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. RiskAssessment table
    op.create_table('risk_assessments',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('org_id', sa.String(length=36), nullable=False),
        sa.Column('change_id', sa.String(length=36), nullable=True),
        sa.Column('asset_id', sa.String(length=36), nullable=True),
        sa.Column('risk_model_version', sa.String(length=20), nullable=False, server_default='v1'),
        sa.Column('risk_score', sa.Float(), nullable=False),
        sa.Column('risk_band', sa.String(length=20), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('factor_breakdown', sa.JSON(), nullable=False),
        sa.Column('context_snapshot', sa.JSON(), nullable=False),
        sa.Column('uncertainty_flags', sa.JSON(), nullable=False),
        sa.Column('explanation', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['change_id'], ['changes.id'], ),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('uix_risk_org_change_version', 'risk_assessments', ['org_id', 'change_id', 'risk_model_version'], unique=True)
    op.create_index('idx_risk_org_band', 'risk_assessments', ['org_id', 'risk_band'], unique=False)
    op.create_index('idx_risk_org_asset', 'risk_assessments', ['org_id', 'asset_id'], unique=False)
    op.create_index('idx_risk_org_created', 'risk_assessments', ['org_id', 'created_at'], unique=False)


def downgrade() -> None:
    op.drop_index('idx_risk_org_created', table_name='risk_assessments')
    op.drop_index('idx_risk_org_asset', table_name='risk_assessments')
    op.drop_index('idx_risk_org_band', table_name='risk_assessments')
    op.drop_index('uix_risk_org_change_version', table_name='risk_assessments')
    op.drop_table('risk_assessments')
