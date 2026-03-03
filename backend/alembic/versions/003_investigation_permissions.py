"""Add investigation_permissions table for per-investigation RBAC.

Revision ID: 003_investigation_permissions
Revises: 002_rls_policies
Create Date: 2026-03-03

Implements Story 1.4 AC6: Per-investigation roles stored in
InvestigationPermission table with user_id, investigation_id, role.

This table is GLOBAL (not tenant-scoped) because:
1. Permission checks need to work across RLS boundaries
2. References tenant-scoped investigations via FK
3. Tenant isolation enforced by investigation_id FK
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "003_investigation_permissions"
down_revision = "002_rls_policies"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Investigation permissions table (global, not tenant-scoped)
    op.create_table(
        "investigation_permissions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("investigation_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(length=50), nullable=False),
        sa.Column("granted_by", sa.Uuid(), nullable=False),
        sa.Column(
            "granted_at",
            sa.DateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["granted_by"],
            ["users.id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "user_id", "investigation_id", name="uq_user_investigation_permission"
        ),
    )

    # Create indexes for performance (AC6 requirement)
    op.create_index(
        "ix_investigation_permissions_user_id",
        "investigation_permissions",
        ["user_id"],
    )
    op.create_index(
        "ix_investigation_permissions_investigation_id",
        "investigation_permissions",
        ["investigation_id"],
    )
    op.create_index(
        "ix_investigation_permissions_role",
        "investigation_permissions",
        ["role"],
    )
    # Compound index for the most common query pattern:
    # SELECT * FROM investigation_permissions WHERE user_id = ? AND investigation_id = ?
    op.create_index(
        "ix_investigation_permissions_user_investigation",
        "investigation_permissions",
        ["user_id", "investigation_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_investigation_permissions_user_investigation",
        table_name="investigation_permissions",
    )
    op.drop_index(
        "ix_investigation_permissions_role", table_name="investigation_permissions"
    )
    op.drop_index(
        "ix_investigation_permissions_investigation_id",
        table_name="investigation_permissions",
    )
    op.drop_index(
        "ix_investigation_permissions_user_id", table_name="investigation_permissions"
    )
    op.drop_table("investigation_permissions")
