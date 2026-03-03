"""Add signup_ip_hash column to users table for GDPR compliance.

Revision ID: 004_add_signup_ip_hash
Revises: 003_investigation_permissions
Create Date: 2026-03-03

Implements Story 1.5 AC21: GDPR compliance endpoint for IP hash data deletion.
Stores SHA256[:16] of signup IP for later GDPR deletion requests.
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "004_add_signup_ip_hash"
down_revision = "003_investigation_permissions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add signup_ip_hash column to users table
    # This stores the SHA256[:16] hash of the user's signup IP address
    # for GDPR compliance - allows users to request deletion of their IP data
    op.add_column(
        "users",
        sa.Column("signup_ip_hash", sa.String(length=16), nullable=True),
    )

    # Create index for efficient lookup during GDPR deletion requests
    op.create_index(
        "ix_users_signup_ip_hash",
        "users",
        ["signup_ip_hash"],
    )


def downgrade() -> None:
    op.drop_index("ix_users_signup_ip_hash", table_name="users")
    op.drop_column("users", "signup_ip_hash")
