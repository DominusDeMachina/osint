"""Initial schema with all core tables.

Revision ID: 001_initial_schema
Revises:
Create Date: 2026-03-01

Creates all core database tables for the OSINT platform:
- tenants (global)
- users (global)
- tenant_memberships (global)
- investigations (tenant-scoped)
- entities (tenant-scoped)
- investigation_entities (tenant-scoped)
- entity_edges (tenant-scoped)
- hypotheses (tenant-scoped)
- evidence_items (tenant-scoped)
- audit_logs (tenant-scoped)
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001_initial_schema'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- Global tables (no tenant_id) ---

    # Tenants table
    op.create_table(
        'tenants',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('slug', sa.String(length=100), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_tenants_name', 'tenants', ['name'])
    op.create_index('ix_tenants_slug', 'tenants', ['slug'], unique=True)

    # Users table
    op.create_table(
        'users',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('clerk_id', sa.String(length=255), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('avatar_url', sa.String(length=500), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_users_clerk_id', 'users', ['clerk_id'], unique=True)
    op.create_index('ix_users_email', 'users', ['email'], unique=True)

    # Tenant memberships junction table
    op.create_table(
        'tenant_memberships',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('user_id', sa.Uuid(), nullable=False),
        sa.Column('tenant_id', sa.Uuid(), nullable=False),
        sa.Column('role', sa.String(length=50), nullable=False, server_default='viewer'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('user_id', 'tenant_id', name='uq_user_tenant')
    )
    op.create_index('ix_tenant_memberships_user_id', 'tenant_memberships', ['user_id'])
    op.create_index('ix_tenant_memberships_tenant_id', 'tenant_memberships', ['tenant_id'])

    # --- Tenant-scoped tables ---

    # Investigations table
    op.create_table(
        'investigations',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('tenant_id', sa.Uuid(), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.String(length=5000), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='active'),
        sa.Column('owner_id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE')
    )
    op.create_index('ix_investigations_tenant_id', 'investigations', ['tenant_id'])
    op.create_index('ix_investigations_title', 'investigations', ['title'])
    op.create_index('ix_investigations_status', 'investigations', ['status'])
    op.create_index('ix_investigations_owner_id', 'investigations', ['owner_id'])

    # Entities table
    op.create_table(
        'entities',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('tenant_id', sa.Uuid(), nullable=False),
        sa.Column('entity_type', sa.String(length=50), nullable=False),
        sa.Column('name', sa.String(length=500), nullable=False),
        sa.Column('properties', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('source_url', sa.String(length=2000), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE')
    )
    op.create_index('ix_entities_tenant_id', 'entities', ['tenant_id'])
    op.create_index('ix_entities_entity_type', 'entities', ['entity_type'])
    op.create_index('ix_entities_name', 'entities', ['name'])

    # Investigation entities junction table
    op.create_table(
        'investigation_entities',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('tenant_id', sa.Uuid(), nullable=False),
        sa.Column('investigation_id', sa.Uuid(), nullable=False),
        sa.Column('entity_id', sa.Uuid(), nullable=False),
        sa.Column('added_by', sa.Uuid(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['entity_id'], ['entities.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['added_by'], ['users.id'], ondelete='SET NULL'),
        sa.UniqueConstraint('investigation_id', 'entity_id', name='uq_investigation_entity')
    )
    op.create_index('ix_investigation_entities_tenant_id', 'investigation_entities', ['tenant_id'])
    op.create_index('ix_investigation_entities_investigation_id', 'investigation_entities', ['investigation_id'])
    op.create_index('ix_investigation_entities_entity_id', 'investigation_entities', ['entity_id'])

    # Entity edges table
    op.create_table(
        'entity_edges',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('tenant_id', sa.Uuid(), nullable=False),
        sa.Column('source_id', sa.Uuid(), nullable=False),
        sa.Column('target_id', sa.Uuid(), nullable=False),
        sa.Column('edge_type', sa.String(length=50), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('properties', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('source_url', sa.String(length=2000), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['source_id'], ['entities.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_id'], ['entities.id'], ondelete='CASCADE')
    )
    op.create_index('ix_entity_edges_tenant_id', 'entity_edges', ['tenant_id'])
    op.create_index('ix_entity_edges_source_id', 'entity_edges', ['source_id'])
    op.create_index('ix_entity_edges_target_id', 'entity_edges', ['target_id'])
    op.create_index('ix_entity_edges_edge_type', 'entity_edges', ['edge_type'])

    # Hypotheses table
    op.create_table(
        'hypotheses',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('tenant_id', sa.Uuid(), nullable=False),
        sa.Column('investigation_id', sa.Uuid(), nullable=False),
        sa.Column('description', sa.String(length=5000), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.5'),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='proposed'),
        sa.Column('created_by', sa.Uuid(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL')
    )
    op.create_index('ix_hypotheses_tenant_id', 'hypotheses', ['tenant_id'])
    op.create_index('ix_hypotheses_investigation_id', 'hypotheses', ['investigation_id'])
    op.create_index('ix_hypotheses_status', 'hypotheses', ['status'])

    # Evidence items table
    op.create_table(
        'evidence_items',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('tenant_id', sa.Uuid(), nullable=False),
        sa.Column('hypothesis_id', sa.Uuid(), nullable=False),
        sa.Column('content', sa.String(length=5000), nullable=False),
        sa.Column('source_url', sa.String(length=2000), nullable=True),
        sa.Column('weight', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('added_by', sa.Uuid(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['hypothesis_id'], ['hypotheses.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['added_by'], ['users.id'], ondelete='SET NULL')
    )
    op.create_index('ix_evidence_items_tenant_id', 'evidence_items', ['tenant_id'])
    op.create_index('ix_evidence_items_hypothesis_id', 'evidence_items', ['hypothesis_id'])

    # Audit logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('tenant_id', sa.Uuid(), nullable=False),
        sa.Column('action_type', sa.String(length=50), nullable=False),
        sa.Column('actor_id', sa.Uuid(), nullable=False),
        sa.Column('target_type', sa.String(length=100), nullable=False),
        sa.Column('target_id', sa.Uuid(), nullable=True),
        sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('checksum', sa.String(length=64), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.String(length=500), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ondelete='CASCADE')
    )
    op.create_index('ix_audit_logs_tenant_id', 'audit_logs', ['tenant_id'])
    op.create_index('ix_audit_logs_action_type', 'audit_logs', ['action_type'])
    op.create_index('ix_audit_logs_actor_id', 'audit_logs', ['actor_id'])
    op.create_index('ix_audit_logs_target_type', 'audit_logs', ['target_type'])
    op.create_index('ix_audit_logs_target_id', 'audit_logs', ['target_id'])
    op.create_index('ix_audit_logs_created_at', 'audit_logs', ['created_at'])


def downgrade() -> None:
    # Drop tables in reverse order (respecting foreign keys)
    op.drop_table('audit_logs')
    op.drop_table('evidence_items')
    op.drop_table('hypotheses')
    op.drop_table('entity_edges')
    op.drop_table('investigation_entities')
    op.drop_table('entities')
    op.drop_table('investigations')
    op.drop_table('tenant_memberships')
    op.drop_table('users')
    op.drop_table('tenants')
