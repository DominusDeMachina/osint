"""Setup Row-Level Security (RLS) policies.

Revision ID: 002_rls_policies
Revises: 001_initial_schema
Create Date: 2026-03-01

Implements multi-tenant RLS for all tenant-scoped tables:
- Creates get_current_tenant() function
- Enables RLS on all tenant-scoped tables
- Creates tenant isolation policies
- Forces RLS even for table owners (FORCE ROW LEVEL SECURITY)

AC1: Queries automatically filter by tenant_id from JWT
AC3: RLS cannot be bypassed by application queries
AC6: Uses app.current_tenant session variable
"""
from alembic import op


# revision identifiers, used by Alembic.
revision = '002_rls_policies'
down_revision = '001_initial_schema'
branch_labels = None
depends_on = None

# All tenant-scoped tables that need RLS
TENANT_SCOPED_TABLES = [
    'investigations',
    'entities',
    'investigation_entities',
    'entity_edges',
    'hypotheses',
    'evidence_items',
    'audit_logs',
]


def upgrade() -> None:
    # Create function to get current tenant from session variable
    op.execute("""
        CREATE OR REPLACE FUNCTION get_current_tenant()
        RETURNS UUID AS $$
        BEGIN
            RETURN current_setting('app.current_tenant', true)::uuid;
        EXCEPTION
            WHEN OTHERS THEN
                RETURN NULL;
        END;
        $$ LANGUAGE plpgsql STABLE;
    """)

    # Enable RLS and create policies for each tenant-scoped table
    for table in TENANT_SCOPED_TABLES:
        # Enable RLS on table
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")

        # Force RLS even for table owners (prevents bypass)
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")

        # Create tenant isolation policy
        # USING clause: controls which rows can be seen (SELECT, UPDATE, DELETE)
        # WITH CHECK clause: controls which rows can be inserted/updated
        op.execute(f"""
            CREATE POLICY tenant_isolation_{table} ON {table}
                USING (tenant_id = get_current_tenant())
                WITH CHECK (tenant_id = get_current_tenant());
        """)

    # Create superuser bypass policy for admin operations
    # This allows the postgres superuser to access all data for maintenance
    # Works with: standard PostgreSQL superuser, AWS RDS rds_superuser, or explicit bypass flag
    for table in TENANT_SCOPED_TABLES:
        op.execute(f"""
            CREATE POLICY superuser_bypass_{table} ON {table}
                USING (
                    current_setting('is_superuser', true) = 'on'
                    OR current_setting('role', true) = 'rds_superuser'
                    OR current_setting('app.bypass_rls', true) = 'on'
                )
                WITH CHECK (
                    current_setting('is_superuser', true) = 'on'
                    OR current_setting('role', true) = 'rds_superuser'
                    OR current_setting('app.bypass_rls', true) = 'on'
                );
        """)


def downgrade() -> None:
    # Drop policies and disable RLS in reverse order
    for table in TENANT_SCOPED_TABLES:
        op.execute(f"DROP POLICY IF EXISTS superuser_bypass_{table} ON {table};")
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_{table} ON {table};")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")

    # Drop the tenant function
    op.execute("DROP FUNCTION IF EXISTS get_current_tenant();")
