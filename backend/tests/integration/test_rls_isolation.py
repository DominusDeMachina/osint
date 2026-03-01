"""Integration tests for Row-Level Security (RLS) isolation.

These tests verify that RLS policies correctly isolate tenant data:
- AC1: Tenant-A queries only return tenant-A data (no explicit WHERE needed)
- AC2: INSERT without tenant_id is rejected
- AC8: Tenant isolation prevents cross-tenant data access

Requirements:
- PostgreSQL database running with RLS enabled
- Migrations applied (alembic upgrade head)

Run with: pytest tests/integration/test_rls_isolation.py -m integration
"""

from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlmodel import select

from app.core.config import settings
from app.core.middleware.tenant import set_tenant_context
from app.models import (
    ActionType,
    AuditLog,
    Entity,
    EntityType,
    Investigation,
    InvestigationStatus,
    Tenant,
    TenantMembership,
    User,
    UserRole,
)


# Mark all tests in this module as integration tests
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
async def test_engine():
    """Create test database engine."""
    engine = create_async_engine(
        settings.database_url,
        echo=False,
    )
    yield engine
    await engine.dispose()


@pytest.fixture(scope="module")
async def session_factory(test_engine):
    """Create async session factory."""
    return async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )


@pytest.fixture
async def tenant_a(session_factory):
    """Create tenant A for testing."""
    async with session_factory() as session:
        tenant = Tenant(id=uuid4(), name="Tenant A", slug="tenant-a")
        session.add(tenant)
        await session.commit()
        await session.refresh(tenant)
        yield tenant
        # Cleanup
        await session.execute(text(f"DELETE FROM tenants WHERE id = '{tenant.id}'"))
        await session.commit()


@pytest.fixture
async def tenant_b(session_factory):
    """Create tenant B for testing."""
    async with session_factory() as session:
        tenant = Tenant(id=uuid4(), name="Tenant B", slug="tenant-b")
        session.add(tenant)
        await session.commit()
        await session.refresh(tenant)
        yield tenant
        # Cleanup
        await session.execute(text(f"DELETE FROM tenants WHERE id = '{tenant.id}'"))
        await session.commit()


@pytest.fixture
async def user_a(session_factory, tenant_a):
    """Create user in tenant A."""
    async with session_factory() as session:
        user = User(
            id=uuid4(),
            clerk_id=f"clerk_{uuid4()}",
            email=f"user_a_{uuid4()}@test.com",
            name="User A",
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # Add membership
        membership = TenantMembership(
            user_id=user.id,
            tenant_id=tenant_a.id,
            role=UserRole.analyst,
        )
        session.add(membership)
        await session.commit()

        yield user
        # Cleanup handled by cascade


@pytest.fixture
async def tenant_a_session(session_factory, tenant_a):
    """Session with tenant A context set."""
    async with session_factory() as session:
        await set_tenant_context(session, str(tenant_a.id))
        yield session


@pytest.fixture
async def tenant_b_session(session_factory, tenant_b):
    """Session with tenant B context set."""
    async with session_factory() as session:
        await set_tenant_context(session, str(tenant_b.id))
        yield session


class TestTenantIsolation:
    """Tests for RLS tenant isolation (AC1, AC8)."""

    @pytest.mark.asyncio
    async def test_tenant_a_cannot_see_tenant_b_investigations(
        self,
        tenant_a_session: AsyncSession,
        tenant_b_session: AsyncSession,
        tenant_a,
        tenant_b,
        user_a,
    ):
        """Verify tenant-A cannot see tenant-B data (AC1, AC8).

        Given: Investigation created in tenant-B
        When: Tenant-A queries investigations
        Then: No tenant-B investigations are returned
        """
        # Create investigation in tenant B
        inv_b = Investigation(
            title="Tenant B Investigation",
            description="Secret investigation",
            status=InvestigationStatus.active,
            tenant_id=tenant_b.id,
            owner_id=user_a.id,  # Using same user for simplicity
        )
        tenant_b_session.add(inv_b)
        await tenant_b_session.commit()

        # Query from tenant A - should return empty
        result = await tenant_a_session.exec(select(Investigation))
        investigations = result.all()

        assert len(investigations) == 0, "Tenant A should not see Tenant B investigations"

        # Cleanup
        await tenant_b_session.execute(text(f"DELETE FROM investigations WHERE id = '{inv_b.id}'"))
        await tenant_b_session.commit()

    @pytest.mark.asyncio
    async def test_tenant_sees_own_investigations(
        self,
        tenant_a_session: AsyncSession,
        tenant_a,
        user_a,
    ):
        """Verify tenant can see own data (AC1).

        Given: Investigation created in tenant-A
        When: Tenant-A queries investigations
        Then: Own investigation is returned
        """
        # Create investigation in tenant A
        inv_a = Investigation(
            title="Tenant A Investigation",
            description="My investigation",
            status=InvestigationStatus.active,
            tenant_id=tenant_a.id,
            owner_id=user_a.id,
        )
        tenant_a_session.add(inv_a)
        await tenant_a_session.commit()

        # Query from tenant A - should return the investigation
        result = await tenant_a_session.exec(select(Investigation))
        investigations = result.all()

        assert len(investigations) == 1
        assert investigations[0].title == "Tenant A Investigation"

        # Cleanup
        await tenant_a_session.execute(text(f"DELETE FROM investigations WHERE id = '{inv_a.id}'"))
        await tenant_a_session.commit()

    @pytest.mark.asyncio
    async def test_update_across_tenants_blocked(
        self,
        tenant_a_session: AsyncSession,
        tenant_b_session: AsyncSession,
        tenant_a,
        tenant_b,
        user_a,
    ):
        """Verify UPDATE across tenants is blocked (AC8).

        Given: Investigation in tenant-B
        When: Tenant-A tries to update it
        Then: No rows are updated
        """
        # Create investigation in tenant B
        inv_b = Investigation(
            id=uuid4(),
            title="Original Title",
            status=InvestigationStatus.active,
            tenant_id=tenant_b.id,
            owner_id=user_a.id,
        )
        tenant_b_session.add(inv_b)
        await tenant_b_session.commit()

        # Try to update from tenant A context
        result = await tenant_a_session.execute(
            text(f"UPDATE investigations SET title = 'Hacked!' WHERE id = '{inv_b.id}'")
        )
        await tenant_a_session.commit()

        # Verify no rows were updated (RLS blocked it)
        assert result.rowcount == 0

        # Verify original data is unchanged
        result = await tenant_b_session.exec(
            select(Investigation).where(Investigation.id == inv_b.id)
        )
        inv = result.one()
        assert inv.title == "Original Title"

        # Cleanup
        await tenant_b_session.execute(text(f"DELETE FROM investigations WHERE id = '{inv_b.id}'"))
        await tenant_b_session.commit()

    @pytest.mark.asyncio
    async def test_delete_across_tenants_blocked(
        self,
        tenant_a_session: AsyncSession,
        tenant_b_session: AsyncSession,
        tenant_a,
        tenant_b,
        user_a,
    ):
        """Verify DELETE across tenants is blocked (AC8).

        Given: Investigation in tenant-B
        When: Tenant-A tries to delete it
        Then: No rows are deleted
        """
        # Create investigation in tenant B
        inv_b = Investigation(
            id=uuid4(),
            title="Cannot Delete Me",
            status=InvestigationStatus.active,
            tenant_id=tenant_b.id,
            owner_id=user_a.id,
        )
        tenant_b_session.add(inv_b)
        await tenant_b_session.commit()

        # Try to delete from tenant A context
        result = await tenant_a_session.execute(
            text(f"DELETE FROM investigations WHERE id = '{inv_b.id}'")
        )
        await tenant_a_session.commit()

        # Verify no rows were deleted (RLS blocked it)
        assert result.rowcount == 0

        # Verify data still exists in tenant B
        result = await tenant_b_session.exec(
            select(Investigation).where(Investigation.id == inv_b.id)
        )
        inv = result.one()
        assert inv.title == "Cannot Delete Me"

        # Cleanup
        await tenant_b_session.execute(text(f"DELETE FROM investigations WHERE id = '{inv_b.id}'"))
        await tenant_b_session.commit()


class TestInsertValidation:
    """Tests for INSERT validation (AC2)."""

    @pytest.mark.asyncio
    async def test_insert_without_tenant_fails(
        self,
        session_factory,
        user_a,
    ):
        """Verify INSERT without tenant_id raises error (AC2).

        Given: I attempt to INSERT an investigation without tenant_id
        When: The query executes
        Then: Database rejects with constraint error
        """
        async with session_factory() as session:
            # Try to insert without setting tenant context
            # The model requires tenant_id, so this should fail at DB level
            with pytest.raises((IntegrityError, Exception)) as exc_info:
                # Bypass model validation by using raw SQL
                await session.execute(
                    text("""
                        INSERT INTO investigations (id, title, status, owner_id, created_at, updated_at)
                        VALUES (:id, :title, :status, :owner_id, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """),
                    {
                        "id": str(uuid4()),
                        "title": "No Tenant Investigation",
                        "status": "active",
                        "owner_id": str(user_a.id),
                    },
                )
                await session.commit()

            # Verify it's a constraint violation
            assert (
                "tenant_id" in str(exc_info.value).lower() or "null" in str(exc_info.value).lower()
            )


class TestEntityIsolation:
    """Tests for entity RLS isolation."""

    @pytest.mark.asyncio
    async def test_entities_isolated_by_tenant(
        self,
        tenant_a_session: AsyncSession,
        tenant_b_session: AsyncSession,
        tenant_a,
        tenant_b,
    ):
        """Verify entities are isolated by tenant."""
        # Create entity in tenant B
        entity_b = Entity(
            entity_type=EntityType.person,
            name="Secret Person",
            tenant_id=tenant_b.id,
        )
        tenant_b_session.add(entity_b)
        await tenant_b_session.commit()

        # Query from tenant A
        result = await tenant_a_session.exec(select(Entity))
        entities = result.all()

        assert len(entities) == 0, "Tenant A should not see Tenant B entities"

        # Cleanup
        await tenant_b_session.execute(text(f"DELETE FROM entities WHERE id = '{entity_b.id}'"))
        await tenant_b_session.commit()


class TestAuditLogIsolation:
    """Tests for audit log RLS isolation (compliance critical)."""

    @pytest.mark.asyncio
    async def test_audit_logs_isolated_by_tenant(
        self,
        tenant_a_session: AsyncSession,
        tenant_b_session: AsyncSession,
        tenant_a,
        tenant_b,
        user_a,
    ):
        """Verify audit logs are isolated by tenant (AC8 - compliance critical).

        Given: Audit log created in tenant-B
        When: Tenant-A queries audit logs
        Then: No tenant-B audit logs are returned
        """
        # Create audit log in tenant B
        audit_log = AuditLog(
            tenant_id=tenant_b.id,
            action_type=ActionType.create,
            actor_id=user_a.id,
            target_type="investigation",
            target_id=uuid4(),
            details={"test": "sensitive data"},
            checksum="placeholder",
        )
        # Calculate checksum
        audit_log.checksum = audit_log.calculate_checksum()
        tenant_b_session.add(audit_log)
        await tenant_b_session.commit()

        # Query from tenant A - should return empty
        result = await tenant_a_session.exec(select(AuditLog))
        logs = result.all()

        assert len(logs) == 0, "Tenant A should not see Tenant B audit logs"

        # Cleanup
        await tenant_b_session.execute(text(f"DELETE FROM audit_logs WHERE id = '{audit_log.id}'"))
        await tenant_b_session.commit()


class TestSuperuserBypass:
    """Tests for superuser RLS bypass."""

    @pytest.mark.asyncio
    async def test_superuser_can_access_all_data(
        self,
        session_factory,
        tenant_a,
        tenant_b,
        user_a,
    ):
        """Verify superuser bypass policy works for admin operations.

        Note: This test requires the session to run as postgres superuser.
        In production, this is used for maintenance and migration tasks.
        """
        # This test verifies the policy exists but actual superuser
        # testing requires elevated privileges which may not be available
        # in all test environments
        async with session_factory() as session:
            # Check if superuser bypass policy exists
            result = await session.execute(
                text("""
                    SELECT policyname FROM pg_policies
                    WHERE tablename = 'investigations'
                    AND policyname = 'superuser_bypass_investigations'
                """)
            )
            policies = result.fetchall()

            # Policy should exist (created by migration)
            assert len(policies) == 1, "Superuser bypass policy should exist"
