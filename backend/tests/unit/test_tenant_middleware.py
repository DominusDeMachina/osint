"""Unit tests for tenant context middleware."""

import inspect
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.core.middleware.tenant import get_tenant_db, set_tenant_context


class TestSetTenantContext:
    """Tests for set_tenant_context function."""

    @pytest.mark.asyncio
    async def test_set_tenant_context_executes_sql(self) -> None:
        """Verify set_tenant_context executes SET LOCAL statement (AC6, AC7)."""
        mock_session = AsyncMock()
        tenant_id = uuid4()

        await set_tenant_context(mock_session, str(tenant_id))

        # Verify execute was called
        mock_session.execute.assert_called_once()

        # Verify the SQL contains SET LOCAL app.current_tenant
        call_args = mock_session.execute.call_args
        sql_text = str(call_args[0][0])
        assert "SET LOCAL app.current_tenant" in sql_text


class TestGetTenantDb:
    """Tests for get_tenant_db dependency."""

    def test_get_tenant_db_is_async_generator(self) -> None:
        """Verify get_tenant_db is an async generator function."""
        assert inspect.isasyncgenfunction(get_tenant_db)
