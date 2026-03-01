"""Integration tests for Clerk webhook handler."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.api.v1.webhooks.clerk import (
    handle_user_created,
    handle_user_deleted,
    handle_user_updated,
)
from app.main import app
from app.models.user import User


class TestClerkWebhook:
    """Integration tests for Clerk webhook endpoint."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    @pytest.fixture
    def user_created_payload(self):
        """Sample user.created webhook payload."""
        return {
            "type": "user.created",
            "data": {
                "id": "user_test123",
                "email_addresses": [{"email_address": "test@example.com", "id": "email_123"}],
                "first_name": "Test",
                "last_name": "User",
                "image_url": "https://example.com/avatar.jpg",
            },
        }

    @pytest.fixture
    def user_updated_payload(self):
        """Sample user.updated webhook payload."""
        return {
            "type": "user.updated",
            "data": {
                "id": "user_test123",
                "email_addresses": [{"email_address": "updated@example.com", "id": "email_123"}],
                "first_name": "Updated",
                "last_name": "Name",
                "image_url": "https://example.com/new-avatar.jpg",
            },
        }

    @pytest.fixture
    def user_deleted_payload(self):
        """Sample user.deleted webhook payload."""
        return {
            "type": "user.deleted",
            "data": {
                "id": "user_test123",
            },
        }

    def test_webhook_requires_svix_headers(self, client):
        """Test webhook rejects requests without Svix headers."""
        response = client.post(
            "/api/v1/webhooks/clerk",
            json={"type": "user.created", "data": {}},
        )
        # Should fail due to missing webhook secret or invalid signature
        assert response.status_code in [400, 500]

    @patch("app.api.v1.webhooks.clerk.verify_webhook")
    @patch("app.api.v1.webhooks.clerk.handle_user_created")
    def test_user_created_webhook(self, mock_handle, mock_verify, client, user_created_payload):
        """Test user.created webhook is processed correctly."""
        mock_verify.return_value = user_created_payload
        mock_handle.return_value = None

        response = client.post(
            "/api/v1/webhooks/clerk",
            json=user_created_payload,
            headers={
                "svix-id": "test-id",
                "svix-timestamp": "1234567890",
                "svix-signature": "test-signature",
            },
        )

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
        mock_handle.assert_called_once_with(user_created_payload["data"])

    @patch("app.api.v1.webhooks.clerk.verify_webhook")
    @patch("app.api.v1.webhooks.clerk.handle_user_updated")
    def test_user_updated_webhook(self, mock_handle, mock_verify, client, user_updated_payload):
        """Test user.updated webhook is processed correctly."""
        mock_verify.return_value = user_updated_payload
        mock_handle.return_value = None

        response = client.post(
            "/api/v1/webhooks/clerk",
            json=user_updated_payload,
            headers={
                "svix-id": "test-id",
                "svix-timestamp": "1234567890",
                "svix-signature": "test-signature",
            },
        )

        assert response.status_code == 200
        mock_handle.assert_called_once_with(user_updated_payload["data"])

    @patch("app.api.v1.webhooks.clerk.verify_webhook")
    @patch("app.api.v1.webhooks.clerk.handle_user_deleted")
    def test_user_deleted_webhook(self, mock_handle, mock_verify, client, user_deleted_payload):
        """Test user.deleted webhook is processed correctly."""
        mock_verify.return_value = user_deleted_payload
        mock_handle.return_value = None

        response = client.post(
            "/api/v1/webhooks/clerk",
            json=user_deleted_payload,
            headers={
                "svix-id": "test-id",
                "svix-timestamp": "1234567890",
                "svix-signature": "test-signature",
            },
        )

        assert response.status_code == 200
        mock_handle.assert_called_once_with(user_deleted_payload["data"])

    @patch("app.api.v1.webhooks.clerk.verify_webhook")
    def test_unknown_event_type_ignored(self, mock_verify, client):
        """Test unknown event types are ignored gracefully."""
        payload = {"type": "unknown.event", "data": {}}
        mock_verify.return_value = payload

        response = client.post(
            "/api/v1/webhooks/clerk",
            json=payload,
            headers={
                "svix-id": "test-id",
                "svix-timestamp": "1234567890",
                "svix-signature": "test-signature",
            },
        )

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestWebhookHandlers:
    """Tests for webhook handler functions."""

    @pytest.mark.asyncio
    @patch("app.api.v1.webhooks.clerk.async_session_maker")
    async def test_handle_user_created_creates_user_and_tenant(self, mock_session_maker):
        """Test handle_user_created creates user, tenant, and membership."""
        # Setup mock session
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(
            return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None))
        )
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()
        mock_session.commit = AsyncMock()

        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_session
        mock_context.__aexit__.return_value = None
        mock_session_maker.return_value = mock_context

        data = {
            "id": "user_new123",
            "email_addresses": [{"email_address": "new@example.com"}],
            "first_name": "New",
            "last_name": "User",
            "image_url": "https://example.com/avatar.jpg",
        }

        await handle_user_created(data)

        # Verify session.add was called for User, Tenant, and TenantMembership
        assert mock_session.add.call_count == 3
        assert mock_session.commit.called

    @pytest.mark.asyncio
    @patch("app.api.v1.webhooks.clerk.async_session_maker")
    async def test_handle_user_created_skips_existing_user(self, mock_session_maker):
        """Test handle_user_created skips if user already exists."""
        # Mock existing user
        existing_user = MagicMock(spec=User)

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_user
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()

        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_session
        mock_context.__aexit__.return_value = None
        mock_session_maker.return_value = mock_context

        data = {
            "id": "user_existing123",
            "email_addresses": [{"email_address": "existing@example.com"}],
            "first_name": "Existing",
            "last_name": "User",
        }

        await handle_user_created(data)

        # Should not add any new records
        assert mock_session.add.call_count == 0

    @pytest.mark.asyncio
    @patch("app.api.v1.webhooks.clerk.async_session_maker")
    async def test_handle_user_updated_updates_user(self, mock_session_maker):
        """Test handle_user_updated syncs user changes."""
        # Mock existing user
        mock_user = MagicMock(spec=User)
        mock_user.email = "old@example.com"
        mock_user.name = "Old Name"
        mock_user.avatar_url = "https://old.com/avatar.jpg"

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()

        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_session
        mock_context.__aexit__.return_value = None
        mock_session_maker.return_value = mock_context

        data = {
            "id": "user_test123",
            "email_addresses": [{"email_address": "new@example.com"}],
            "first_name": "New",
            "last_name": "Name",
            "image_url": "https://new.com/avatar.jpg",
        }

        await handle_user_updated(data)

        # Verify user attributes were updated
        assert mock_user.email == "new@example.com"
        assert mock_user.name == "New Name"
        assert mock_user.avatar_url == "https://new.com/avatar.jpg"
        assert mock_session.commit.called

    @pytest.mark.asyncio
    @patch("app.api.v1.webhooks.clerk.async_session_maker")
    async def test_handle_user_deleted_soft_deletes(self, mock_session_maker):
        """Test handle_user_deleted sets is_active=False."""
        # Mock existing user
        mock_user = MagicMock(spec=User)
        mock_user.is_active = True

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()

        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_session
        mock_context.__aexit__.return_value = None
        mock_session_maker.return_value = mock_context

        data = {"id": "user_test123"}

        await handle_user_deleted(data)

        # Verify user was soft deleted
        assert mock_user.is_active is False
        assert mock_session.commit.called
