"""Unit tests for AuditLog model."""

from app.models.audit import ActionType, AuditLog


class TestActionType:
    """Tests for ActionType enum."""

    def test_action_type_values(self) -> None:
        """Verify ActionType has expected values."""
        assert ActionType.create == "create"
        assert ActionType.read == "read"
        assert ActionType.update == "update"
        assert ActionType.delete == "delete"
        assert ActionType.export == "export"
        assert ActionType.login == "login"
        assert ActionType.logout == "logout"


class TestAuditLog:
    """Tests for AuditLog model."""

    def test_audit_is_table(self) -> None:
        """Verify AuditLog is a database table."""
        assert hasattr(AuditLog, "__tablename__")
        assert AuditLog.__tablename__ == "audit_logs"

    def test_audit_is_tenant_scoped(self) -> None:
        """Verify AuditLog has tenant_id (AC4)."""
        assert "tenant_id" in AuditLog.model_fields

    def test_audit_has_action_type(self) -> None:
        """Verify AuditLog has action_type field."""
        assert "action_type" in AuditLog.model_fields

    def test_audit_has_actor_id(self) -> None:
        """Verify AuditLog has actor_id field."""
        assert "actor_id" in AuditLog.model_fields

    def test_audit_has_target_type(self) -> None:
        """Verify AuditLog has target_type field."""
        assert "target_type" in AuditLog.model_fields

    def test_audit_has_target_id(self) -> None:
        """Verify AuditLog has target_id field."""
        assert "target_id" in AuditLog.model_fields

    def test_audit_has_details(self) -> None:
        """Verify AuditLog has details field (JSONB)."""
        assert "details" in AuditLog.model_fields

    def test_audit_has_checksum(self) -> None:
        """Verify AuditLog has checksum field for integrity."""
        assert "checksum" in AuditLog.model_fields

    def test_audit_has_calculate_checksum_method(self) -> None:
        """Verify AuditLog has method for HMAC-SHA256 checksum."""
        assert hasattr(AuditLog, "calculate_checksum")
        assert callable(AuditLog.calculate_checksum)
