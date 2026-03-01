"""Unit tests for Investigation and Entity models."""

from app.models.entity import Entity, EntityType, InvestigationEntity
from app.models.investigation import Investigation, InvestigationStatus


class TestInvestigationStatus:
    """Tests for InvestigationStatus enum."""

    def test_status_values(self) -> None:
        """Verify InvestigationStatus has expected values."""
        assert InvestigationStatus.active == "active"
        assert InvestigationStatus.paused == "paused"
        assert InvestigationStatus.closed == "closed"


class TestInvestigationModel:
    """Tests for Investigation model."""

    def test_investigation_is_table(self) -> None:
        """Verify Investigation is a database table."""
        assert hasattr(Investigation, "__tablename__")
        assert Investigation.__tablename__ == "investigations"

    def test_investigation_is_tenant_scoped(self) -> None:
        """Verify Investigation has tenant_id (AC4, AC5)."""
        assert "tenant_id" in Investigation.model_fields

    def test_investigation_has_title(self) -> None:
        """Verify Investigation has title field."""
        assert "title" in Investigation.model_fields

    def test_investigation_has_description(self) -> None:
        """Verify Investigation has description field."""
        assert "description" in Investigation.model_fields

    def test_investigation_has_status(self) -> None:
        """Verify Investigation has status field."""
        assert "status" in Investigation.model_fields

    def test_investigation_has_owner_id(self) -> None:
        """Verify Investigation has owner_id field."""
        assert "owner_id" in Investigation.model_fields

    def test_investigation_has_timestamps(self) -> None:
        """Verify Investigation has timestamp fields."""
        assert "created_at" in Investigation.model_fields
        assert "updated_at" in Investigation.model_fields


class TestEntityType:
    """Tests for EntityType enum."""

    def test_entity_type_values(self) -> None:
        """Verify EntityType has expected values from PRD."""
        assert EntityType.person == "person"
        assert EntityType.organization == "organization"
        assert EntityType.domain == "domain"
        assert EntityType.email == "email"
        assert EntityType.phone == "phone"
        assert EntityType.address == "address"


class TestEntityModel:
    """Tests for Entity model."""

    def test_entity_is_table(self) -> None:
        """Verify Entity is a database table."""
        assert hasattr(Entity, "__tablename__")
        assert Entity.__tablename__ == "entities"

    def test_entity_is_tenant_scoped(self) -> None:
        """Verify Entity has tenant_id (AC4, AC5)."""
        assert "tenant_id" in Entity.model_fields

    def test_entity_has_type(self) -> None:
        """Verify Entity has type field."""
        assert "entity_type" in Entity.model_fields

    def test_entity_has_name(self) -> None:
        """Verify Entity has name field."""
        assert "name" in Entity.model_fields

    def test_entity_has_properties(self) -> None:
        """Verify Entity has properties field (JSONB)."""
        assert "properties" in Entity.model_fields

    def test_entity_has_confidence(self) -> None:
        """Verify Entity has confidence field."""
        assert "confidence" in Entity.model_fields


class TestInvestigationEntity:
    """Tests for InvestigationEntity junction table."""

    def test_junction_is_table(self) -> None:
        """Verify InvestigationEntity is a database table."""
        assert hasattr(InvestigationEntity, "__tablename__")
        assert InvestigationEntity.__tablename__ == "investigation_entities"

    def test_junction_has_investigation_id(self) -> None:
        """Verify InvestigationEntity has investigation_id."""
        assert "investigation_id" in InvestigationEntity.model_fields

    def test_junction_has_entity_id(self) -> None:
        """Verify InvestigationEntity has entity_id."""
        assert "entity_id" in InvestigationEntity.model_fields

    def test_junction_is_tenant_scoped(self) -> None:
        """Verify junction table has tenant_id."""
        assert "tenant_id" in InvestigationEntity.model_fields
