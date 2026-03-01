"""Unit tests for Edge and Hypothesis models."""

from app.models.edge import EdgeType, EntityEdge
from app.models.hypothesis import EvidenceItem, Hypothesis, HypothesisStatus


class TestEdgeType:
    """Tests for EdgeType enum."""

    def test_edge_type_values(self) -> None:
        """Verify EdgeType has expected values."""
        assert EdgeType.owns == "owns"
        assert EdgeType.works_at == "works_at"
        assert EdgeType.related_to == "related_to"
        assert EdgeType.controls == "controls"
        assert EdgeType.registered_at == "registered_at"


class TestEntityEdge:
    """Tests for EntityEdge model."""

    def test_edge_is_table(self) -> None:
        """Verify EntityEdge is a database table."""
        assert hasattr(EntityEdge, "__tablename__")
        assert EntityEdge.__tablename__ == "entity_edges"

    def test_edge_is_tenant_scoped(self) -> None:
        """Verify EntityEdge has tenant_id (AC4, AC5)."""
        assert "tenant_id" in EntityEdge.model_fields

    def test_edge_has_source_id(self) -> None:
        """Verify EntityEdge has source_id field."""
        assert "source_id" in EntityEdge.model_fields

    def test_edge_has_target_id(self) -> None:
        """Verify EntityEdge has target_id field."""
        assert "target_id" in EntityEdge.model_fields

    def test_edge_has_type(self) -> None:
        """Verify EntityEdge has edge_type field."""
        assert "edge_type" in EntityEdge.model_fields

    def test_edge_has_confidence(self) -> None:
        """Verify EntityEdge has confidence field."""
        assert "confidence" in EntityEdge.model_fields


class TestHypothesisStatus:
    """Tests for HypothesisStatus enum."""

    def test_status_values(self) -> None:
        """Verify HypothesisStatus has expected values."""
        assert HypothesisStatus.proposed == "proposed"
        assert HypothesisStatus.under_investigation == "under_investigation"
        assert HypothesisStatus.confirmed == "confirmed"
        assert HypothesisStatus.refuted == "refuted"


class TestHypothesis:
    """Tests for Hypothesis model."""

    def test_hypothesis_is_table(self) -> None:
        """Verify Hypothesis is a database table."""
        assert hasattr(Hypothesis, "__tablename__")
        assert Hypothesis.__tablename__ == "hypotheses"

    def test_hypothesis_is_tenant_scoped(self) -> None:
        """Verify Hypothesis has tenant_id (AC4, AC5)."""
        assert "tenant_id" in Hypothesis.model_fields

    def test_hypothesis_has_investigation_id(self) -> None:
        """Verify Hypothesis has investigation_id field."""
        assert "investigation_id" in Hypothesis.model_fields

    def test_hypothesis_has_description(self) -> None:
        """Verify Hypothesis has description field."""
        assert "description" in Hypothesis.model_fields

    def test_hypothesis_has_confidence(self) -> None:
        """Verify Hypothesis has confidence field."""
        assert "confidence" in Hypothesis.model_fields

    def test_hypothesis_has_status(self) -> None:
        """Verify Hypothesis has status field."""
        assert "status" in Hypothesis.model_fields


class TestEvidenceItem:
    """Tests for EvidenceItem model."""

    def test_evidence_is_table(self) -> None:
        """Verify EvidenceItem is a database table."""
        assert hasattr(EvidenceItem, "__tablename__")
        assert EvidenceItem.__tablename__ == "evidence_items"

    def test_evidence_is_tenant_scoped(self) -> None:
        """Verify EvidenceItem has tenant_id (AC4, AC5)."""
        assert "tenant_id" in EvidenceItem.model_fields

    def test_evidence_has_hypothesis_id(self) -> None:
        """Verify EvidenceItem has hypothesis_id field."""
        assert "hypothesis_id" in EvidenceItem.model_fields

    def test_evidence_has_content(self) -> None:
        """Verify EvidenceItem has content field."""
        assert "content" in EvidenceItem.model_fields

    def test_evidence_has_source_url(self) -> None:
        """Verify EvidenceItem has source_url field."""
        assert "source_url" in EvidenceItem.model_fields
