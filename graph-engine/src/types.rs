//! Core types for the OSINT graph engine

use pyo3::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Types of entities that can exist in the investigation graph
#[pyclass(eq, eq_int, from_py_object)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityType {
    /// A person (individual)
    Person,
    /// A company or organization
    Company,
    /// A domain name
    Domain,
    /// An IP address
    IpAddress,
    /// An email address
    Email,
    /// A phone number
    Phone,
    /// A physical address
    Address,
    /// A social media account
    SocialMedia,
    /// A cryptocurrency wallet
    CryptoWallet,
    /// A document or file
    Document,
    /// A generic/unknown entity type
    Unknown,
}

#[pymethods]
impl EntityType {
    fn __str__(&self) -> String {
        format!("{:?}", self)
    }

    fn __repr__(&self) -> String {
        format!("EntityType.{:?}", self)
    }
}

/// Types of relationships between entities
#[pyclass(eq, eq_int, from_py_object)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelationshipType {
    /// Person is employed by company
    EmployedBy,
    /// Person owns/controls entity
    Owns,
    /// Entity is related to another entity
    RelatedTo,
    /// Entity is associated with another entity
    AssociatedWith,
    /// Domain resolves to IP address
    ResolvesTo,
    /// Entity is registered at address
    RegisteredAt,
    /// Entity uses email/phone
    Uses,
    /// Entity is a subsidiary of another
    SubsidiaryOf,
    /// Entity is a director/officer of company
    DirectorOf,
    /// Entity is a shareholder of company
    ShareholderOf,
    /// Transaction between entities
    TransactedWith,
    /// Entity contacted another entity
    Contacted,
    /// Generic connection
    ConnectedTo,
}

#[pymethods]
impl RelationshipType {
    fn __str__(&self) -> String {
        format!("{:?}", self)
    }

    fn __repr__(&self) -> String {
        format!("RelationshipType.{:?}", self)
    }
}

/// An entity node in the investigation graph
#[pyclass(from_py_object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    /// Unique identifier for the entity
    #[pyo3(get)]
    pub id: String,

    /// Type of entity
    #[pyo3(get)]
    pub entity_type: EntityType,

    /// Display name/label for the entity
    #[pyo3(get)]
    pub name: String,

    /// Additional metadata as JSON
    #[pyo3(get)]
    pub metadata: Option<String>,

    /// Confidence score (0.0 to 1.0)
    #[pyo3(get)]
    pub confidence: f64,
}

#[pymethods]
impl Entity {
    #[new]
    #[pyo3(signature = (id, entity_type, name, metadata=None, confidence=1.0))]
    pub fn new(
        id: &str,
        entity_type: EntityType,
        name: &str,
        metadata: Option<String>,
        confidence: f64,
    ) -> Self {
        Self {
            id: id.to_string(),
            entity_type,
            name: name.to_string(),
            metadata,
            confidence,
        }
    }

    /// Create entity with auto-generated UUID
    #[staticmethod]
    #[pyo3(signature = (entity_type, name, metadata=None, confidence=1.0))]
    pub fn create(
        entity_type: EntityType,
        name: &str,
        metadata: Option<String>,
        confidence: f64,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            entity_type,
            name: name.to_string(),
            metadata,
            confidence,
        }
    }

    fn __str__(&self) -> String {
        format!(
            "Entity({}: {} - {})",
            self.id,
            self.entity_type.__str__(),
            self.name
        )
    }

    fn __repr__(&self) -> String {
        format!(
            "Entity(id='{}', type={:?}, name='{}', confidence={})",
            self.id, self.entity_type, self.name, self.confidence
        )
    }
}

/// An edge (relationship) in the investigation graph
#[pyclass(from_py_object)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    /// Source entity ID (internal graph index)
    #[pyo3(get)]
    pub source: usize,

    /// Target entity ID (internal graph index)
    #[pyo3(get)]
    pub target: usize,

    /// Type of relationship
    #[pyo3(get)]
    pub relationship_type: RelationshipType,

    /// Relationship strength/weight (0.0 to 1.0)
    #[pyo3(get)]
    pub weight: f64,

    /// Additional metadata as JSON
    #[pyo3(get)]
    pub metadata: Option<String>,
}

#[pymethods]
impl Edge {
    #[new]
    #[pyo3(signature = (source, target, relationship_type, weight=1.0, metadata=None))]
    pub fn new(
        source: usize,
        target: usize,
        relationship_type: RelationshipType,
        weight: f64,
        metadata: Option<String>,
    ) -> Self {
        Self {
            source,
            target,
            relationship_type,
            weight,
            metadata,
        }
    }

    fn __str__(&self) -> String {
        format!(
            "Edge({} --[{}]--> {})",
            self.source,
            self.relationship_type.__str__(),
            self.target
        )
    }

    fn __repr__(&self) -> String {
        format!(
            "Edge(source={}, target={}, type={:?}, weight={})",
            self.source, self.target, self.relationship_type, self.weight
        )
    }
}
