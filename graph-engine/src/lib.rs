//! OSINT Graph Engine - High-performance graph processing for investigations
//!
//! This crate provides a Rust-based graph engine with Python bindings via PyO3.
//! It powers the graph visualization and analysis features of the OSINT platform.

mod graph;
mod types;

use pyo3::prelude::*;
use pyo3::types::PyModule;

pub use graph::GraphEngine;
pub use types::{Edge, Entity, EntityType, RelationshipType};

/// Python module initialization
#[pymodule]
fn osint_graph_engine(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<GraphEngine>()?;
    m.add_class::<Entity>()?;
    m.add_class::<Edge>()?;
    m.add_class::<EntityType>()?;
    m.add_class::<RelationshipType>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_engine_creation() {
        let engine = GraphEngine::new();
        assert_eq!(engine.node_count(), 0);
        assert_eq!(engine.edge_count(), 0);
    }

    #[test]
    fn test_add_entity() {
        let mut engine = GraphEngine::new();
        let entity = Entity::new("test-id", EntityType::Person, "John Doe");
        let node_id = engine.add_entity(entity);
        assert!(node_id.is_some());
        assert_eq!(engine.node_count(), 1);
    }

    #[test]
    fn test_add_relationship() {
        let mut engine = GraphEngine::new();

        let person = Entity::new("person-1", EntityType::Person, "John Doe");
        let company = Entity::new("company-1", EntityType::Company, "Acme Corp");

        let person_id = engine.add_entity(person).unwrap();
        let company_id = engine.add_entity(company).unwrap();

        let edge = Edge::new(person_id, company_id, RelationshipType::EmployedBy);
        let edge_id = engine.add_relationship(edge);

        assert!(edge_id.is_some());
        assert_eq!(engine.edge_count(), 1);
    }
}
