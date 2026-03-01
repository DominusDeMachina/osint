//! Graph engine implementation using petgraph

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use pyo3::prelude::*;

use crate::types::{Edge, Entity, RelationshipType};

/// Main graph engine for OSINT investigations
#[pyclass]
pub struct GraphEngine {
    /// Internal directed graph structure
    graph: DiGraph<Entity, Edge>,
}

#[pymethods]
impl GraphEngine {
    /// Create a new empty graph engine
    #[new]
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
        }
    }

    /// Get the number of nodes (entities) in the graph
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Get the number of edges (relationships) in the graph
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Add an entity to the graph
    ///
    /// Returns the internal node index for the entity
    pub fn add_entity(&mut self, entity: Entity) -> Option<usize> {
        let idx = self.graph.add_node(entity);
        Some(idx.index())
    }

    /// Add a relationship between two entities
    ///
    /// Returns the internal edge index
    pub fn add_relationship(&mut self, edge: Edge) -> Option<usize> {
        let source = NodeIndex::new(edge.source);
        let target = NodeIndex::new(edge.target);

        // Verify both nodes exist
        if self.graph.node_weight(source).is_none() || self.graph.node_weight(target).is_none() {
            return None;
        }

        let idx = self.graph.add_edge(source, target, edge);
        Some(idx.index())
    }

    /// Get an entity by its internal index
    pub fn get_entity(&self, index: usize) -> Option<Entity> {
        let node_idx = NodeIndex::new(index);
        self.graph.node_weight(node_idx).cloned()
    }

    /// Get all entities in the graph
    pub fn get_all_entities(&self) -> Vec<Entity> {
        self.graph
            .node_indices()
            .filter_map(|idx| self.graph.node_weight(idx).cloned())
            .collect()
    }

    /// Get all edges in the graph
    pub fn get_all_edges(&self) -> Vec<Edge> {
        self.graph
            .edge_indices()
            .filter_map(|idx| self.graph.edge_weight(idx).cloned())
            .collect()
    }

    /// Find neighbors of an entity (outgoing connections)
    pub fn get_neighbors(&self, index: usize) -> Vec<usize> {
        let node_idx = NodeIndex::new(index);
        self.graph
            .neighbors_directed(node_idx, Direction::Outgoing)
            .map(|idx| idx.index())
            .collect()
    }

    /// Find entities connected to this one (incoming connections)
    pub fn get_incoming(&self, index: usize) -> Vec<usize> {
        let node_idx = NodeIndex::new(index);
        self.graph
            .neighbors_directed(node_idx, Direction::Incoming)
            .map(|idx| idx.index())
            .collect()
    }

    /// Get all connections for an entity (both incoming and outgoing)
    pub fn get_connections(&self, index: usize) -> Vec<usize> {
        let mut connections = self.get_neighbors(index);
        connections.extend(self.get_incoming(index));
        connections.sort();
        connections.dedup();
        connections
    }

    /// Find entities by type
    pub fn find_by_type(&self, entity_type: crate::types::EntityType) -> Vec<usize> {
        self.graph
            .node_indices()
            .filter(|&idx| {
                self.graph
                    .node_weight(idx)
                    .map(|e| e.entity_type == entity_type)
                    .unwrap_or(false)
            })
            .map(|idx| idx.index())
            .collect()
    }

    /// Find relationships by type
    pub fn find_relationships_by_type(&self, rel_type: RelationshipType) -> Vec<Edge> {
        self.graph
            .edge_indices()
            .filter_map(|idx| {
                let edge = self.graph.edge_weight(idx)?;
                if edge.relationship_type == rel_type {
                    Some(edge.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Remove an entity from the graph
    ///
    /// Returns true if the entity was removed
    pub fn remove_entity(&mut self, index: usize) -> bool {
        let node_idx = NodeIndex::new(index);
        self.graph.remove_node(node_idx).is_some()
    }

    /// Clear all entities and relationships from the graph
    pub fn clear(&mut self) {
        self.graph.clear();
    }

    /// Export graph to JSON format
    pub fn to_json(&self) -> String {
        let entities: Vec<_> = self.get_all_entities();
        let edges: Vec<_> = self.get_all_edges();

        serde_json::json!({
            "nodes": entities,
            "edges": edges
        })
        .to_string()
    }

    fn __str__(&self) -> String {
        format!(
            "GraphEngine(nodes={}, edges={})",
            self.node_count(),
            self.edge_count()
        )
    }

    fn __repr__(&self) -> String {
        self.__str__()
    }
}

impl Default for GraphEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EntityType;

    #[test]
    fn test_find_by_type() {
        let mut engine = GraphEngine::new();

        engine.add_entity(Entity::new("p1", EntityType::Person, "Person 1", None, 1.0));
        engine.add_entity(Entity::new("p2", EntityType::Person, "Person 2", None, 1.0));
        engine.add_entity(Entity::new(
            "c1",
            EntityType::Company,
            "Company 1",
            None,
            1.0,
        ));

        let people = engine.find_by_type(EntityType::Person);
        assert_eq!(people.len(), 2);

        let companies = engine.find_by_type(EntityType::Company);
        assert_eq!(companies.len(), 1);
    }

    #[test]
    fn test_connections() {
        let mut engine = GraphEngine::new();

        let p1 = engine
            .add_entity(Entity::new("p1", EntityType::Person, "Person 1", None, 1.0))
            .unwrap();
        let c1 = engine
            .add_entity(Entity::new(
                "c1",
                EntityType::Company,
                "Company 1",
                None,
                1.0,
            ))
            .unwrap();
        let c2 = engine
            .add_entity(Entity::new(
                "c2",
                EntityType::Company,
                "Company 2",
                None,
                1.0,
            ))
            .unwrap();

        engine.add_relationship(Edge::new(p1, c1, RelationshipType::EmployedBy, 1.0, None));
        engine.add_relationship(Edge::new(p1, c2, RelationshipType::DirectorOf, 1.0, None));

        let neighbors = engine.get_neighbors(p1);
        assert_eq!(neighbors.len(), 2);

        let connections = engine.get_connections(p1);
        assert_eq!(connections.len(), 2);
    }

    #[test]
    fn test_to_json() {
        let mut engine = GraphEngine::new();

        engine.add_entity(Entity::new("p1", EntityType::Person, "Test", None, 1.0));

        let json = engine.to_json();
        assert!(json.contains("nodes"));
        assert!(json.contains("edges"));
        assert!(json.contains("Test"));
    }
}
