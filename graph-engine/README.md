# OSINT Graph Engine

High-performance graph processing engine for OSINT investigations, written in Rust with Python bindings.

## Overview

This crate provides the core graph processing capabilities for the OSINT platform:

- **Entity Management**: Add, query, and remove entities (people, companies, domains, etc.)
- **Relationship Tracking**: Model connections between entities with typed relationships
- **Graph Queries**: Find paths, neighbors, and patterns in investigation data
- **High Performance**: Rust implementation for compute-intensive graph operations

## Building

### Prerequisites

- Rust 1.75+
- Python 3.12+
- Maturin (`pip install maturin`)

### Development Build

```bash
# Build and install in development mode
maturin develop

# Run Rust tests
cargo test

# Run with release optimizations
maturin develop --release
```

### Production Build

```bash
# Build wheel for distribution
maturin build --release
```

## Usage from Python

```python
from osint_graph_engine import GraphEngine, Entity, Edge, EntityType, RelationshipType

# Create a new graph
engine = GraphEngine()

# Add entities
person_id = engine.add_entity(
    Entity("person-1", EntityType.Person, "John Doe")
)
company_id = engine.add_entity(
    Entity("company-1", EntityType.Company, "Acme Corp")
)

# Add relationships
engine.add_relationship(
    Edge(person_id, company_id, RelationshipType.EmployedBy)
)

# Query the graph
print(f"Nodes: {engine.node_count()}")
print(f"Edges: {engine.edge_count()}")

# Find neighbors
neighbors = engine.get_neighbors(person_id)

# Export to JSON
json_data = engine.to_json()
```

## Entity Types

- `Person` - Individual people
- `Company` - Organizations and businesses
- `Domain` - Internet domain names
- `IpAddress` - IP addresses
- `Email` - Email addresses
- `Phone` - Phone numbers
- `Address` - Physical addresses
- `SocialMedia` - Social media accounts
- `CryptoWallet` - Cryptocurrency wallets
- `Document` - Documents and files
- `Unknown` - Generic entities

## Relationship Types

- `EmployedBy` - Employment relationship
- `Owns` - Ownership/control
- `RelatedTo` - General relation
- `AssociatedWith` - Association
- `ResolvesTo` - DNS resolution
- `RegisteredAt` - Registration address
- `Uses` - Usage of email/phone
- `SubsidiaryOf` - Corporate subsidiary
- `DirectorOf` - Director/officer role
- `ShareholderOf` - Shareholding
- `TransactedWith` - Financial transaction
- `Contacted` - Communication
- `ConnectedTo` - Generic connection

## Architecture

The engine uses `petgraph` for the underlying graph data structure:

- **Directed Graph**: All relationships have direction (source → target)
- **Weighted Edges**: Relationships can have confidence/strength weights
- **Metadata Support**: Both entities and relationships support JSON metadata

## Performance

- Written in Rust for maximum performance
- Zero-copy where possible via PyO3
- Efficient graph algorithms from petgraph

## Testing

```bash
# Run all Rust tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Run specific test
cargo test test_graph_engine_creation
```

## License

MIT License
