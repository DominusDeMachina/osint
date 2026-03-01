#!/usr/bin/env bash
# =============================================================================
# Build Graph Engine Script
# =============================================================================
# Builds the Rust graph-engine and installs it for Python development
# =============================================================================

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

# Navigate to graph-engine directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
GRAPH_ENGINE_DIR="$PROJECT_ROOT/graph-engine"

info "Building graph-engine..."

cd "$GRAPH_ENGINE_DIR"

# Check if maturin is available
if ! command -v maturin &> /dev/null; then
    info "Installing maturin..."
    pip install maturin
fi

# Build in development mode
info "Running maturin develop..."
maturin develop

success "Graph engine built and installed!"

# Verify installation
info "Verifying Python import..."
python -c "from osint_graph_engine import GraphEngine; print('Import successful!')"

success "Graph engine is ready to use!"
