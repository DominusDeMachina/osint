#!/usr/bin/env bash
# =============================================================================
# OSINT Platform - Development Environment Setup Script
# =============================================================================
# This script sets up the complete development environment for new developers.
# Run from the project root: ./scripts/setup-dev.sh
# =============================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
    exit 1
}

# =============================================================================
# Check Prerequisites
# =============================================================================

echo ""
echo "============================================="
echo "  OSINT Platform Development Setup"
echo "============================================="
echo ""

info "Checking prerequisites..."

# Check Python 3.12+
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    if [[ $(echo "$PYTHON_VERSION >= 3.12" | bc -l) -eq 1 ]]; then
        success "Python $PYTHON_VERSION found"
    else
        error "Python 3.12+ required, found $PYTHON_VERSION"
    fi
else
    error "Python 3 not found. Please install Python 3.12+"
fi

# Check Rust
if command -v rustc &> /dev/null; then
    RUST_VERSION=$(rustc --version | awk '{print $2}')
    success "Rust $RUST_VERSION found"
else
    error "Rust not found. Please install Rust: https://rustup.rs/"
fi

# Check Node.js
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version | tr -d 'v')
    NODE_MAJOR=$(echo "$NODE_VERSION" | cut -d. -f1)
    if [[ $NODE_MAJOR -ge 20 ]]; then
        success "Node.js v$NODE_VERSION found"
    else
        warning "Node.js 20+ recommended, found v$NODE_VERSION"
    fi
else
    error "Node.js not found. Please install Node.js 20+"
fi

# Check Docker
if command -v docker &> /dev/null; then
    success "Docker found"
else
    warning "Docker not found. You'll need it for local services."
fi

# =============================================================================
# Install uv (Python package manager)
# =============================================================================

info "Setting up uv (Python package manager)..."

if command -v uv &> /dev/null; then
    success "uv already installed"
else
    info "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.cargo/bin:$PATH"
    success "uv installed"
fi

# =============================================================================
# Install pnpm (Node.js package manager)
# =============================================================================

info "Setting up pnpm (Node.js package manager)..."

if command -v pnpm &> /dev/null; then
    success "pnpm already installed"
else
    info "Installing pnpm..."
    npm install -g pnpm
    success "pnpm installed"
fi

# =============================================================================
# Install Maturin (Rust-Python build tool)
# =============================================================================

info "Setting up Maturin (Rust-Python build tool)..."

if command -v maturin &> /dev/null; then
    success "Maturin already installed"
else
    info "Installing maturin..."
    pip install maturin
    success "Maturin installed"
fi

# =============================================================================
# Setup Backend
# =============================================================================

info "Setting up backend..."

if [[ -d "backend" ]]; then
    cd backend
    info "Installing Python dependencies with uv..."
    uv sync
    cd ..
    success "Backend dependencies installed"
else
    warning "Backend directory not found. Skipping backend setup."
fi

# =============================================================================
# Build Graph Engine
# =============================================================================

info "Building graph-engine..."

if [[ -d "graph-engine" ]]; then
    cd graph-engine
    info "Building Rust graph-engine with Maturin..."
    maturin develop
    cd ..
    success "Graph-engine built and installed"
else
    warning "Graph-engine directory not found. Skipping graph-engine build."
fi

# =============================================================================
# Setup Frontend
# =============================================================================

info "Setting up frontend..."

if [[ -d "frontend" ]]; then
    cd frontend
    info "Installing Node.js dependencies with pnpm..."
    pnpm install
    cd ..
    success "Frontend dependencies installed"
else
    warning "Frontend directory not found. Skipping frontend setup."
fi

# =============================================================================
# Setup Pre-commit Hooks
# =============================================================================

info "Setting up pre-commit hooks..."

if command -v pre-commit &> /dev/null; then
    success "pre-commit already installed"
else
    info "Installing pre-commit..."
    pip install pre-commit
fi

if [[ -f ".pre-commit-config.yaml" ]]; then
    pre-commit install
    success "Pre-commit hooks installed"
else
    warning ".pre-commit-config.yaml not found. Skipping pre-commit setup."
fi

# =============================================================================
# Setup Environment File
# =============================================================================

info "Setting up environment file..."

if [[ -f ".env" ]]; then
    warning ".env file already exists. Skipping."
else
    if [[ -f ".env.example" ]]; then
        cp .env.example .env
        success "Created .env from .env.example"
        warning "Please update .env with your actual values!"
    else
        warning ".env.example not found. Skipping."
    fi
fi

# =============================================================================
# Final Summary
# =============================================================================

echo ""
echo "============================================="
echo "  Setup Complete!"
echo "============================================="
echo ""
success "Development environment is ready!"
echo ""
info "Next steps:"
echo "  1. Update .env with your actual values"
echo "  2. Start Docker services: docker compose -f docker/docker-compose.yml up -d"
echo "  3. Run database migrations: make db-migrate"
echo "  4. Start development: make dev"
echo ""
info "Useful commands:"
echo "  make help     - Show all available commands"
echo "  make test     - Run all tests"
echo "  make lint     - Run all linters"
echo ""

exit 0
