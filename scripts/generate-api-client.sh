#!/usr/bin/env bash
# =============================================================================
# Generate API Client Script
# =============================================================================
# Generates TypeScript API client from OpenAPI specification using Orval
# =============================================================================

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Navigate to frontend directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FRONTEND_DIR="$PROJECT_ROOT/frontend"

cd "$FRONTEND_DIR"

info "Checking if backend is running..."

# Check if backend is running by testing the OpenAPI endpoint
if ! curl -s http://localhost:8000/api/v1/openapi.json > /dev/null 2>&1; then
    warning "Backend is not running at http://localhost:8000"
    warning "Please start the backend first: cd backend && uv run uvicorn app.main:app --reload"
    exit 1
fi

info "Generating API client from OpenAPI specification..."

# Run orval to generate the client
pnpm generate-api

success "API client generated successfully!"
info "Generated files are in: frontend/src/api/generated/"
