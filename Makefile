# =============================================================================
# OSINT Platform Makefile
# =============================================================================

.PHONY: setup dev test lint build clean help docker-up docker-down graph-engine

# Default target
.DEFAULT_GOAL := help

# =============================================================================
# Setup
# =============================================================================

## setup: One-command setup for new developers
setup:
	@echo "🚀 Running setup script..."
	./scripts/setup-dev.sh

# =============================================================================
# Development
# =============================================================================

## dev: Start all services for local development
dev: docker-up
	@echo "🚀 Starting development servers..."
	@echo "Backend will run on http://localhost:8000"
	@echo "Frontend will run on http://localhost:3000"
	@echo ""
	@echo "Starting backend..."
	cd backend && uv run uvicorn app.main:app --reload --port 8000 &
	@echo "Starting frontend..."
	cd frontend && pnpm dev

## docker-up: Start Docker services (PostgreSQL, Redis, Celery)
docker-up:
	@echo "🐳 Starting Docker services..."
	docker compose -f docker/docker-compose.yml up -d
	@echo "Waiting for services to be healthy..."
	@sleep 5
	docker compose -f docker/docker-compose.yml ps

## docker-down: Stop Docker services
docker-down:
	@echo "🐳 Stopping Docker services..."
	docker compose -f docker/docker-compose.yml down

## graph-engine: Build and install graph-engine locally
graph-engine:
	@echo "🦀 Building graph-engine with Maturin..."
	cd graph-engine && maturin develop

# =============================================================================
# Testing
# =============================================================================

## test: Run all tests across all projects
test:
	@echo "🧪 Running all tests..."
	@echo ""
	@echo "=== Backend Tests (pytest) ==="
	cd backend && uv run pytest -v
	@echo ""
	@echo "=== Graph Engine Tests (cargo test) ==="
	cd graph-engine && cargo test
	@echo ""
	@echo "=== Frontend Tests (vitest) ==="
	cd frontend && pnpm test

## test-backend: Run backend tests only
test-backend:
	@echo "🧪 Running backend tests..."
	cd backend && uv run pytest -v

## test-graph: Run graph-engine tests only
test-graph:
	@echo "🧪 Running graph-engine tests..."
	cd graph-engine && cargo test

## test-frontend: Run frontend tests only
test-frontend:
	@echo "🧪 Running frontend tests..."
	cd frontend && pnpm test

## test-coverage: Run tests with coverage reports
test-coverage:
	@echo "🧪 Running tests with coverage..."
	cd backend && uv run pytest --cov=app --cov-report=html
	cd frontend && pnpm test:coverage

# =============================================================================
# Linting
# =============================================================================

## lint: Run all linters
lint:
	@echo "🔍 Running all linters..."
	@echo ""
	@echo "=== Python (ruff + mypy) ==="
	cd backend && uv run ruff check . && uv run mypy app/
	@echo ""
	@echo "=== Rust (clippy + fmt check) ==="
	cd graph-engine && cargo clippy -- -D warnings && cargo fmt --check
	@echo ""
	@echo "=== TypeScript (eslint) ==="
	cd frontend && pnpm lint

## lint-fix: Run linters and auto-fix issues
lint-fix:
	@echo "🔧 Running linters with auto-fix..."
	cd backend && uv run ruff check --fix . && uv run ruff format .
	cd graph-engine && cargo fmt
	cd frontend && pnpm lint:fix

## format: Format all code
format:
	@echo "✨ Formatting all code..."
	cd backend && uv run ruff format .
	cd graph-engine && cargo fmt
	cd frontend && pnpm format

# =============================================================================
# Build
# =============================================================================

## build: Build all projects for production
build:
	@echo "📦 Building all projects..."
	@echo ""
	@echo "=== Building graph-engine ==="
	cd graph-engine && maturin build --release
	@echo ""
	@echo "=== Building backend ==="
	cd backend && uv build
	@echo ""
	@echo "=== Building frontend ==="
	cd frontend && pnpm build

## build-docker: Build Docker images
build-docker:
	@echo "🐳 Building Docker images..."
	docker build -f docker/Dockerfile.backend -t osint-backend .
	docker build -f docker/Dockerfile.frontend -t osint-frontend .

# =============================================================================
# Database
# =============================================================================

## db-migrate: Run database migrations
db-migrate:
	@echo "🗄️ Running database migrations..."
	cd backend && uv run alembic upgrade head

## db-revision: Create a new migration revision
db-revision:
	@echo "🗄️ Creating new migration revision..."
	@read -p "Enter migration message: " msg; \
	cd backend && uv run alembic revision --autogenerate -m "$$msg"

## db-downgrade: Downgrade database by one revision
db-downgrade:
	@echo "🗄️ Downgrading database..."
	cd backend && uv run alembic downgrade -1

# =============================================================================
# Code Generation
# =============================================================================

## generate-api: Generate frontend API client from OpenAPI spec
generate-api:
	@echo "🔄 Generating API client..."
	cd frontend && pnpm generate-api

# =============================================================================
# Cleanup
# =============================================================================

## clean: Clean all build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	cd graph-engine && cargo clean
	cd frontend && rm -rf dist node_modules/.vite
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name htmlcov -exec rm -rf {} + 2>/dev/null || true
	@echo "✅ Clean complete"

## clean-docker: Remove Docker volumes and images
clean-docker:
	@echo "🧹 Cleaning Docker resources..."
	docker compose -f docker/docker-compose.yml down -v
	docker rmi osint-backend osint-frontend 2>/dev/null || true

# =============================================================================
# Pre-commit
# =============================================================================

## pre-commit: Run pre-commit hooks on all files
pre-commit:
	@echo "🔍 Running pre-commit hooks..."
	pre-commit run --all-files

## pre-commit-install: Install pre-commit hooks
pre-commit-install:
	@echo "📦 Installing pre-commit hooks..."
	pre-commit install

# =============================================================================
# Help
# =============================================================================

## help: Show this help message
help:
	@echo "OSINT Platform - Available Commands"
	@echo "===================================="
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //' | column -t -s ':'
