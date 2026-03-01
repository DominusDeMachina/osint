# OSINT Platform

A comprehensive Open Source Intelligence platform for investigative research, entity resolution, and relationship mapping.

## Overview

This monorepo contains three main components:

- **`backend/`** - Python 3.12 + FastAPI API server with Celery background tasks
- **`graph-engine/`** - Rust graph processing engine with PyO3 Python bindings
- **`frontend/`** - React + TypeScript + Vite web application with shadcn/ui

## Prerequisites

- **Python 3.12+** - Backend runtime
- **Rust 1.75+** - Graph engine compilation
- **Node.js 20+** - Frontend development
- **Docker & Docker Compose** - Local services (PostgreSQL, Redis)
- **uv** - Python dependency management (installed automatically)
- **pnpm** - Node.js package manager (installed automatically)

## Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd osint
./scripts/setup-dev.sh
```

The setup script will:
- Install `uv` for Python dependency management
- Install `pnpm` for Node.js dependencies
- Build the graph-engine with Maturin
- Install pre-commit hooks
- Create `.env` from `.env.example`

### 2. Start Local Services

```bash
docker compose -f docker/docker-compose.yml up -d
```

This starts:
- PostgreSQL 16 on `localhost:5432`
- Redis on `localhost:6379`
- Celery worker for background tasks

### 3. Run Development Servers

```bash
make dev
```

Or run components individually:

```bash
# Backend (port 8000)
cd backend && uv run uvicorn app.main:app --reload --port 8000

# Frontend (port 3000)
cd frontend && pnpm dev
```

## Available Commands

Run from the project root:

| Command | Description |
|---------|-------------|
| `make setup` | One-command setup for new developers |
| `make dev` | Start all services for local development |
| `make test` | Run all tests across all projects |
| `make lint` | Run all linters |
| `make build` | Build all projects for production |
| `make clean` | Clean all build artifacts |

## Project Structure

```
osint-platform/
├── .github/workflows/     # CI/CD pipelines
├── .vscode/               # Editor configuration
├── backend/               # Python FastAPI backend
│   ├── app/               # Application code
│   ├── alembic/           # Database migrations
│   └── tests/             # Backend tests
├── graph-engine/          # Rust graph processing
│   ├── src/               # Rust source code
│   └── tests/             # Rust tests
├── frontend/              # React frontend
│   ├── src/               # TypeScript source
│   └── public/            # Static assets
├── docker/                # Docker configurations
├── scripts/               # Development scripts
└── docs/                  # Documentation
```

## Development Workflow

### Pre-commit Hooks

Pre-commit hooks run automatically on every commit:
- **ruff** - Python linting and formatting
- **mypy** - Python type checking
- **eslint** - TypeScript/React linting
- **cargo fmt** - Rust formatting
- **detect-secrets** - Prevents committing credentials

To run hooks manually:
```bash
pre-commit run --all-files
```

### Testing

```bash
# Run all tests
make test

# Run specific test suites
cd backend && uv run pytest
cd graph-engine && cargo test
cd frontend && pnpm test
```

### Graph Engine Development

The graph engine is built with Rust and exposed to Python via PyO3:

```bash
# Build and install locally
cd graph-engine && maturin develop

# Verify import in Python
cd backend && uv run python -c "from osint_graph_engine import *"
```

## Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Required variables:
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_URL` - Redis connection string
- `CLERK_SECRET_KEY` - Clerk authentication
- `OPENAI_API_KEY` - LLM integration

See `.env.example` for all available options.

## Deployment

### Railway (Staging/Production)

The project auto-deploys to Railway on merge to `main`:

1. Backend service at `api.osint-platform.railway.app`
2. Frontend service at `osint-platform.railway.app`

Required Railway secrets:
- `CLERK_SECRET_KEY`
- `OPENAI_API_KEY`
- `DATABASE_URL` (Railway PostgreSQL add-on)
- `REDIS_URL` (Railway Redis add-on)

### CI/CD Pipeline

GitHub Actions runs on every PR:
- Linting (ruff, clippy, eslint)
- Type checking (mypy, TypeScript)
- Unit tests (pytest, cargo test, vitest)
- Security scanning (pip-audit, cargo-audit, pnpm audit)

## Security

- Pre-commit hooks include secret detection
- All Docker ports bound to localhost only in development
- Production Dockerfiles use non-root users
- Dependabot monitors dependency vulnerabilities

## Contributing

1. Create a feature branch from `main`
2. Make changes following existing patterns
3. Ensure all tests pass: `make test`
4. Ensure linting passes: `make lint`
5. Submit a pull request

## License

[License information to be added]
