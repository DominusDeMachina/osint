# OSINT Platform Backend

FastAPI-based backend service for the OSINT Platform.

## Features

- RESTful API for OSINT data management
- Integration with graph-engine for relationship analysis
- Celery task queue for async processing
- PostgreSQL database with SQLModel ORM

## Development

```bash
# Install dependencies
uv sync

# Run development server
uvicorn app.main:app --reload
```

## Testing

```bash
pytest
```
