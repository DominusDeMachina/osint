"""Celery application configuration."""

from celery import Celery

from app.core.config import settings


celery_app = Celery(
    "osint",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)

# Auto-discover tasks from app.tasks module
celery_app.autodiscover_tasks(["app.tasks"])


@celery_app.task(bind=True)
def health_check_task(self) -> dict[str, str]:
    """Health check task for Celery worker."""
    return {"status": "healthy", "task_id": self.request.id}
