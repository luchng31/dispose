from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

app = Celery("vuln_ticket")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

app.conf.beat_schedule = {
    "sync-cmdb-hourly": {
        "task": "cmdb.sync_cmdb",
        "schedule": 3600.0,
    },
    "check-sla-daily": {
        "task": "apps.tickets.tasks.check_sla",
        "schedule": crontab(hour=2, minute=0),
    },
    "check-ignore-expiry-hourly": {
        "task": "apps.tickets.tasks.check_ignore_expiry",
        "schedule": 3600.0,
    },
}


@app.task(bind=True)
def debug_task(self: object) -> str:
    task_id: str = getattr(getattr(self, "request", None), "id", "") or ""
    return f"Request: {task_id}"
