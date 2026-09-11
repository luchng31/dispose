from __future__ import annotations

import os

from celery import Celery
from celery.schedules import crontab

# wsgi/manage.py each set DJANGO_SETTINGS_MODULE themselves; the celery CLI
# (-A config) reads app.conf during option parsing, before Django's fixup
# runs, so this entrypoint must provide it too.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

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
