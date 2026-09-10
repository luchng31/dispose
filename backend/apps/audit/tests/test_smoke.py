from __future__ import annotations

import pytest

from apps.accounts.models import User
from apps.audit.models import AuditLog


@pytest.mark.django_db
def test_create_audit_log_smoke() -> None:
    user: User = User.objects.create_user(username="aud1", wecom_userid="aud1")
    log: AuditLog = AuditLog.objects.create(
        actor=user, action="ticket.create", entity="vuln_ticket", entity_id="1"
    )
    assert AuditLog.objects.filter(action="ticket.create").exists()
    assert log.entity == "vuln_ticket"
