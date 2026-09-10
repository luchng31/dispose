from __future__ import annotations

import hashlib

import pytest
from django.db import connection
from django.utils import timezone

from apps.assets.models import Asset
from apps.tickets.models import Severity, SlaPolicy, TicketState, VulnTicket


@pytest.mark.django_db
def test_create_ticket_and_query_view_smoke() -> None:
    asset: Asset = Asset.objects.create(ip="10.0.0.2")
    raw: str = "10.0.0.2|443|RSAS-WEB-001|CVE-2024-0001"
    dedup: str = hashlib.md5(raw.encode()).hexdigest()
    ticket: VulnTicket = VulnTicket.objects.create(
        dedup_key=dedup,
        ip="10.0.0.2",
        port=443,
        protocol="tcp",
        plugin_id="RSAS-WEB-001",
        cve="CVE-2024-0001",
        severity=Severity.HIGH,
        asset=asset,
        state=TicketState.PENDING_ASSIGN,
        first_seen_at=timezone.now(),
        last_seen_at=timezone.now(),
    )
    assert VulnTicket.objects.filter(dedup_key=dedup).exists()
    assert ticket.state == TicketState.PENDING_ASSIGN
    with connection.cursor() as cur:
        cur.execute("SELECT ip, open_count FROM v_ticket_ip_summary WHERE ip = %s", ["10.0.0.2"])
        row: tuple[str, int] | None = cur.fetchone()
    assert row is not None
    assert row[0] == "10.0.0.2"
    assert row[1] >= 1


@pytest.mark.django_db
def test_sla_policy_seeded_smoke() -> None:
    expected: dict[str, int] = {"严重": 7, "高": 30, "中": 90, "低": 180}
    for severity, days in expected.items():
        policy: SlaPolicy = SlaPolicy.objects.get(severity=severity)
        assert policy.days == days
        assert policy.warn_days_before == 3
