"""Demo seed for the vuln-ticket system (Task10 final gate).

Runnable two ways (no new dependencies):
  DB_ENGINE=sqlite python3 scripts/seed_demo.py          # standalone, from repo root
  DB_ENGINE=sqlite python3 manage.py shell < scripts/seed_demo.py   # via shell

Re-runs top up missing rows and reset the 10 demo tickets (matched by
dedup_key) to their spec state, so the SEED checks stay green even after the
demo orphan was triaged by hand. Non-demo rows are never touched.
All passwords below are TEST-ONLY demo credentials, never real secrets.
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django  # noqa: E402
from django.apps import apps  # noqa: E402

if not apps.ready:
    django.setup()

from django.db.models import Count  # noqa: E402
from django.utils import timezone  # noqa: E402

from apps.accounts.models import Role, User  # noqa: E402
from apps.assets.dispatch import remap_owner  # noqa: E402
from apps.assets.models import Asset, AssetOwnerMap, AssetStatus  # noqa: E402
from apps.imports.models import BatchSource, ScanBatch  # noqa: E402
from apps.tickets.models import Severity, TicketState, VulnTicket  # noqa: E402

TEST_PASSWORD = "Demo1234!"
DEPT_OPS = "运维部"
DEPT_DEV = "研发部"


def _user(username: str, role: str, dept: str) -> tuple[User, bool]:
    user, created = User.objects.get_or_create(
        username=username,
        defaults={"wecom_userid": f"{username}_wx", "dept": dept, "role": role},
    )
    if created:
        user.set_password(TEST_PASSWORD)
        user.save(update_fields=["password"])
    return user, created


def _asset(ip: str, hostname: str, owner: User | None) -> tuple[Asset, bool]:
    asset, created = Asset.objects.get_or_create(
        ip=ip,
        defaults={
            "hostname": hostname,
            "os": "Ubuntu 22.04",
            "biz_system": DEPT_OPS,
            "status": AssetStatus.ONLINE,
        },
    )
    if owner is not None:
        remap_owner(asset, owner)
    return asset, created


def _ticket(
    idx: int,
    ip: str,
    state: str,
    severity: str,
    assignee: User | None,
    sla_days: int | None,
    asset: Asset | None,
    batch: ScanBatch | None,
    extra_evidence: dict[str, object] | None = None,
) -> tuple[VulnTicket, bool]:
    dedup_key = uuid.uuid5(uuid.NAMESPACE_URL, f"demo-seed-ticket-{idx}").hex
    now = timezone.now()
    sla_due = now + timedelta(days=sla_days) if sla_days is not None else None
    if sla_days is not None and sla_days < 0:
        sla_due = now + timedelta(days=sla_days)
    defaults = {
        "ip": ip,
        "port": 443,
        "protocol": "tcp",
        "service": "https",
        "plugin_id": f"RSAS-DEMO-{idx:03d}",
        "plugin_name": f"演示漏洞 {idx}",
        "cve": f"CVE-2024-{9000 + idx}",
        "severity": severity,
        "cvss": 7.5,
        "description": "演示数据",
        "solution": "升级修复版本",
        "asset": asset,
        "assignee": assignee,
        "state": state,
        "sla_due_at": sla_due,
        "first_seen_at": now - timedelta(days=2),
        "last_seen_at": now,
        "fix_evidence": dict(extra_evidence or {}),
        "batch": batch,
    }
    ticket, created = VulnTicket.objects.get_or_create(dedup_key=dedup_key, defaults=defaults)
    if not created:
        _reset_demo_ticket(ticket, defaults)
    return ticket, created


_DEMO_TICKET_RESET_FIELDS = (
    "ip", "port", "protocol", "service", "plugin_id", "plugin_name", "cve",
    "severity", "cvss", "description", "solution", "asset", "assignee",
    "state", "sla_due_at", "first_seen_at", "last_seen_at", "fix_evidence",
    "batch",
)


def _reset_demo_ticket(ticket: VulnTicket, defaults: dict[str, object]) -> None:
    for field in _DEMO_TICKET_RESET_FIELDS:
        setattr(ticket, field, defaults[field])
    ticket.save()


def _ensure_ticket_side_state(idx: int, state: str, now: object) -> None:
    dedup_key = uuid.uuid5(uuid.NAMESPACE_URL, f"demo-seed-ticket-{idx}").hex
    if state == TicketState.DELAYED:
        t = VulnTicket.objects.get(dedup_key=dedup_key)
        if t.delay_until is None:
            t.delay_until = now + timedelta(days=7)
            t.save(update_fields=["delay_until", "updated_at"])
    elif state == TicketState.IGNORED:
        t = VulnTicket.objects.get(dedup_key=dedup_key)
        if not t.ignore_reason:
            t.ignore_reason = "演示忽略：误报"
            t.save(update_fields=["ignore_reason", "updated_at"])


def main() -> None:
    now = timezone.now()
    users_created = 0
    assets_created = 0
    tickets_created = 0
    batches_created = 0

    specs = [
        ("demo_operator", Role.OPERATOR, DEPT_OPS),
        ("demo_owner_a", Role.OWNER, DEPT_OPS),
        ("demo_owner_b", Role.OWNER, DEPT_DEV),
        ("demo_auditor", Role.AUDITOR, DEPT_OPS),
    ]
    users: dict[str, User] = {}
    for username, role, dept in specs:
        user, created = _user(username, role, dept)
        users[username] = user
        users_created += created
    owner_a = users["demo_owner_a"]
    owner_b = users["demo_owner_b"]

    asset_specs = [
        ("10.9.0.11", "demo-web-01", owner_a),
        ("10.9.0.12", "demo-web-02", owner_a),
        ("10.9.0.13", "demo-app-01", owner_b),
        ("10.9.0.14", "demo-app-02", owner_b),
        ("10.9.0.15", "demo-orphan-01", None),
    ]
    assets: dict[str, Asset] = {}
    for ip, hostname, owner in asset_specs:
        asset, created = _asset(ip, hostname, owner)
        assets[ip] = asset
        assets_created += created

    batch, batch_created = ScanBatch.objects.get_or_create(
        file_hash="demo-seed-batch-001",
        defaults={
            "file_name": "demo_seed_scan.zip",
            "source": BatchSource.MANUAL,
            "rsas_version": "V6.0R04F04SP11-demo",
            "uploaded_by": users["demo_operator"],
            "stats_json": {"new": 10, "demo": True},
        },
    )
    batches_created += batch_created

    ticket_specs = [
        (1, "10.9.0.11", TicketState.PENDING_ASSIGN, Severity.HIGH, owner_a, 30, None),
        (2, "10.9.0.15", TicketState.PENDING_ASSIGN, Severity.CRITICAL, None, 7, None),
        (3, "10.9.0.12", TicketState.PENDING_FIX, Severity.MEDIUM, owner_a, 30, None),
        (4, "10.9.0.13", TicketState.PENDING_FIX, Severity.HIGH, owner_b, -1, None),
        (5, "10.9.0.13", TicketState.DELAYED, Severity.MEDIUM, owner_b, 30, None),
        (6, "10.9.0.14", TicketState.DELAYED, Severity.LOW, owner_b, -3, None),
        (7, "10.9.0.12", TicketState.PENDING_RETEST, Severity.HIGH, owner_a, 30,
         {"note": "已修复并自验证"}),
        (8, "10.9.0.11", TicketState.CLOSED, Severity.MEDIUM, owner_a, 30, None),
        (9, "10.9.0.14", TicketState.IGNORED, Severity.LOW, owner_b, 30, None),
        (10, "10.9.0.11", TicketState.PENDING_FIX, Severity.CRITICAL, owner_a, 7,
         {"reopened": True}),
    ]
    for idx, ip, state, severity, assignee, sla_days, evidence in ticket_specs:
        asset = None if ip == "10.9.0.15" else assets[ip]
        _, created = _ticket(idx, ip, state, severity, assignee, sla_days,
                             asset, batch, evidence)
        tickets_created += created
        _ensure_ticket_side_state(idx, state, now)

    print(f"users: +{users_created} (total {User.objects.count()})")
    print(f"assets: +{assets_created} (total {Asset.objects.count()})")
    print(f"tickets: +{tickets_created} (total {VulnTicket.objects.count()})")
    print(f"batches: +{batches_created} (total {ScanBatch.objects.count()})")
    print("demo credentials (TEST-ONLY passwords):")
    for username in ("demo_operator", "demo_owner_a", "demo_owner_b", "demo_auditor"):
        print(f"  {username} / {TEST_PASSWORD}  [TEST]")

    checks: list[tuple[str, bool]] = [
        ("six states present",
         VulnTicket.objects.values("state").distinct().count() >= 6),
        ("orphan ticket exists (assignee NULL)",
         VulnTicket.objects.filter(assignee__isnull=True).exclude(
             state__in=[TicketState.CLOSED, TicketState.IGNORED]).exists()),
        ("overdue ticket exists (sla_due_at past, open)",
         VulnTicket.objects.filter(sla_due_at__lt=now).exclude(
             state__in=[TicketState.CLOSED, TicketState.IGNORED]).exists()),
        ("reopened flag present",
         VulnTicket.objects.filter(fix_evidence__reopened=True).exists()),
        ("owner_a owns >=2 mapped assets",
         Asset.objects.filter(
             ip__in=Asset.objects.filter(
                 owner_history__user=owner_a,
                 owner_history__valid_to__isnull=True
             ).values("ip")).count() >= 2),
        ("unmapped asset 10.9.0.15 has no current owner",
         not AssetOwnerMap.objects.filter(
             ip_id="10.9.0.15", valid_to__isnull=True).exists()),
        ("demo batch linked to >=1 ticket",
         VulnTicket.objects.filter(batch__file_hash="demo-seed-batch-001").exists()),
    ]
    for label, ok in checks:
        print(f"{'PASS' if ok else 'FAIL'}: {label}")
    by_state = {row["state"]: row["n"] for row in
                VulnTicket.objects.values("state").order_by().annotate(n=Count("id"))}
    print(f"state counts: {by_state}")
    failed = [label for label, ok in checks if not ok]
    if failed:
        raise SystemExit(f"SEED CHECKS FAILED: {failed}")
    print("SEED OK")


if __name__ == "__main__":
    main()
