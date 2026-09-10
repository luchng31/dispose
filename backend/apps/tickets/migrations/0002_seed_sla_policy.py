from __future__ import annotations

from django.db import migrations


def seed_sla_policies(apps: object, schema_editor: object) -> None:
    from django.apps import apps as django_apps

    SlaPolicy = django_apps.get_model("tickets", "SlaPolicy")
    rows: list[tuple[str, int]] = [("严重", 7), ("高", 30), ("中", 90), ("低", 180)]
    for severity, days in rows:
        SlaPolicy.objects.update_or_create(
            severity=severity, defaults={"days": days, "warn_days_before": 3}
        )


def unseed_sla_policies(apps: object, schema_editor: object) -> None:
    from django.apps import apps as django_apps

    SlaPolicy = django_apps.get_model("tickets", "SlaPolicy")
    SlaPolicy.objects.filter(severity__in=["严重", "高", "中", "低"]).delete()


class Migration(migrations.Migration):
    dependencies = [("tickets", "0001_initial")]

    operations = [
        migrations.RunPython(seed_sla_policies, reverse_code=unseed_sla_policies),
    ]
