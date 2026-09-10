from __future__ import annotations

from django.db import migrations

CREATE_VIEW_SQL = """
CREATE VIEW v_ticket_ip_summary AS
SELECT
    ip,
    COUNT(*) AS total,
    SUM(CASE WHEN state NOT IN ('已闭合', '已忽略') THEN 1 ELSE 0 END) AS open_count,
    SUM(CASE WHEN severity = '严重' THEN 1 ELSE 0 END) AS critical_count,
    SUM(CASE WHEN severity = '高' THEN 1 ELSE 0 END) AS high_count,
    SUM(CASE WHEN severity = '中' THEN 1 ELSE 0 END) AS medium_count,
    SUM(CASE WHEN severity = '低' THEN 1 ELSE 0 END) AS low_count,
    MAX(sla_due_at) AS latest_sla_due_at
FROM vuln_ticket
GROUP BY ip
"""

DROP_VIEW_SQL = "DROP VIEW IF EXISTS v_ticket_ip_summary"


class Migration(migrations.Migration):
    dependencies = [("tickets", "0002_seed_sla_policy")]

    operations = [
        migrations.RunSQL(sql=CREATE_VIEW_SQL, reverse_sql=DROP_VIEW_SQL),
    ]
