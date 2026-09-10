from __future__ import annotations

import hashlib
import io
import zipfile

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from apps.imports.models import ScanBatch
from apps.imports.tasks import dedup_key_for, import_batch
from apps.tickets.models import TicketState, VulnTicket


def _make_user(role: str = "operator") -> object:
    user_model = get_user_model()
    return user_model.objects.create_user(
        username=f"op_{role}_{user_model.objects.count()}",
        password="x" * 12,
        wecom_userid=f"wx_{role}_{user_model.objects.count()}",  # type: ignore[attr-defined]
        role=role,  # type: ignore[attr-defined]
    )


def _client_for(user: object) -> APIClient:
    client = APIClient()
    client.force_authenticate(user=user)  # type: ignore[arg-type]
    return client


def _vuln_xml(rows: str, version: str = "V6.0R04F04SP11") -> bytes:
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<rsas version="{version}"><vulns>{rows}</vulns></rsas>'
    ).encode()


def _row(**kw: str) -> str:
    attrs = " ".join(f'{k}="{v}"' for k, v in kw.items())
    return f"<vuln {attrs}/>"


ROW_A = {
    "ip": "192.168.1.10",
    "port": "80",
    "plugin_id": "1001",
    "title": "Apache HTTP Server RCE",
    "cve": "CVE-2024-1234",
    "severity": "高危",
}
ROW_B = {
    "ip": "192.168.1.11",
    "port": "443",
    "plugin_id": "1002",
    "title": "OpenSSL信息泄露",
    "cve": "CVE-2024-5678",
    "severity": "中危",
}


def _zip_of(name: str, payload: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(name, payload)
    return buf.getvalue()


def _post(client: APIClient, payload: bytes, name: str, dry_run: bool) -> object:
    from django.core.files.uploadedfile import SimpleUploadedFile

    up = SimpleUploadedFile(name, payload, content_type="application/octet-stream")
    return client.post(f"/api/imports/rsas?dry_run={'true' if dry_run else 'false'}", {"file": up})


@pytest.mark.django_db
def test_dedup_key_is_md5_of_ip_port_plugin_cve() -> None:
    key = dedup_key_for("192.168.1.10", 80, "1001", "CVE-2024-1234")
    assert key == hashlib.md5(b"192.168.1.10|80|1001|CVE-2024-1234").hexdigest()


@pytest.mark.django_db
def test_reupload_same_file_skipped_by_hash() -> None:
    client = _client_for(_make_user())
    payload = _zip_of("scan.xml", _vuln_xml(_row(**ROW_A)))
    resp1 = _post(client, payload, "scan.zip", dry_run=False)
    assert resp1.status_code == 201  # type: ignore[attr-defined]
    resp2 = _post(client, payload, "scan.zip", dry_run=False)
    assert resp2.status_code == 200  # type: ignore[attr-defined]
    assert resp2.data["skipped"] is True  # type: ignore[attr-defined]
    assert ScanBatch.objects.count() == 1
    assert VulnTicket.objects.count() == 1


@pytest.mark.django_db
def test_same_finding_twice_yields_single_ticket() -> None:
    client = _client_for(_make_user())
    payload = _vuln_xml(_row(**ROW_A) + _row(**ROW_A))
    resp = _post(client, payload, "dup.xml", dry_run=False)
    assert resp.status_code == 201  # type: ignore[attr-defined]
    assert VulnTicket.objects.count() == 1


@pytest.mark.django_db
def test_rescan_missing_marks_fixed_unverified_never_autoclose() -> None:
    client = _client_for(_make_user())
    _post(client, _vuln_xml(_row(**ROW_A) + _row(**ROW_B)), "full.xml", dry_run=False)
    assert VulnTicket.objects.count() == 2
    resp = _post(client, _vuln_xml(_row(**ROW_A)), "rescan.xml", dry_run=False)
    assert resp.status_code == 201  # type: ignore[attr-defined]
    missing = VulnTicket.objects.get(ip="192.168.1.11")
    assert missing.state != TicketState.CLOSED
    assert missing.fix_evidence.get("retest_status") == "fixed-unverified"
    assert resp.data["stats"]["fixed_unverified"] == 1  # type: ignore[attr-defined]


@pytest.mark.django_db
def test_dry_run_returns_preview_with_zero_writes() -> None:
    client = _client_for(_make_user())
    _post(client, _vuln_xml(_row(**ROW_A)), "base.xml", dry_run=False)
    n_batch, n_ticket = ScanBatch.objects.count(), VulnTicket.objects.count()
    payload = _zip_of("scan.xml", _vuln_xml(_row(**ROW_A) + _row(**ROW_B)))
    resp = _post(client, payload, "scan.zip", dry_run=True)
    assert resp.status_code == 200  # type: ignore[attr-defined]
    data = resp.data  # type: ignore[attr-defined]
    assert (data["new"], data["still_open"]) == (1, 1)
    assert data["fixed_unverified"] == 0
    assert data["reopened"] == 0
    assert isinstance(data["errors"], list)
    assert ScanBatch.objects.count() == n_batch
    assert VulnTicket.objects.count() == n_ticket


@pytest.mark.django_db
def test_malformed_xml_returns_400_per_row_errors() -> None:
    client = _client_for(_make_user())
    resp = _post(client, b"<rsas><vuln ip='oops' port=!!!", "bad.xml", dry_run=False)
    assert resp.status_code == 400  # type: ignore[attr-defined]
    assert len(resp.data["errors"]) >= 1  # type: ignore[attr-defined]
    assert ScanBatch.objects.count() == 0
    assert VulnTicket.objects.count() == 0


@pytest.mark.django_db
def test_reappearing_closed_ticket_reopened_with_new_sla_link() -> None:
    client = _client_for(_make_user())
    _post(client, _vuln_xml(_row(**ROW_A)), "v1.xml", dry_run=False)
    ticket = VulnTicket.objects.get(ip="192.168.1.10")
    ticket.state = TicketState.CLOSED
    ticket.save(update_fields=["state"])
    resp = _post(client, _vuln_xml(_row(**ROW_A), version="V6.0R04F04SP12"), "v2.xml", dry_run=False)
    assert resp.status_code == 201  # type: ignore[attr-defined]
    ticket.refresh_from_db()
    assert ticket.state == TicketState.PENDING_FIX
    assert ticket.fix_evidence.get("reopened") is True
    assert ticket.sla_due_at is None  # new SLA clock recomputed by Task5
    assert resp.data["stats"]["reopened"] == 1  # type: ignore[attr-defined]


@pytest.mark.django_db
def test_empty_cve_falls_back_to_nocve() -> None:
    client = _client_for(_make_user())
    row = dict(ROW_A)
    row.pop("cve")
    resp = _post(client, _vuln_xml(_row(**row)), "nocve.xml", dry_run=False)
    assert resp.status_code == 201  # type: ignore[attr-defined]
    ticket = VulnTicket.objects.get(ip="192.168.1.10")
    assert ticket.cve == "NOCVE"


@pytest.mark.django_db
def test_import_batch_task_runs_synchronously() -> None:
    from apps.imports.mapping import normalize_row

    finding = normalize_row(
        {"ip": "10.0.0.1", "port": "22", "plugin_id": "999",
         "title": "SSH弱口令", "severity": "低危"}
    )
    batch = ScanBatch.objects.create(file_name="t.xml", file_hash="b" * 64)
    stats = import_batch.run(batch.id, rows=[finding.to_dict()])
    assert stats["new"] == 1
    assert VulnTicket.objects.filter(ip="10.0.0.1").exists()


@pytest.mark.django_db
def test_batch_list_exposes_hash_and_stats() -> None:
    client = _client_for(_make_user())
    _post(client, _vuln_xml(_row(**ROW_A)), "listed.xml", dry_run=False)
    resp = client.get("/api/imports/batches")
    assert resp.status_code == 200
    assert resp.data["results"][0]["file_hash"]  # type: ignore[index]
    assert "stats" in resp.data["results"][0]  # type: ignore[index]


def test_xml_entities_not_expanded() -> None:
    from apps.imports.parsers import parse_xml_bytes

    payload = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<!DOCTYPE rsas [<!ENTITY x "EXPANDED-SECRET">]>'
        b'<rsas><vulns><vuln ip="10.9.9.9"><title>&x;</title></vuln></vulns></rsas>'
    )
    rows, errors = parse_xml_bytes(payload)
    assert errors == []
    assert rows, "entity-bearing row should still parse"
    blob = str(rows)
    assert "EXPANDED-SECRET" not in blob
    title = str(rows[0].get("title", ""))
    assert title in ("", "&x;")


def test_xml_billion_laughs_not_expanded() -> None:
    from apps.imports.parsers import parse_xml_bytes

    payload = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE lolz ['
        b'<!ENTITY lol "lollollollollollollollollollol">'
        b'<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        b']>'
        b'<rsas><vulns><vuln ip="10.9.9.8"><title>&lol2;</title></vuln></vulns></rsas>'
    )
    rows, _errors = parse_xml_bytes(payload)
    blob = str(rows)
    assert "lollollol" not in blob


@pytest.mark.django_db
def test_zip_member_size_and_count_limits() -> None:
    from unittest import mock

    from apps.imports import parsers
    from apps.imports.parsers import parse_upload

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("huge.xml", b"<rsas><vulns>" + b" " * 2048 + b"</vulns></rsas>")
        archive.writestr("ok.xml", _vuln_xml(_row(**ROW_A)))
    with mock.patch.object(parsers, "_MAX_ZIP_MEMBER_BYTES", 1024):
        rows, errors = parse_upload("bundle.zip", buf.getvalue())
    assert any(e["field"] == "huge.xml" for e in errors)
    assert any("192.168.1.10" in str(r) for r in rows)

    crowded = io.BytesIO()
    with zipfile.ZipFile(crowded, "w", zipfile.ZIP_STORED) as archive:
        for i in range(201):
            archive.writestr(f"m{i}.xml", b"<rsas><vulns /></rsas>")
    with mock.patch.object(parsers, "_MAX_ZIP_MEMBERS", 200):
        rows, errors = parse_upload("crowded.zip", crowded.getvalue())
    assert rows == []
    assert any(e["field"] == "zip" for e in errors)
