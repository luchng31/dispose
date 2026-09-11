"""RSAS <aurora> parser: host flavor (ip+ports) and web flavor (site URL)."""

from __future__ import annotations

import io
import zipfile
from typing import Any

import pytest

from apps.imports.parsers import parse_and_normalize, parse_upload

HOST_AURORA: str = """<?xml version="1.0" encoding="utf-8"?>
<aurora><report>
  <targets><target>
    <ip>10.66.0.1</ip>
    <vuln_scanned>
      <vuln><port>443</port><protocol>tcp</protocol><service>https</service><vul_id>1001</vul_id></vuln>
    </vuln_scanned>
    <vuln_detail>
      <vuln><vul_id>1001</vul_id><plugin_id>1001</plugin_id><name>OpenSSL 心跳出血</name>
        <cve_id>CVE-2014-0160</cve_id><risk_points>9</risk_points>
        <description>d</description><solution>s</solution></vuln>
    </vuln_detail>
  </target></targets>
</report></aurora>"""

WEB_AURORA: str = """<?xml version="1.0" encoding="utf-8"?>
<aurora><data><report>
  <targets>
    <target>
      <site>http://wxp-proxy.winning.com.cn</site>
      <vuln_scanned>
        <vuln><port/><vul_id>1000256</vul_id><url>http://wxp-proxy.winning.com.cn/</url></vuln>
      </vuln_scanned>
      <vuln_detail>
        <vuln><vul_id>1000256</vul_id><plugin_id>1000256</plugin_id>
          <name>检测到目标X-Content-Type-Options响应头缺失</name><cve_id/>
          <risk_points>2</risk_points><description>desc</description><solution>sol</solution></vuln>
      </vuln_detail>
    </target>
    <target>
      <site>https://ydgw.winning.com.cn:8443</site>
      <vuln_scanned>
        <vuln><port/><vul_id>2000001</vul_id></vuln>
      </vuln_scanned>
      <vuln_detail>
        <vuln><vul_id>2000001</vul_id><plugin_id>2000001</plugin_id>
          <name>SQL注入</name><cve_id>CVE-2026-9999</cve_id><risk_points>9</risk_points></vuln>
      </vuln_detail>
    </target>
  </targets>
</report></data></aurora>"""


def _as_zip(xml: str) -> tuple[str, bytes]:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("96.xml", xml)
    return "scan.zip", buf.getvalue()


def _ips(findings: list[Any]) -> list[tuple[str, int, str, str]]:
    return [(f.ip, f.port, f.plugin_name, f.severity) for f in findings]


@pytest.mark.django_db
def test_aurora_host_flavor_unchanged() -> None:
    findings, errors = parse_and_normalize("h.xml", HOST_AURORA.encode("utf-8"))
    assert errors == []
    assert _ips(findings) == [("10.66.0.1", 443, "OpenSSL 心跳出血", "严重")]


@pytest.mark.django_db
def test_aurora_web_flavor_site_url() -> None:
    findings, errors = parse_and_normalize("w.xml", WEB_AURORA.encode("utf-8"))
    assert errors == []
    rows = _ips(findings)
    assert ("wxp-proxy.winning.com.cn", 80, "检测到目标X-Content-Type-Options响应头缺失", "低") in rows
    assert ("ydgw.winning.com.cn", 8443, "SQL注入", "严重") in rows
    assert len(rows) == 2


@pytest.mark.django_db
def test_aurora_web_flavor_via_zip() -> None:
    name, data = _as_zip(WEB_AURORA)
    findings, errors = parse_and_normalize(name, data)
    assert errors == []
    assert {f.ip for f in findings} == {"wxp-proxy.winning.com.cn", "ydgw.winning.com.cn"}


@pytest.mark.django_db
def test_aurora_target_without_ip_or_site_skipped() -> None:
    xml = WEB_AURORA.replace("<site>http://wxp-proxy.winning.com.cn</site>", "<site></site>")
    findings, errors = parse_and_normalize("w.xml", xml.encode("utf-8"))
    assert len(findings) == 1  # only the https target survives
    assert any("without ip/site" in e["message"] for e in errors)


@pytest.mark.django_db
def test_parse_upload_dispatch_still_works() -> None:
    rows, errors = parse_upload("h.xml", HOST_AURORA.encode("utf-8"))
    assert errors == []
    assert rows and rows[0]["ip"] == "10.66.0.1"
