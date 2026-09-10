"""CMDB REST adapter (Task4). ISOLATION BOUNDARY: everything CMDB-shaped
lives here; tasks/views only consume normalized ``CmdbAsset`` dicts.

Assumed upstream shape (user-confirmed CMDB HAS a REST API; exact schema
unverified — this adapter absorbs the difference):
  GET {base_url}/assets?updated_since=<cursor>&page=<n>&page_size=<m>
  -> {"results": [{ip, hostname, os, dept, owner_wecomid, status}], "next": ...}
Field aliases + envelope variants ("items"/"data", truthy "next") are
tolerated. If the real API differs, change ONLY this file.

Auth: Bearer token from env CMDB_TOKEN; base from env CMDB_BASE_URL.
No credentials are ever committed — both raise a clear error when absent
(unless passed explicitly, as tests do).

Production cursor: Task9 persists the updated_since cursor in Redis/DB via
beat; here the caller passes it in and tasks.py keeps a best-effort local
file copy (see tasks.load_cursor/save_cursor).
"""

from __future__ import annotations

import os
import time
from typing import Any, TypedDict

import requests

from apps.sysconfig import store as cfg


class CmdbAsset(TypedDict, total=False):
    ip: str
    hostname: str
    os: str
    dept: str
    owner_wecomid: str
    status: str


class CmdbSyncError(RuntimeError):
    """CMDB unreachable or unusable after retries — visible failure for ops."""


def _effective(key: str, env_name: str) -> str:
    """DB override wins, else env (page edit on /ops/config needs no restart)."""
    return cfg.get(key, os.environ.get(env_name, ""))


class CmdbClient:
    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        timeout: int = 10,
        max_retries: int = 3,
        page_size: int = 200,
    ) -> None:
        base = base_url or _effective("cmdb.base_url", "CMDB_BASE_URL")
        if not base:
            msg = "CMDB_BASE_URL is not set (env only; never commit credentials)"
            raise CmdbSyncError(msg)
        self._base: str = base.rstrip("/")
        self._token: str = token or _effective("cmdb.token", "CMDB_TOKEN")
        self._timeout: int = timeout
        self._retries: int = max(1, max_retries)
        self._page_size: int = page_size

    MAX_PAGES: int = 200

    def fetch_assets(self, updated_since: str | None = None) -> list[CmdbAsset]:
        """Pull all assets changed since cursor; follows ``next`` pages."""
        out: list[CmdbAsset] = []
        page = 1
        while True:
            if page > self.MAX_PAGES:
                raise CmdbSyncError(
                    f"CMDB pagination exceeded {self.MAX_PAGES} pages; aborting sync"
                )
            payload = self._get_page(updated_since, page)
            items, has_next = self._split_page(payload)
            out.extend(self._normalize(item) for item in items if item.get("ip"))
            if not has_next:
                return out
            page += 1

    def _get_page(self, updated_since: str | None, page: int) -> Any:
        params: dict[str, object] = {"page": page, "page_size": self._page_size}
        if updated_since:
            params["updated_since"] = updated_since
        headers: dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        url = f"{self._base}/assets"
        last: Exception | None = None
        for attempt in range(self._retries):
            try:
                resp = requests.get(url, params=params, headers=headers, timeout=self._timeout)
                resp.raise_for_status()
                return resp.json()
            except (requests.RequestException, ValueError) as exc:
                last = exc
                time.sleep(2**attempt)  # backoff: 1s, 2s, 4s, ...
        msg = f"CMDB GET {url} failed after {self._retries} attempts: {last}"
        raise CmdbSyncError(msg)

    @staticmethod
    def _split_page(payload: Any) -> tuple[list[dict[str, Any]], bool]:
        if isinstance(payload, list):
            return payload, False
        if isinstance(payload, dict):
            for key in ("results", "items", "data"):
                items = payload.get(key)
                if isinstance(items, list):
                    nxt = payload.get("next")
                    return items, bool(nxt)
        return [], False

    @staticmethod
    def _normalize(raw: dict[str, Any]) -> CmdbAsset:
        def pick(*keys: str) -> str:
            for key in keys:
                val = raw.get(key)
                if isinstance(val, str) and val.strip():
                    return val.strip()
            return ""

        return CmdbAsset(
            ip=pick("ip", "ip_address"),
            hostname=pick("hostname", "name"),
            os=pick("os", "os_name"),
            dept=pick("dept", "department", "biz_system"),
            owner_wecomid=pick("owner_wecomid", "owner", "owner_id"),
            status=pick("status", "state").lower() or "unknown",
        )
