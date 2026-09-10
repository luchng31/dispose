"""RSAS drop watcher: FTP dir -> POST /api/imports/rsas (Task9).

Polls WATCH_DIR for new FILE_PATTERN files (*.zip), skips already-seen
sha256 hashes via STATE_FILE, and POSTs each newcomer as multipart ``file``
to ${API_BASE}/api/imports/rsas?dry_run=false&source=ftp with a scoped
operator token (Authorization: Bearer ${WATCHER_TOKEN}).

Server-side file_hash is the second replay defense; the local seen-state
file is the first (avoids re-uploading after restarts).

Env: API_BASE, WATCH_DIR, STATE_FILE, POLL_INTERVAL, FILE_PATTERN,
     WATCHER_TOKEN (required), DRY_RUN (true => ?dry_run=true, zero writes).
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import os
import sys
import time
import urllib.parse

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("rsas-watcher")

API_BASE = os.environ.get("API_BASE", "http://api:8000").rstrip("/")
WATCH_DIR = os.environ.get("WATCH_DIR", "/rsas-drop")
STATE_FILE = os.environ.get("STATE_FILE", "/state/seen.json")
POLL_INTERVAL = max(5, int(os.environ.get("POLL_INTERVAL", "15") or 15))
FILE_PATTERN = os.environ.get("FILE_PATTERN", "*.zip")
DRY_RUN = (os.environ.get("DRY_RUN", "false") or "").strip().lower() in {
    "1", "true", "yes", "on",
}
WATCHER_TOKEN = os.environ.get("WATCHER_TOKEN", "")

SETTLE_SECONDS = 3  # re-stat size; upload only once the file stops growing


def load_seen(path: str) -> dict[str, str]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
            return dict(data) if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_seen(path: str, seen: dict[str, str]) -> None:
    tmp = path + ".tmp"
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(seen, fh, indent=2, sort_keys=True)
        os.replace(tmp, path)
    except OSError as exc:
        log.error("state-write-failed path=%s error=%s", path, exc)


def sha256_of(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def settled(path: str) -> bool:
    """True when the file size is stable across a short re-stat window."""
    try:
        first = os.path.getsize(path)
    except OSError:
        return False
    time.sleep(SETTLE_SECONDS)
    try:
        return os.path.getsize(path) == first
    except OSError:
        return False


def post_file(path: str, filename: str) -> dict:
    query = urllib.parse.urlencode(
        {"dry_run": "true" if DRY_RUN else "false", "source": "ftp"}
    )
    url = f"{API_BASE}/api/imports/rsas?{query}"
    headers = {"Authorization": f"Bearer {WATCHER_TOKEN}"}
    with open(path, "rb") as fh:
        resp = requests.post(
            url, headers=headers, files={"file": (filename, fh)}, timeout=300
        )
    try:
        body = resp.json()
    except ValueError:
        body = {"raw": resp.text[:500]}
    if resp.status_code >= 400:
        raise RuntimeError(f"HTTP {resp.status_code}: {body}")
    return body if isinstance(body, dict) else {"raw": body}


def scan_once(seen: dict[str, str]) -> bool:
    """One poll pass. Returns True if the seen-state changed."""
    try:
        names = sorted(os.listdir(WATCH_DIR))
    except OSError as exc:
        log.error("watch-dir-unreadable dir=%s error=%s", WATCH_DIR, exc)
        return False
    changed = False
    for name in names:
        if not fnmatch.fnmatch(name, FILE_PATTERN):
            continue
        path = os.path.join(WATCH_DIR, name)
        if not os.path.isfile(path):
            continue
        try:
            file_hash = sha256_of(path)
        except OSError as exc:
            log.error("hash-failed file=%s error=%s", name, exc)
            continue
        if file_hash in seen:
            log.info("skip-seen filename=%s hash=%.12s...", name, file_hash)
            continue
        if not settled(path):
            log.info("skip-unsettled filename=%s (still growing)", name)
            continue
        try:
            result = post_file(path, name)
            counts = result.get("stats", result)
            log.info(
                "uploaded filename=%s hash=%.12s... skipped=%s counts=%s",
                name, file_hash, result.get("skipped", False), counts,
            )
        except Exception as exc:  # noqa: BLE001 - must never kill the loop
            log.error("upload-failed filename=%s error=%s", name, exc)
            continue
        seen[file_hash] = name
        changed = True
    return changed


def main() -> int:
    if not WATCHER_TOKEN:
        log.error("WATCHER_TOKEN is not set; refusing to start")
        return 2
    if not os.path.isdir(WATCH_DIR):
        log.error("WATCH_DIR missing dir=%s", WATCH_DIR)
        return 2
    seen = load_seen(STATE_FILE)
    log.info(
        "watch-start dir=%s pattern=%s api=%s dry_run=%s seen=%d",
        WATCH_DIR, FILE_PATTERN, API_BASE, DRY_RUN, len(seen),
    )
    while True:
        try:
            if scan_once(seen):
                save_seen(STATE_FILE, seen)
        except Exception as exc:  # noqa: BLE001 - watcher must stay alive
            log.error("scan-error error=%s", exc)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    raise SystemExit(main())
