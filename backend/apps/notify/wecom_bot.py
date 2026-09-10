from __future__ import annotations

import json
import logging
import urllib.request

from django.conf import settings

from apps.sysconfig import store as cfg

logger = logging.getLogger(__name__)


def wecom_webhook() -> str:
    return cfg.get("wecom.bot_webhook", str(getattr(settings, "NOTIFY_WECOM_WEBHOOK", ""))).strip()


def wecom_configured() -> bool:
    return bool(wecom_webhook())


def send_wecom_text(content: str) -> int:
    """Post text to the WeCom group bot webhook. Never raises; 1 sent / 0 skipped."""
    url = wecom_webhook()
    if not url:
        logger.info("wecom bot skipped (not configured): %s", content[:80])
        return 0
    payload = json.dumps({"msgtype": "text", "text": {"content": content[:2000]}}).encode()
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode() or "{}")
    except Exception:
        logger.exception("wecom bot request failed")
        return 0
    if int(body.get("errcode", -1)) != 0:
        logger.warning("wecom bot rejected: %s", body)
        return 0
    return 1
