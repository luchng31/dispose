from __future__ import annotations

import os
from dataclasses import dataclass

import requests

from apps.sysconfig import store as cfg


class WeComNotConfiguredError(RuntimeError):
    pass


class WeComExchangeError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class WeComUserInfo:
    userid: str
    name: str = ""
    department: str = ""


def _env(name: str) -> str:
    return os.environ.get(name, "")


def _corpid() -> str:
    return cfg.get("wecom.login_corpid", _env("WECOM_CORPID"))


def _secret() -> str:
    return cfg.get("wecom.login_secret", _env("WECOM_SECRET"))


def is_configured() -> bool:
    return bool(_corpid() and _secret())


def exchange_code_for_user(code: str, timeout: float = 5.0) -> WeComUserInfo:
    # Graceful fallback: without WECOM_CORPID/WECOM_SECRET in env (and no DB
    # override on the /ops/config page) the caller must fall back to local
    # login instead of failing with a 500.
    corpid: str = _corpid()
    secret: str = _secret()
    if not corpid or not secret:
        raise WeComNotConfiguredError("wecom oauth not configured; use local login")
    try:
        token_resp = requests.get(
            "https://qyapi.weixin.qq.com/cgi-bin/gettoken",
            params={"corpid": corpid, "corpsecret": secret},
            timeout=timeout,
        )
        token_body: dict[str, object] = token_resp.json()
        access_token: str = str(token_body.get("access_token", ""))
        if not access_token:
            raise WeComExchangeError("wecom gettoken returned no access_token")
        user_resp = requests.get(
            "https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo",
            params={"access_token": access_token, "code": code},
            timeout=timeout,
        )
        user_body: dict[str, object] = user_resp.json()
        userid: str = str(user_body.get("UserId", ""))
        if not userid:
            raise WeComExchangeError("wecom code exchange failed")
        return WeComUserInfo(userid=userid)
    except (WeComNotConfiguredError, WeComExchangeError):
        raise
    except Exception as exc:
        raise WeComExchangeError("wecom code exchange failed") from exc
