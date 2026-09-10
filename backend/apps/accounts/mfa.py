from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from dataclasses import dataclass

STEP_SECONDS: int = 30
DIGITS: int = 6
LOOK_AROUND_STEPS: int = 1


class TotpError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class TotpResult:
    code: str


def generate_secret(num_bytes: int = 20) -> str:
    raw: bytes = secrets.token_bytes(num_bytes)
    return base64.b32encode(raw).decode("ascii")


def _hotp(secret_b32: str, counter: int) -> str:
    try:
        key: bytes = base64.b32decode(secret_b32.upper(), casefold=True)
    except Exception as exc:
        raise TotpError("invalid totp secret") from exc
    msg: bytes = struct.pack(">Q", counter)
    digest: bytes = hmac.new(key, msg, hashlib.sha1).digest()
    offset: int = digest[-1] & 0x0F
    code_int: int = (
        struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    ) % (10**DIGITS)
    return str(code_int).zfill(DIGITS)


def current_code(secret_b32: str, at: float | None = None) -> str:
    now: float = time.time() if at is None else at
    return _hotp(secret_b32, int(now // STEP_SECONDS))


def verify_code(secret_b32: str, code: str, at: float | None = None) -> bool:
    candidate: str = code.strip()
    if len(candidate) != DIGITS or not candidate.isdigit():
        return False
    now: float = time.time() if at is None else at
    base: int = int(now // STEP_SECONDS)
    for delta in range(-LOOK_AROUND_STEPS, LOOK_AROUND_STEPS + 1):
        if hmac.compare_digest(_hotp(secret_b32, base + delta), candidate):
            return True
    return False
