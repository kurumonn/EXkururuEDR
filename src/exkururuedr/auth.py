from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass

from .trusted_sources import TrustedSourceRegistry


@dataclass(frozen=True)
class AuthResult:
    ok: bool
    source_id: str = ""
    reason: str = ""


def sign_payload(timestamp: str, body: bytes, secret: str) -> str:
    signing_payload = timestamp.encode("utf-8") + b"." + body
    return hmac.new(secret.encode("utf-8"), signing_payload, hashlib.sha256).hexdigest()


def verify_hmac_headers(
    headers: dict[str, str],
    body: bytes,
    registry: TrustedSourceRegistry,
    now_ts: int | None = None,
    max_skew_sec: int = 300,
) -> AuthResult:
    source_id = headers.get("X-EDR-Source-Id", "").strip()
    ts_raw = headers.get("X-EDR-Timestamp", "").strip()
    recv_sig = headers.get("X-EDR-Signature", "").strip().lower()

    if not source_id or not ts_raw or not recv_sig:
        return AuthResult(ok=False, reason="missing_headers")
    source = registry.get(source_id)
    if source is None:
        return AuthResult(ok=False, reason="unknown_or_disabled_source")
    try:
        ts = int(ts_raw)
    except ValueError:
        return AuthResult(ok=False, source_id=source_id, reason="invalid_timestamp")

    current = int(time.time()) if now_ts is None else int(now_ts)
    if abs(current - ts) > max_skew_sec:
        return AuthResult(ok=False, source_id=source_id, reason="timestamp_out_of_range")

    expected = sign_payload(ts_raw, body, source.secret)
    if not hmac.compare_digest(expected, recv_sig):
        return AuthResult(ok=False, source_id=source_id, reason="bad_signature")

    return AuthResult(ok=True, source_id=source_id, reason="ok")

