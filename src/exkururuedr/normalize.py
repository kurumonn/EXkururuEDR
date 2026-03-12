from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


SEVERITY_SCORE = {
    "low": 20,
    "medium": 50,
    "high": 80,
    "critical": 95,
}

DEFAULT_LABELS = ("edr", "endpoint")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_raw_event(raw: dict[str, Any]) -> dict[str, Any]:
    return _normalize_raw_event(raw, default_time=None)


def _normalize_raw_event(raw: dict[str, Any], *, default_time: str | None) -> dict[str, Any]:
    get = raw.get
    severity_raw = get("severity")
    event_id_raw = get("event_id")
    event_type_raw = get("event_type")
    hostname_raw = get("hostname")
    user_raw = get("user")
    labels = get("labels")

    # Fast path for expected EDR collector payloads.
    if (
        isinstance(event_id_raw, str)
        and event_id_raw
        and isinstance(severity_raw, str)
        and isinstance(event_type_raw, str)
        and event_type_raw
        and isinstance(hostname_raw, str)
        and hostname_raw
        and isinstance(user_raw, str)
        and user_raw
        and isinstance(labels, list)
    ):
        severity = severity_raw.lower()
        if severity not in SEVERITY_SCORE:
            severity = "medium"
        score_raw = get("score")
        if score_raw is None:
            score = float(SEVERITY_SCORE[severity])
        elif isinstance(score_raw, (int, float)):
            score = float(score_raw)
        else:
            score = float(score_raw)
        if score < 0.0:
            score = 0.0
        elif score > 100.0:
            score = 100.0

        event_time_raw = get("time")
        if isinstance(event_time_raw, str) and event_time_raw:
            event_time = event_time_raw
        elif default_time is not None:
            event_time = default_time
        else:
            event_time = _utc_now_iso()

        category_raw = get("category")
        raw_ref_raw = get("raw_ref")
        asset_id_raw = get("asset_id")
        src_ip = _none_if_empty(get("src_ip"))
        dst_ip = _none_if_empty(get("dst_ip"))
        asset_id = hostname_raw if asset_id_raw is None else (
            asset_id_raw if isinstance(asset_id_raw, str) and asset_id_raw else str(asset_id_raw)
        )
        return {
            "schema_version": "common_security_event_v1",
            "event_id": event_id_raw,
            "time": event_time,
            "product": "exkururuedr",
            "category": (
                category_raw if isinstance(category_raw, str) and category_raw else str(category_raw or "process")
            ),
            "event_type": event_type_raw,
            "severity": severity,
            "score": score,
            "labels": labels,
            "asset_id": asset_id,
            "hostname": hostname_raw,
            "user": user_raw,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "raw_ref": raw_ref_raw if isinstance(raw_ref_raw, str) else str(raw_ref_raw or ""),
        }

    if isinstance(severity_raw, str):
        severity = severity_raw.lower()
    elif severity_raw is None:
        severity = "medium"
    else:
        severity = str(severity_raw).lower()
    if severity not in SEVERITY_SCORE:
        severity = "medium"

    score_raw = get("score")
    if score_raw is None:
        score = float(SEVERITY_SCORE[severity])
    elif isinstance(score_raw, (int, float)):
        score = float(score_raw)
    else:
        score = float(score_raw)
    if score < 0.0:
        score = 0.0
    elif score > 100.0:
        score = 100.0

    event_id = event_id_raw if isinstance(event_id_raw, str) and event_id_raw else (
        str(event_id_raw) if event_id_raw else f"edr-{uuid4()}"
    )

    event_time_raw = get("time")
    if isinstance(event_time_raw, str) and event_time_raw:
        event_time = event_time_raw
    elif event_time_raw:
        event_time = str(event_time_raw)
    elif default_time is not None:
        event_time = default_time
    else:
        event_time = _utc_now_iso()

    asset_id_raw = get("asset_id")
    hostname = (
        hostname_raw
        if isinstance(hostname_raw, str) and hostname_raw
        else asset_id_raw
        if isinstance(asset_id_raw, str) and asset_id_raw
        else str(hostname_raw or asset_id_raw or "unknown-host")
    )
    user = user_raw if isinstance(user_raw, str) and user_raw else str(user_raw or "unknown")

    if labels is None:
        normalized_labels = ["edr", "endpoint"]
    elif isinstance(labels, list):
        normalized_labels = [item if isinstance(item, str) else str(item) for item in labels]
    else:
        normalized_labels = [labels if isinstance(labels, str) else str(labels)]

    src_ip = _none_if_empty(get("src_ip"))
    dst_ip = _none_if_empty(get("dst_ip"))
    category_raw = get("category")
    raw_ref_raw = get("raw_ref")
    asset_id = asset_id_raw if isinstance(asset_id_raw, str) and asset_id_raw else str(asset_id_raw or hostname)

    return {
        "schema_version": "common_security_event_v1",
        "event_id": event_id,
        "time": event_time,
        "product": "exkururuedr",
        "category": category_raw if isinstance(category_raw, str) and category_raw else str(category_raw or "process"),
        "event_type": (
            event_type_raw if isinstance(event_type_raw, str) and event_type_raw else str(event_type_raw or "EDR_GENERIC_ALERT")
        ),
        "severity": severity,
        "score": score,
        "labels": normalized_labels,
        "asset_id": asset_id,
        "hostname": hostname,
        "user": user,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "raw_ref": raw_ref_raw if isinstance(raw_ref_raw, str) else str(raw_ref_raw or ""),
    }


def normalize_raw_events_iter(raw_events: list[dict[str, Any]]) -> Any:
    # Share one timestamp per batch when source event has no explicit time.
    batch_now = _utc_now_iso()
    normalize = _normalize_raw_event
    for raw in raw_events:
        yield normalize(raw, default_time=batch_now)


def _none_if_empty(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        if not value:
            return None
        text = value.strip()
    else:
        text = str(value).strip()
    return text if text else None
