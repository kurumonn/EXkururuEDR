from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .config import AgentConfig


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _join(base: str, path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return base.rstrip("/") + path


def _headers(config: AgentConfig) -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "X-Source-Key": config.xdr_source_key,
        "X-Source-Token": config.xdr_source_token,
    }


def _request_json(
    method: str,
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any] | None,
    timeout_sec: int,
) -> tuple[int, dict[str, Any]]:
    data = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = Request(url=url, data=data, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urlopen(req, timeout=timeout_sec) as resp:
            raw = resp.read().decode("utf-8")
            parsed = json.loads(raw) if raw else {}
            if not isinstance(parsed, dict):
                parsed = {"raw": parsed}
            return resp.status, parsed
    except HTTPError as exc:
        raw = exc.read().decode("utf-8") if exc.fp else ""
        parsed = {"error": raw or str(exc)}
        return int(exc.code), parsed
    except URLError as exc:
        return 0, {"error": f"url_error:{exc}"}


def export_batch(config: AgentConfig, events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        return {"ok": True, "sent": 0, "status": 200, "body": {"accepted": 0, "inserted": 0, "duplicates": 0}}
    url = _join(config.xdr_base_url, config.xdr_batch_path)
    status, body = _request_json("POST", url, _headers(config), {"events": events}, config.xdr_timeout_sec)
    return {"ok": 200 <= status < 300, "sent": len(events), "status": status, "body": body}


def send_heartbeat(config: AgentConfig, pending_events: int) -> dict[str, Any]:
    url = _join(config.xdr_base_url, config.xdr_single_path)
    payload = {
        "schema_version": "common_security_event_v1",
        "event_id": f"{config.agent_id}-heartbeat-{int(datetime.now(timezone.utc).timestamp())}",
        "time": _utc_now(),
        "product": "exkururuedr",
        "category": "identity",
        "event_type": "EDR_HEARTBEAT",
        "severity": "low",
        "score": 5,
        "labels": ["heartbeat", "edr"],
        "asset_id": socket.gethostname(),
        "hostname": socket.gethostname(),
        "user": "system",
        "src_ip": None,
        "dst_ip": None,
        "pending_events": pending_events,
    }
    status, body = _request_json("POST", url, _headers(config), payload, config.xdr_timeout_sec)
    return {"ok": 200 <= status < 300, "status": status, "body": body}


def fetch_policy(config: AgentConfig) -> dict[str, Any]:
    url = _join(config.xdr_base_url, config.xdr_policy_path)
    status, body = _request_json("GET", url, _headers(config), None, config.xdr_timeout_sec)
    return {"ok": 200 <= status < 300, "status": status, "body": body}


def send_policy_ack(config: AgentConfig, policy_id: str, apply_ok: bool, note: str = "") -> dict[str, Any]:
    url = _join(config.xdr_base_url, config.xdr_ack_path)
    payload = {
        "schema_version": "common_security_event_v1",
        "event_id": f"{config.agent_id}-policy-ack-{int(datetime.now(timezone.utc).timestamp())}",
        "time": _utc_now(),
        "product": "exkururuedr",
        "category": "correlation",
        "event_type": "EDR_POLICY_ACK",
        "severity": "low" if apply_ok else "medium",
        "score": 10 if apply_ok else 40,
        "labels": ["policy", "ack", "edr"],
        "asset_id": socket.gethostname(),
        "hostname": socket.gethostname(),
        "user": "system",
        "src_ip": None,
        "dst_ip": None,
        "policy_id": policy_id,
        "apply_ok": bool(apply_ok),
        "note": note,
    }
    status, body = _request_json("POST", url, _headers(config), payload, config.xdr_timeout_sec)
    return {"ok": 200 <= status < 300, "status": status, "body": body}


def list_actions(config: AgentConfig) -> dict[str, Any]:
    url = _join(config.xdr_base_url, "/api/v1/actions")
    status, body = _request_json("GET", url, {}, None, config.xdr_timeout_sec)
    items = body.get("items", []) if isinstance(body, dict) else []
    if not isinstance(items, list):
        items = []
    return {"ok": 200 <= status < 300, "status": status, "items": items, "body": body}


def update_action_status(config: AgentConfig, action_id: int, status_value: str, result_message: str) -> dict[str, Any]:
    url = _join(config.xdr_base_url, f"/api/v1/actions/{action_id}")
    payload = {"status": status_value, "result_message": result_message}
    status, body = _request_json("PATCH", url, {"Content-Type": "application/json"}, payload, config.xdr_timeout_sec)
    return {"ok": 200 <= status < 300, "status": status, "body": body}
