from __future__ import annotations

import json
import shutil
import signal
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import AgentConfig


@dataclass(frozen=True)
class ResponseResult:
    ok: bool
    action: str
    target: str
    dry_run: bool
    detail: str
    time: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def execute_response(action: str, target: str, config: AgentConfig, dry_run: bool | None = None) -> ResponseResult:
    mode = config.response_dry_run if dry_run is None else bool(dry_run)
    action = action.strip().lower()
    target = target.strip()
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    if action not in {"kill", "quarantine", "isolate"}:
        return ResponseResult(False, action, target, mode, "unsupported_action", now)

    if not target:
        return ResponseResult(False, action, target, mode, "empty_target", now)

    if mode:
        return ResponseResult(True, action, target, True, "dry_run_noop", now)

    if action == "kill":
        return _kill_process(target, config, now)
    if action == "quarantine":
        return _quarantine_file(target, config, now)
    if action == "isolate":
        # MVP: record isolate intent only. Real enforcement hook will be added later.
        return ResponseResult(True, action, target, False, "isolate_intent_recorded", now)
    return ResponseResult(False, action, target, mode, "unreachable", now)


def append_response_log(log_dir: str, result: ResponseResult) -> str:
    path = Path(log_dir)
    path.mkdir(parents=True, exist_ok=True)
    f = path / "response_actions.jsonl"
    with f.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(result.to_dict(), ensure_ascii=False) + "\n")
    return str(f)


def map_decision_to_response(event: dict[str, Any]) -> tuple[str, str] | None:
    decision = event.get("local_decision", {})
    action = str(decision.get("final_action", "allow")).lower()
    category = str(event.get("category", "")).lower()
    event_type = str(event.get("event_type", ""))
    if action == "block":
        if category == "process":
            return ("kill", event_type or "unknown-process")
        if category == "file":
            return ("quarantine", _non_empty(event.get("raw_ref"), "/tmp/unknown.file"))
        return ("isolate", _non_empty(event.get("src_ip"), "host-network"))
    if action in {"challenge", "limit"}:
        if category == "file":
            return ("quarantine", _non_empty(event.get("raw_ref"), "/tmp/unknown.file"))
        return ("isolate", _non_empty(event.get("src_ip"), "host-network"))
    return None


def _non_empty(value: Any, default: str) -> str:
    text = str(value or "").strip()
    return text if text else default


def _kill_process(target: str, config: AgentConfig, now: str) -> ResponseResult:
    allowed = set(config.allow_kill_processes)
    if target not in allowed:
        return ResponseResult(False, "kill", target, False, "target_not_allowlisted", now)
    try:
        pid = int(target)
        if pid <= 1:
            return ResponseResult(False, "kill", target, False, "refuse_pid", now)
        signal.kill(pid, signal.SIGTERM)
        return ResponseResult(True, "kill", target, False, "sigterm_sent", now)
    except ValueError:
        # keep MVP safe: do not kill by process name unless explicitly mapped to PID in future.
        return ResponseResult(False, "kill", target, False, "pid_required_for_non_dry_run", now)
    except ProcessLookupError:
        return ResponseResult(False, "kill", target, False, "process_not_found", now)
    except PermissionError:
        return ResponseResult(False, "kill", target, False, "permission_denied", now)


def _quarantine_file(target: str, config: AgentConfig, now: str) -> ResponseResult:
    src = Path(target)
    if not src.exists():
        return ResponseResult(False, "quarantine", target, False, "file_not_found", now)
    qdir = Path(config.quarantine_dir)
    qdir.mkdir(parents=True, exist_ok=True)
    dst = qdir / src.name
    try:
        shutil.move(str(src), str(dst))
        return ResponseResult(True, "quarantine", target, False, f"moved_to:{dst}", now)
    except OSError as exc:
        return ResponseResult(False, "quarantine", target, False, f"move_failed:{exc}", now)
