from __future__ import annotations

import getpass
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .normalize import SEVERITY_SCORE


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def collect_process_summary(limit: int = 100) -> dict[str, Any]:
    proc = Path("/proc")
    count = 0
    names: list[str] = []
    for entry in proc.iterdir() if proc.exists() else []:
        if not entry.name.isdigit():
            continue
        comm = entry / "comm"
        if comm.exists():
            try:
                name = comm.read_text(encoding="utf-8").strip()
                if name:
                    names.append(name)
            except OSError:
                pass
        count += 1
        if count >= limit:
            break
    return {
        "kind": "process",
        "sampled_processes": count,
        "top_names": names[:10],
    }


def collect_network_summary() -> dict[str, Any]:
    tcp_path = Path("/proc/net/tcp")
    udp_path = Path("/proc/net/udp")
    tcp_count = 0
    udp_count = 0
    if tcp_path.exists():
        try:
            tcp_count = max(0, len(tcp_path.read_text(encoding="utf-8").splitlines()) - 1)
        except OSError:
            tcp_count = 0
    if udp_path.exists():
        try:
            udp_count = max(0, len(udp_path.read_text(encoding="utf-8").splitlines()) - 1)
        except OSError:
            udp_count = 0
    return {
        "kind": "network",
        "tcp_sockets": tcp_count,
        "udp_sockets": udp_count,
    }


def collect_persistence_summary() -> dict[str, Any]:
    paths = [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/rc.local",
        "/etc/systemd/system",
    ]
    existing: list[str] = []
    for p in paths:
        path = Path(p)
        if path.exists():
            existing.append(p)
    return {
        "kind": "persistence",
        "known_paths_checked": len(paths),
        "existing_paths": existing,
    }


def collect_file_summary() -> dict[str, Any]:
    watch_paths = [
        "/tmp",
        "/var/tmp",
    ]
    stats: dict[str, int] = {}
    for p in watch_paths:
        path = Path(p)
        if not path.exists() or not path.is_dir():
            stats[p] = 0
            continue
        try:
            stats[p] = len(list(path.iterdir()))
        except OSError:
            stats[p] = 0
    return {
        "kind": "file",
        "watch_paths": stats,
    }


def collect_linux_summaries() -> dict[str, dict[str, Any]]:
    return {
        "process": collect_process_summary(),
        "network": collect_network_summary(),
        "persistence": collect_persistence_summary(),
        "file": collect_file_summary(),
    }


def summaries_to_raw_events(summaries: dict[str, dict[str, Any]], agent_id: str) -> list[dict[str, Any]]:
    host = socket.gethostname()
    user = getpass.getuser()
    now = _utc_now()
    now_epoch = int(datetime.now(timezone.utc).timestamp())
    events: list[dict[str, Any]] = []
    mapping = {
        "process": ("SUSPICIOUS_PROCESS_SUMMARY", "medium"),
        "network": ("SUSPICIOUS_NETWORK_SUMMARY", "medium"),
        "persistence": ("PERSISTENCE_SURFACE_SUMMARY", "high"),
        "file": ("FILE_SURFACE_SUMMARY", "low"),
    }
    for category, summary in summaries.items():
        event_type, severity = mapping.get(category, ("EDR_SUMMARY", "low"))
        events.append(
            {
                "event_id": f"{agent_id}-{category}-{now_epoch}",
                "time": now,
                "event_type": event_type,
                "category": category,
                "severity": severity,
                "hostname": host,
                "user": user,
                "labels": ["collector", "summary", category],
                "raw_ref": "local:collector",
                "summary": summary,
                "src_ip": "",
                "dst_ip": "",
            }
        )
    return events


def summaries_to_normalized_events(summaries: dict[str, dict[str, Any]], agent_id: str) -> list[dict[str, Any]]:
    host = socket.gethostname()
    user = getpass.getuser()
    now = _utc_now()
    now_epoch = int(datetime.now(timezone.utc).timestamp())
    events: list[dict[str, Any]] = []
    mapping = {
        "process": ("SUSPICIOUS_PROCESS_SUMMARY", "medium"),
        "network": ("SUSPICIOUS_NETWORK_SUMMARY", "medium"),
        "persistence": ("PERSISTENCE_SURFACE_SUMMARY", "high"),
        "file": ("FILE_SURFACE_SUMMARY", "low"),
    }
    for category in summaries.keys():
        event_type, severity = mapping.get(category, ("EDR_SUMMARY", "low"))
        events.append(
            {
                "schema_version": "common_security_event_v1",
                "event_id": f"{agent_id}-{category}-{now_epoch}",
                "time": now,
                "product": "exkururuedr",
                "category": category,
                "event_type": event_type,
                "severity": severity,
                "score": float(SEVERITY_SCORE.get(severity, 20)),
                "labels": ["edr", "endpoint", "collector", "summary", category],
                "asset_id": host,
                "hostname": host,
                "user": user,
                "src_ip": None,
                "dst_ip": None,
                "raw_ref": "local:collector",
            }
        )
    return events
