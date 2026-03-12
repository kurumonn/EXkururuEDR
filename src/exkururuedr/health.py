from __future__ import annotations

import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import AgentConfig
from .spool import EventSpool


def _rss_kb() -> int:
    status = Path("/proc/self/status")
    if not status.exists():
        return 0
    for line in status.read_text(encoding="utf-8").splitlines():
        if line.startswith("VmRSS:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
    return 0


def health_snapshot(config: AgentConfig, spool: EventSpool) -> dict[str, Any]:
    loadavg = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)
    spool.init_dirs()
    disk = shutil.disk_usage(spool.root)
    return {
        "ok": True,
        "time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "agent": {
            "agent_id": config.agent_id,
            "workspace": config.workspace,
            "heartbeat_sec": config.heartbeat_sec,
        },
        "runtime": {
            "pid": os.getpid(),
            "cpu_count": os.cpu_count() or 1,
            "loadavg_1m": round(float(loadavg[0]), 4),
            "loadavg_5m": round(float(loadavg[1]), 4),
            "rss_kb": _rss_kb(),
            "rss_mb": round(_rss_kb() / 1024.0, 3),
        },
        "spool": spool.stats(),
        "disk": {
            "total_mb": round(disk.total / (1024 * 1024), 2),
            "used_mb": round(disk.used / (1024 * 1024), 2),
            "free_mb": round(disk.free / (1024 * 1024), 2),
        },
    }

