from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class EventSpool:
    def __init__(self, spool_dir: str, max_spool_files: int = 2000) -> None:
        self.root = Path(spool_dir)
        self.pending = self.root / "pending"
        self.sent = self.root / "sent"
        self.failed = self.root / "failed"
        self.queue_file = self.pending / "events.jsonl"
        self.max_spool_files = max(100, int(max_spool_files))

    def init_dirs(self) -> None:
        self.pending.mkdir(parents=True, exist_ok=True)
        self.sent.mkdir(parents=True, exist_ok=True)
        self.failed.mkdir(parents=True, exist_ok=True)
        if not self.queue_file.exists():
            self.queue_file.touch()

    def enqueue(self, event: dict[str, Any]) -> None:
        self.init_dirs()
        line = json.dumps(event, ensure_ascii=False)
        with self.queue_file.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        self._enforce_limit()

    def pending_count(self) -> int:
        if not self.queue_file.exists():
            return 0
        with self.queue_file.open("r", encoding="utf-8") as f:
            return sum(1 for _ in f if _.strip())

    def peek_batch(self, limit: int = 100) -> list[dict[str, Any]]:
        self.init_dirs()
        rows: list[dict[str, Any]] = []
        with self.queue_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(row, dict):
                    rows.append(row)
                if len(rows) >= max(1, limit):
                    break
        return rows

    def drop_batch(self, n: int) -> int:
        if n <= 0:
            return 0
        self.init_dirs()
        with self.queue_file.open("r", encoding="utf-8") as f:
            lines = [line for line in f if line.strip()]
        dropped = min(n, len(lines))
        remain = lines[dropped:]
        with self.queue_file.open("w", encoding="utf-8") as f:
            for line in remain:
                f.write(line if line.endswith("\n") else line + "\n")
        return dropped

    def stats(self) -> dict[str, Any]:
        return {
            "spool_root": str(self.root),
            "pending_file": str(self.queue_file),
            "pending_events": self.pending_count(),
            "max_spool_files": self.max_spool_files,
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }

    def _enforce_limit(self) -> None:
        # Keep only the latest N records to avoid unlimited local growth.
        if not self.queue_file.exists():
            return
        lines = self.queue_file.read_text(encoding="utf-8").splitlines()
        if len(lines) <= self.max_spool_files:
            return
        kept = lines[-self.max_spool_files :]
        self.queue_file.write_text("\n".join(kept) + "\n", encoding="utf-8")
