from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class EdrStandaloneStorage:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS edr_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT,
                    severity TEXT,
                    category TEXT,
                    event_type TEXT,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS edr_policy_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    policy_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS edr_responses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    dry_run INTEGER NOT NULL,
                    ok INTEGER NOT NULL,
                    detail TEXT,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )

    def add_events(self, events: list[dict[str, Any]]) -> int:
        now = _utc_now()
        rows = [
            (
                str(event.get("event_id", "")),
                str(event.get("severity", "")),
                str(event.get("category", "")),
                str(event.get("event_type", "")),
                json.dumps(event, ensure_ascii=False),
                now,
            )
            for event in events
        ]
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO edr_events(event_id,severity,category,event_type,payload_json,created_at)
                VALUES(?,?,?,?,?,?)
                """,
                rows,
            )
        return len(rows)

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT id,event_id,severity,category,event_type,payload_json,created_at
                FROM edr_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (max(1, min(limit, 1000)),),
            )
            rows = cur.fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            payload = json.loads(row["payload_json"])
            out.append(
                {
                    "id": row["id"],
                    "event_id": row["event_id"],
                    "severity": row["severity"],
                    "category": row["category"],
                    "event_type": row["event_type"],
                    "payload": payload,
                    "created_at": row["created_at"],
                }
            )
        return out

    def count_events(self) -> int:
        with self._connect() as conn:
            cur = conn.execute("SELECT COUNT(*) AS c FROM edr_events")
            return int(cur.fetchone()["c"])

    def list_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        events = self.list_events(limit=max(1, min(limit * 3, 1000)))
        out: list[dict[str, Any]] = []
        for ev in events:
            payload = ev.get("payload", {})
            severity = str(payload.get("severity", ev.get("severity", ""))).lower()
            action = str(payload.get("local_decision", {}).get("final_action", "")).lower()
            if severity in {"high", "critical"} or action in {"limit", "challenge", "block"}:
                out.append(ev)
            if len(out) >= limit:
                break
        return out

    def set_policy(self, title: str, policy: dict[str, Any]) -> int:
        now = _utc_now()
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO edr_policy_versions(title,policy_json,created_at)
                VALUES(?,?,?)
                """,
                (title, json.dumps(policy, ensure_ascii=False), now),
            )
            return int(cur.lastrowid)

    def current_policy(self) -> dict[str, Any] | None:
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT id,title,policy_json,created_at
                FROM edr_policy_versions
                ORDER BY id DESC
                LIMIT 1
                """
            )
            row = cur.fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "title": row["title"],
            "policy": json.loads(row["policy_json"]),
            "created_at": row["created_at"],
        }

    def add_response(self, result: dict[str, Any]) -> int:
        now = _utc_now()
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO edr_responses(action,target,dry_run,ok,detail,result_json,created_at)
                VALUES(?,?,?,?,?,?,?)
                """,
                (
                    str(result.get("action", "")),
                    str(result.get("target", "")),
                    1 if bool(result.get("dry_run", True)) else 0,
                    1 if bool(result.get("ok", False)) else 0,
                    str(result.get("detail", "")),
                    json.dumps(result, ensure_ascii=False),
                    now,
                ),
            )
            return int(cur.lastrowid)

    def list_responses(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT id,action,target,dry_run,ok,detail,result_json,created_at
                FROM edr_responses
                ORDER BY id DESC
                LIMIT ?
                """,
                (max(1, min(limit, 1000)),),
            )
            rows = cur.fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            out.append(
                {
                    "id": row["id"],
                    "action": row["action"],
                    "target": row["target"],
                    "dry_run": bool(row["dry_run"]),
                    "ok": bool(row["ok"]),
                    "detail": row["detail"],
                    "result": json.loads(row["result_json"]),
                    "created_at": row["created_at"],
                }
            )
        return out

