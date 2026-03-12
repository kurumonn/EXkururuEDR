from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class AgentConfig:
    agent_id: str
    workspace: str
    spool_dir: str
    log_dir: str
    heartbeat_sec: int = 30
    max_spool_files: int = 2000
    response_dry_run: bool = True
    quarantine_dir: str = "./data/quarantine"
    allow_kill_processes: tuple[str, ...] = ("malware-sample",)
    xdr_base_url: str = "http://127.0.0.1:8810"
    xdr_source_key: str = "edr-lab-01"
    xdr_source_token: str = ""
    xdr_timeout_sec: int = 5
    xdr_batch_path: str = "/api/v1/events/batch"
    xdr_single_path: str = "/api/v1/events/single"
    xdr_policy_path: str = "/api/v1/policy/current"
    xdr_ack_path: str = "/api/v1/events/single"

    @classmethod
    def from_file(cls, path: str) -> "AgentConfig":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            agent_id=str(payload.get("agent_id", "edr-agent-unknown")),
            workspace=str(payload.get("workspace", "default")),
            spool_dir=str(payload.get("spool_dir", "./data/spool")),
            log_dir=str(payload.get("log_dir", "./data/logs")),
            heartbeat_sec=max(5, int(payload.get("heartbeat_sec", 30))),
            max_spool_files=max(100, int(payload.get("max_spool_files", 2000))),
            response_dry_run=bool(payload.get("response_dry_run", True)),
            quarantine_dir=str(payload.get("quarantine_dir", "./data/quarantine")),
            allow_kill_processes=tuple(
                str(v) for v in payload.get("allow_kill_processes", ["malware-sample"]) if str(v).strip()
            ),
            xdr_base_url=str(payload.get("xdr_base_url", "http://127.0.0.1:8810")).rstrip("/"),
            xdr_source_key=str(payload.get("xdr_source_key", "edr-lab-01")),
            xdr_source_token=str(payload.get("xdr_source_token", "")),
            xdr_timeout_sec=max(1, int(payload.get("xdr_timeout_sec", 5))),
            xdr_batch_path=str(payload.get("xdr_batch_path", "/api/v1/events/batch")),
            xdr_single_path=str(payload.get("xdr_single_path", "/api/v1/events/single")),
            xdr_policy_path=str(payload.get("xdr_policy_path", "/api/v1/policy/current")),
            xdr_ack_path=str(payload.get("xdr_ack_path", "/api/v1/events/single")),
        )

    def to_dict(self) -> dict:
        return asdict(self)
