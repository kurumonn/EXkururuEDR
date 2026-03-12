from pathlib import Path

from exkururuedr.config import AgentConfig
from exkururuedr.response import execute_response, map_decision_to_response


def _config(tmp_path: Path) -> AgentConfig:
    return AgentConfig(
        agent_id="a",
        workspace="w",
        spool_dir=str(tmp_path / "spool"),
        log_dir=str(tmp_path / "logs"),
        response_dry_run=True,
        quarantine_dir=str(tmp_path / "quarantine"),
        allow_kill_processes=("malware-sample",),
    )


def test_execute_response_dry_run() -> None:
    config = _config(Path("/tmp"))
    result = execute_response("isolate", "host-network", config=config, dry_run=True)
    assert result.ok is True
    assert result.dry_run is True


def test_execute_response_quarantine_enforce(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    src = tmp_path / "sample.bin"
    src.write_text("x", encoding="utf-8")
    result = execute_response("quarantine", str(src), config=cfg, dry_run=False)
    assert result.ok is True
    assert "moved_to:" in result.detail


def test_map_decision_to_response() -> None:
    event = {
        "category": "persistence",
        "event_type": "PERSISTENCE_SURFACE_SUMMARY",
        "local_decision": {"final_action": "block"},
        "src_ip": "10.0.0.5",
    }
    action = map_decision_to_response(event)
    assert action == ("isolate", "10.0.0.5")

