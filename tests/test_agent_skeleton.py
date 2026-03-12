from pathlib import Path

from exkururuedr.config import AgentConfig
from exkururuedr.health import health_snapshot
from exkururuedr.spool import EventSpool


def test_config_from_file_and_spool_stats(tmp_path: Path) -> None:
    cfg_path = tmp_path / "agent_config.json"
    spool_dir = tmp_path / "spool"
    log_dir = tmp_path / "logs"
    cfg_path.write_text(
        (
            "{"
            "\"agent_id\":\"test-agent\","
            "\"workspace\":\"ws\","
            f"\"spool_dir\":\"{spool_dir}\","
            f"\"log_dir\":\"{log_dir}\""
            "}"
        ),
        encoding="utf-8",
    )

    config = AgentConfig.from_file(str(cfg_path))
    spool = EventSpool(config.spool_dir, max_spool_files=100)
    spool.init_dirs()
    for i in range(120):
        spool.enqueue({"event_id": f"e-{i}", "event_type": "x"})
    stats = spool.stats()
    assert stats["pending_events"] == 100

    health = health_snapshot(config, spool)
    assert health["ok"] is True
    assert health["agent"]["agent_id"] == "test-agent"
