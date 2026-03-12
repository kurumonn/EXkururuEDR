from pathlib import Path

from exkururuedr.standalone_storage import EdrStandaloneStorage


def test_storage_events_policy_response_roundtrip(tmp_path: Path) -> None:
    db = tmp_path / "edr.sqlite3"
    storage = EdrStandaloneStorage(db)

    inserted = storage.add_events(
        [
            {
                "event_id": "e-1",
                "severity": "high",
                "category": "process",
                "event_type": "SUSPICIOUS_PROCESS",
            }
        ]
    )
    assert inserted == 1
    assert storage.count_events() == 1
    alerts = storage.list_alerts(limit=10)
    assert len(alerts) == 1

    pid = storage.set_policy("p1", {"x": 1})
    assert pid > 0
    current = storage.current_policy()
    assert current is not None
    assert current["title"] == "p1"

    rid = storage.add_response(
        {
            "ok": True,
            "action": "isolate",
            "target": "host-network",
            "dry_run": True,
            "detail": "dry_run_noop",
        }
    )
    assert rid > 0
    responses = storage.list_responses(limit=10)
    assert len(responses) == 1

