from exkururuedr.normalize import normalize_raw_event


def test_normalize_raw_event_sets_common_schema_fields() -> None:
    raw = {
        "event_id": "raw-1",
        "time": "2026-03-11T10:00:00Z",
        "event_type": "SUSPICIOUS_PROCESS",
        "severity": "high",
        "hostname": "edge-node-01",
        "user": "alice",
    }
    event = normalize_raw_event(raw)
    assert event["schema_version"] == "common_security_event_v1"
    assert event["product"] == "exkururuedr"
    assert event["severity"] == "high"
    assert event["score"] == 80.0
    assert event["labels"] == ["edr", "endpoint"]


def test_normalize_raw_event_clamps_score_range() -> None:
    raw = {"score": 1000, "severity": "critical"}
    event = normalize_raw_event(raw)
    assert event["score"] == 100.0

