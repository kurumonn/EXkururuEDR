from exkururuedr.collector import collect_linux_summaries, summaries_to_raw_events


def test_collect_linux_summaries_has_expected_keys() -> None:
    summaries = collect_linux_summaries()
    assert set(summaries.keys()) == {"process", "network", "persistence", "file"}


def test_summaries_to_raw_events_shape() -> None:
    summaries = {
        "process": {"kind": "process", "sampled_processes": 1},
        "network": {"kind": "network", "tcp_sockets": 1, "udp_sockets": 1},
    }
    events = summaries_to_raw_events(summaries, agent_id="agent-x")
    assert len(events) == 2
    assert all("event_id" in e for e in events)
    assert all("category" in e for e in events)
    assert all("summary" in e for e in events)

