from exkururuedr.agent_cli import _map_xdr_action_to_local


def test_map_xdr_action_to_local_supported() -> None:
    assert _map_xdr_action_to_local("host_isolate", "host-a") == ("isolate", "host-a")
    assert _map_xdr_action_to_local("process_kill", "1234") == ("kill", "1234")
    assert _map_xdr_action_to_local("file_quarantine", "/tmp/a.bin") == ("quarantine", "/tmp/a.bin")


def test_map_xdr_action_to_local_unsupported() -> None:
    assert _map_xdr_action_to_local("ndr_block_ip", "1.2.3.4") is None

