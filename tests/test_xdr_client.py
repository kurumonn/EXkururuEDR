import json
from io import BytesIO
from unittest.mock import patch

from exkururuedr.config import AgentConfig
from exkururuedr.xdr_client import export_batch


class _Resp:
    def __init__(self, status: int, payload: dict):
        self.status = status
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _cfg() -> AgentConfig:
    return AgentConfig(
        agent_id="a",
        workspace="w",
        spool_dir="/tmp/sp",
        log_dir="/tmp/lg",
        xdr_base_url="http://127.0.0.1:8810",
        xdr_source_key="edr-lab-01",
        xdr_source_token="tok",
    )


def test_export_batch_empty_is_ok() -> None:
    result = export_batch(_cfg(), [])
    assert result["ok"] is True
    assert result["sent"] == 0


def test_export_batch_success_response() -> None:
    with patch("exkururuedr.xdr_client.urlopen", return_value=_Resp(202, {"accepted": 1, "inserted": 1})):
        result = export_batch(_cfg(), [{"event_id": "e1"}])
    assert result["ok"] is True
    assert result["status"] == 202

