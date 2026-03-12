from exkururuedr.auth import sign_payload, verify_hmac_headers
from exkururuedr.trusted_sources import TrustedSource, TrustedSourceRegistry


def _registry() -> TrustedSourceRegistry:
    return TrustedSourceRegistry(
        {
            "agent-1": TrustedSource(source_id="agent-1", secret="secret-1", enabled=True),
            "agent-2": TrustedSource(source_id="agent-2", secret="secret-2", enabled=False),
        }
    )


def test_verify_hmac_headers_success() -> None:
    body = b'{"events":[{"x":1}]}'
    timestamp = "1700000000"
    signature = sign_payload(timestamp, body, "secret-1")
    headers = {
        "X-EDR-Source-Id": "agent-1",
        "X-EDR-Timestamp": timestamp,
        "X-EDR-Signature": signature,
    }
    result = verify_hmac_headers(headers, body, _registry(), now_ts=1700000000, max_skew_sec=300)
    assert result.ok is True
    assert result.reason == "ok"


def test_verify_hmac_headers_rejects_disabled_source() -> None:
    body = b"{}"
    headers = {
        "X-EDR-Source-Id": "agent-2",
        "X-EDR-Timestamp": "1700000000",
        "X-EDR-Signature": "x",
    }
    result = verify_hmac_headers(headers, body, _registry(), now_ts=1700000000)
    assert result.ok is False
    assert result.reason == "unknown_or_disabled_source"


def test_verify_hmac_headers_rejects_bad_signature() -> None:
    body = b"{}"
    headers = {
        "X-EDR-Source-Id": "agent-1",
        "X-EDR-Timestamp": "1700000000",
        "X-EDR-Signature": "invalid",
    }
    result = verify_hmac_headers(headers, body, _registry(), now_ts=1700000000)
    assert result.ok is False
    assert result.reason == "bad_signature"

