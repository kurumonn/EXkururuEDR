# EDR Shared Secret Contract (MVP)

This document defines the EDR-side request authentication contract for
cross-product ingestion.

## Required headers

- `X-EDR-Source-Id`
- `X-EDR-Timestamp` (UNIX seconds)
- `X-EDR-Signature` (hex, hmac-sha256)

## Signing payload

`"{timestamp}.{raw_request_body_bytes}"`

## Signature

`HMAC-SHA256(shared_secret, signing_payload)`

## Time skew policy

- default allow: `+-300` seconds
- reject when out of range

## Trusted source model

Trusted source registry is loaded from JSON:

```json
{
  "sources": [
    {"source_id": "edr-agent-01", "secret": "replace-with-shared-secret", "enabled": true}
  ]
}
```

Disabled sources are rejected as `unknown_or_disabled_source`.
