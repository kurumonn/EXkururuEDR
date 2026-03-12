from __future__ import annotations

import argparse
import json
from pathlib import Path

from .auth import sign_payload, verify_hmac_headers
from .trusted_sources import TrustedSourceRegistry


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate EDR HMAC auth contract.")
    parser.add_argument("--sources", required=True, help="trusted sources JSON path")
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--timestamp", required=True, help="unix seconds")
    parser.add_argument("--body-file", required=True, help="raw request body file")
    parser.add_argument("--signature", default="", help="optional pre-computed signature")
    parser.add_argument("--max-skew-sec", type=int, default=300)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    registry = TrustedSourceRegistry.from_json_file(args.sources)
    body = Path(args.body_file).read_bytes()

    signature = args.signature.strip().lower()
    if not signature:
        source = registry.get(args.source_id)
        if source is None:
            print("ERROR: source not found")
            return 1
        signature = sign_payload(args.timestamp, body, source.secret)
        print(f"generated_signature={signature}")

    headers = {
        "X-EDR-Source-Id": args.source_id,
        "X-EDR-Timestamp": args.timestamp,
        "X-EDR-Signature": signature,
    }
    result = verify_hmac_headers(headers, body, registry, max_skew_sec=args.max_skew_sec)
    print(json.dumps({"ok": result.ok, "source_id": result.source_id, "reason": result.reason}))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

