#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import resource
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from exkururuedr.auth import sign_payload, verify_hmac_headers
from exkururuedr.normalize import normalize_raw_events_iter
from exkururuedr.trusted_sources import TrustedSourceRegistry


def _make_raw_event(i: int) -> dict:
    return {
        "event_id": f"raw-{i}",
        "event_type": "SUSPICIOUS_PROCESS" if i % 2 == 0 else "SUSPICIOUS_NETWORK",
        "severity": "high" if i % 3 else "medium",
        "hostname": f"host-{i % 50}",
        "user": f"user-{i % 20}",
        "src_ip": f"10.10.{(i // 255) % 255}.{i % 255}",
        "dst_ip": "198.51.100.10",
        "labels": ["edr", "endpoint", "benchmark"],
    }


def run_benchmark(events: int, loops: int, max_skew_sec: int) -> dict:
    registry = TrustedSourceRegistry.from_json_file(str(ROOT / "examples" / "trusted_sources.json"))
    source_id = "edr-agent-01"
    source = registry.get(source_id)
    if source is None:
        raise RuntimeError("trusted source 'edr-agent-01' not found")

    # Keep auth payload compact for steady-state verification benchmark.
    body = b'{"probe":"auth"}'
    now_ts = int(time.time())
    ts_str = str(now_ts)
    signature = sign_payload(ts_str, body, source.secret)
    headers = {
        "X-EDR-Source-Id": source_id,
        "X-EDR-Timestamp": ts_str,
        "X-EDR-Signature": signature,
    }

    rss_start_kb = _current_rss_kb()
    t0_wall = time.perf_counter()
    t0_cpu = time.process_time()

    raw_events = [_make_raw_event(i) for i in range(events)]
    normalized_count = 0
    auth_ok_count = 0
    for _ in range(loops):
        result = verify_hmac_headers(headers, body, registry, now_ts=now_ts, max_skew_sec=max_skew_sec)
        if result.ok:
            auth_ok_count += 1
        for _ in normalize_raw_events_iter(raw_events):
            normalized_count += 1

    elapsed_wall = time.perf_counter() - t0_wall
    elapsed_cpu = time.process_time() - t0_cpu

    max_rss_kb = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    rss_end_kb = _current_rss_kb()
    throughput_eps = normalized_count / elapsed_wall if elapsed_wall > 0 else 0.0

    return {
        "events_per_loop": events,
        "loops": loops,
        "normalized_total": normalized_count,
        "auth_total": loops,
        "auth_ok_total": auth_ok_count,
        "auth_success_rate": round(auth_ok_count / loops, 6) if loops else 0.0,
        "elapsed_wall_sec": round(elapsed_wall, 6),
        "elapsed_cpu_sec": round(elapsed_cpu, 6),
        "throughput_events_per_sec": round(throughput_eps, 2),
        "rss_start_kb": rss_start_kb,
        "rss_end_kb": rss_end_kb,
        "max_rss_kb": max_rss_kb,
        "rss_delta_kb": max(0, rss_end_kb - rss_start_kb),
        "rss_start_mb": round(rss_start_kb / 1024.0, 3),
        "rss_end_mb": round(rss_end_kb / 1024.0, 3),
        "max_rss_mb": round(max_rss_kb / 1024.0, 3),
        "rss_delta_mb": round(max(0, rss_end_kb - rss_start_kb) / 1024.0, 3),
        "target_vps": "1core_512mb",
    }


def _current_rss_kb() -> int:
    status = Path("/proc/self/status")
    if not status.exists():
        return 0
    for line in status.read_text(encoding="utf-8").splitlines():
        if line.startswith("VmRSS:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Benchmark EDR normalize + auth flow.")
    parser.add_argument("--events", type=int, default=1000, help="events per loop")
    parser.add_argument("--loops", type=int, default=20, help="benchmark loop count")
    parser.add_argument("--max-skew-sec", type=int, default=300)
    parser.add_argument("--out", default="", help="optional output JSON path")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    result = run_benchmark(args.events, args.loops, args.max_skew_sec)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
