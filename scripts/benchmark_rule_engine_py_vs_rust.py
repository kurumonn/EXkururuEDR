#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PY_BENCH = ROOT / "scripts" / "benchmark_rule_engine_python.py"
RUST_CRATE = ROOT / "rust_rule_bench"
RUST_BIN = RUST_CRATE / "target" / "release" / "rust_rule_bench"


def run_command(cmd: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True)


def parse_time_v(stderr: str) -> dict[str, float]:
    def find(pattern: str) -> float:
        m = re.search(pattern, stderr)
        return float(m.group(1)) if m else 0.0

    max_rss_kb = find(r"Maximum resident set size \(kbytes\):\s*(\d+)")
    return {
        "max_rss_kb": max_rss_kb,
        "max_rss_mb": round(max_rss_kb / 1024.0, 3),
        "user_sec": find(r"User time \(seconds\):\s*([0-9.]+)"),
        "sys_sec": find(r"System time \(seconds\):\s*([0-9.]+)"),
        "cpu_percent": find(r"Percent of CPU this job got:\s*(\d+)"),
    }


def parse_json_stdout(stdout: str) -> dict[str, Any]:
    for line in reversed(stdout.splitlines()):
        text = line.strip()
        if text.startswith("{") and text.endswith("}"):
            return json.loads(text)
    raise RuntimeError("json payload not found")


def generate_input_lines(*, rules: int, events: int, loops: int) -> list[str]:
    severities = ["low", "medium", "high", "critical"]
    event_types = ["SUSPICIOUS_PROCESS", "SUSPICIOUS_NETWORK", "FILE_CHANGE", "LOGIN_ANOMALY"]
    categories = ["process", "network", "file", "auth"]

    lines: list[str] = [f"CONFIG|{loops}"]
    for i in range(rules):
        enabled = "1"
        event_type = event_types[i % len(event_types)]
        category = categories[i % len(categories)]
        severity = severities[i % len(severities)]
        labels = "edr,endpoint" if i % 2 == 0 else "powershell,endpoint"
        min_score = 20.0 + float((i * 7) % 70)
        action = "block" if i % 5 == 0 else "observe" if i % 3 == 0 else "limit"
        lines.append(
            f"RULE|r{i}|{enabled}|{event_type}|{category}|{severity}|{labels}|{min_score:.2f}|{action}|reason-{i}"
        )

    for i in range(events):
        event_type = event_types[(i * 3) % len(event_types)]
        category = categories[(i * 5) % len(categories)]
        severity = severities[(i * 7) % len(severities)]
        score = 10.0 + float((i * 13) % 90)
        labels = "edr,endpoint,powershell" if i % 4 == 0 else "edr,endpoint"
        lines.append(f"EVENT|{event_type}|{category}|{severity}|{score:.2f}|{labels}")
    return lines


def run_python(input_path: Path) -> dict[str, Any]:
    proc = run_command(
        ["/usr/bin/time", "-v", "python3", str(PY_BENCH), str(input_path)],
        cwd=ROOT,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"python bench failed\nstdout={proc.stdout}\nstderr={proc.stderr}")
    payload = parse_json_stdout(proc.stdout)
    payload["resource"] = parse_time_v(proc.stderr)
    return payload


def run_rust(input_path: Path) -> dict[str, Any]:
    build = run_command(["cargo", "build", "--release", "--quiet"], cwd=RUST_CRATE)
    if build.returncode != 0:
        raise RuntimeError(f"rust build failed\nstdout={build.stdout}\nstderr={build.stderr}")
    proc = run_command(
        ["/usr/bin/time", "-v", str(RUST_BIN), str(input_path)],
        cwd=RUST_CRATE,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"rust bench failed\nstdout={proc.stdout}\nstderr={proc.stderr}")
    payload = parse_json_stdout(proc.stdout)
    payload["resource"] = parse_time_v(proc.stderr)
    return payload


def ratio(numerator: float, denominator: float) -> float | None:
    if denominator <= 0:
        return None
    return numerator / denominator


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules", type=int, default=120)
    parser.add_argument("--events", type=int, default=160000)
    parser.add_argument("--loops", type=int, default=8)
    parser.add_argument("--out", type=Path, default=ROOT / "docs" / "perf_edr_rule_py_vs_rust.json")
    args = parser.parse_args()

    lines = generate_input_lines(rules=max(1, args.rules), events=max(1, args.events), loops=max(1, args.loops))
    with NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False) as fp:
        temp_path = Path(fp.name)
        fp.write("\n".join(lines))

    try:
        py = run_python(temp_path)
        rs = run_rust(temp_path)
    finally:
        temp_path.unlink(missing_ok=True)

    py_elapsed = float(py.get("elapsed_sec", 0.0))
    rs_elapsed = float(rs.get("elapsed_sec", 0.0))
    py_rss = float(py.get("resource", {}).get("max_rss_mb", 0.0))
    rs_rss = float(rs.get("resource", {}).get("max_rss_mb", 0.0))

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "workload": {"rules": args.rules, "events": args.events, "loops": args.loops},
        "python": py,
        "rust": rs,
        "comparison": {
            "speedup_rust_vs_python": ratio(py_elapsed, rs_elapsed),
            "rss_ratio_rust_vs_python": ratio(rs_rss, py_rss),
            "rss_reduction_percent": (1.0 - ratio(rs_rss, py_rss)) * 100.0 if py_rss > 0 else None,
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(result, indent=2)
    args.out.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
