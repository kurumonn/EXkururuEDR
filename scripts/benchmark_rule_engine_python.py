#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
import sys

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from exkururuedr.rule_engine import ACTION_PRIORITY, _matches
from exkururuedr.rules import LocalRule


def parse_list(value: str) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(v for v in value.split(",") if v)


def parse_input(path: Path) -> tuple[int, list[LocalRule], list[dict]]:
    loops = 0
    rules: list[LocalRule] = []
    events: list[dict] = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        parts = line.split("|")
        if parts[0] == "CONFIG":
            if len(parts) != 2:
                raise ValueError(f"invalid CONFIG line {line_no}")
            loops = int(parts[1])
        elif parts[0] == "RULE":
            if len(parts) != 10:
                raise ValueError(f"invalid RULE line {line_no}")
            rules.append(
                LocalRule(
                    rule_id=parts[1],
                    name=parts[1],
                    enabled=parts[2] == "1",
                    event_types=parse_list(parts[3]),
                    categories=parse_list(parts[4]),
                    severities=tuple(v.lower() for v in parse_list(parts[5])),
                    labels_contains=parse_list(parts[6]),
                    min_score=float(parts[7]),
                    action=parts[8],
                    reason=parts[9],
                )
            )
        elif parts[0] == "EVENT":
            if len(parts) != 6:
                raise ValueError(f"invalid EVENT line {line_no}")
            events.append(
                {
                    "event_type": parts[1],
                    "category": parts[2],
                    "severity": parts[3].lower(),
                    "score": float(parts[4]),
                    "labels": [v for v in parts[5].split(",") if v],
                }
            )
        else:
            raise ValueError(f"unknown record type line {line_no}")
    if loops < 1:
        raise ValueError("invalid loops")
    return loops, rules, events


def evaluate_once(events: list[dict], rules: list[LocalRule]) -> int:
    blocked = 0
    for event in events:
        top_priority = -1
        for rule in rules:
            if not rule.enabled:
                continue
            if _matches(event, rule):
                p = ACTION_PRIORITY.get(rule.action, 0)
                if p > top_priority:
                    top_priority = p
        if top_priority >= ACTION_PRIORITY["block"]:
            blocked += 1
    return blocked


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", type=Path)
    args = parser.parse_args()
    loops, rules, events = parse_input(args.input_file)

    started = time.perf_counter()
    total_blocked = 0
    for _ in range(loops):
        total_blocked += evaluate_once(events, rules)
    elapsed_sec = time.perf_counter() - started
    loops_per_sec = loops / elapsed_sec if elapsed_sec > 0 else 0.0
    print(
        json.dumps(
            {
                "loops": loops,
                "rule_count": len(rules),
                "event_count": len(events),
                "total_blocked": total_blocked,
                "elapsed_sec": elapsed_sec,
                "loops_per_sec": loops_per_sec,
            }
        )
    )


if __name__ == "__main__":
    main()
