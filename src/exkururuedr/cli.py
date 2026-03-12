from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .normalize import normalize_raw_events_iter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Normalize raw EDR events to common_security_event_v1.")
    parser.add_argument("input", help="Input JSON file (object/list/{events:[]})")
    parser.add_argument("--pretty", action="store_true", help="Pretty print output")
    return parser


def _load(path: str) -> list[dict]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, dict) and isinstance(raw.get("events"), list):
        return [x for x in raw["events"] if isinstance(x, dict)]
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    if isinstance(raw, dict):
        return [raw]
    raise ValueError("Unsupported input JSON shape")


def main() -> int:
    args = build_parser().parse_args()
    raw_events = _load(args.input)
    # Stream output to avoid building a second large list in memory.
    if args.pretty:
        sys.stdout.write('{\n  "events": [\n')
        first = True
        for event in normalize_raw_events_iter(raw_events):
            if not first:
                sys.stdout.write(",\n")
            sys.stdout.write("    ")
            sys.stdout.write(json.dumps(event, ensure_ascii=False, indent=2).replace("\n", "\n    "))
            first = False
        sys.stdout.write("\n  ]\n}\n")
    else:
        sys.stdout.write('{"events":[')
        first = True
        for event in normalize_raw_events_iter(raw_events):
            if not first:
                sys.stdout.write(",")
            sys.stdout.write(json.dumps(event, ensure_ascii=False))
            first = False
        sys.stdout.write("]}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
