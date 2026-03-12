from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


ALLOWED_ACTIONS = {"allow", "observe", "limit", "challenge", "block"}


@dataclass(frozen=True)
class LocalRule:
    rule_id: str
    name: str
    enabled: bool
    event_types: tuple[str, ...]
    categories: tuple[str, ...]
    severities: tuple[str, ...]
    labels_contains: tuple[str, ...]
    min_score: float
    action: str
    reason: str


def load_local_rules(rule_file: str | Path) -> list[LocalRule]:
    raw = yaml.safe_load(Path(rule_file).read_text(encoding="utf-8")) or {}
    rows = raw.get("rules", raw if isinstance(raw, list) else [])
    if not isinstance(rows, list):
        raise ValueError("rules file must contain array or {rules:[...]}")

    rules: list[LocalRule] = []
    for item in rows:
        if not isinstance(item, dict):
            raise ValueError("rule must be object")
        rules.append(_parse_rule(item))
    return rules


def _parse_rule(item: dict[str, Any]) -> LocalRule:
    rule_id = str(item.get("rule_id", "")).strip()
    name = str(item.get("name", "")).strip()
    if not rule_id or not name:
        raise ValueError("rule_id and name are required")
    action = str(item.get("action", "observe")).strip().lower()
    if action not in ALLOWED_ACTIONS:
        raise ValueError(f"invalid action: {action}")
    return LocalRule(
        rule_id=rule_id,
        name=name,
        enabled=bool(item.get("enabled", True)),
        event_types=tuple(str(v).strip() for v in item.get("event_types", []) if str(v).strip()),
        categories=tuple(str(v).strip() for v in item.get("categories", []) if str(v).strip()),
        severities=tuple(str(v).strip().lower() for v in item.get("severities", []) if str(v).strip()),
        labels_contains=tuple(str(v).strip() for v in item.get("labels_contains", []) if str(v).strip()),
        min_score=float(item.get("min_score", 0.0)),
        action=action,
        reason=str(item.get("reason", name)),
    )

