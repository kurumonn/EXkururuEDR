from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .rules import LocalRule


ACTION_PRIORITY = {
    "allow": 0,
    "observe": 1,
    "limit": 2,
    "challenge": 3,
    "block": 4,
}


@dataclass(frozen=True)
class _CompiledRule:
    rule_id: str
    action: str
    reason: str
    priority: int
    event_types: frozenset[str]
    categories: frozenset[str]
    severities: frozenset[str]
    labels_contains: tuple[str, ...]
    min_score: float


def _compile_rules(rules: list[LocalRule]) -> list[_CompiledRule]:
    compiled: list[_CompiledRule] = []
    for rule in rules:
        if not rule.enabled:
            continue
        compiled.append(
            _CompiledRule(
                rule_id=rule.rule_id,
                action=rule.action,
                reason=rule.reason,
                priority=ACTION_PRIORITY.get(rule.action, 0),
                event_types=frozenset(rule.event_types),
                categories=frozenset(rule.categories),
                severities=frozenset(v.lower() for v in rule.severities),
                labels_contains=tuple(rule.labels_contains),
                min_score=float(rule.min_score),
            )
        )
    return compiled


def _evaluate_event_compiled(event: dict[str, Any], compiled_rules: list[_CompiledRule]) -> dict[str, Any]:
    event_type = str(event.get("event_type", ""))
    category = str(event.get("category", ""))
    severity = str(event.get("severity", "")).lower()
    score = float(event.get("score", 0.0))
    labels = event.get("labels", [])
    label_set = {str(v) for v in labels} if isinstance(labels, list) else {str(labels)}

    matches: list[dict[str, Any]] = []
    top_action = "allow"
    top_reason = "no_rule_matched"
    top_priority = -1
    for rule in compiled_rules:
        if rule.event_types and event_type not in rule.event_types:
            continue
        if rule.categories and category not in rule.categories:
            continue
        if rule.severities and severity not in rule.severities:
            continue
        if score < rule.min_score:
            continue
        if rule.labels_contains and not all(req in label_set for req in rule.labels_contains):
            continue
        matches.append(
            {
                "matched": True,
                "rule_id": rule.rule_id,
                "action": rule.action,
                "reason": rule.reason,
                "priority": rule.priority,
            }
        )
        if rule.priority > top_priority:
            top_priority = rule.priority
            top_action = rule.action
            top_reason = rule.reason

    if not matches:
        return {
            "final_action": "allow",
            "matched_rules": [],
            "reason": "no_rule_matched",
        }
    if len(matches) > 1:
        matches.sort(key=lambda m: int(m.get("priority", 0)), reverse=True)
    return {
        "final_action": top_action,
        "reason": top_reason,
        "matched_rules": matches,
    }


def evaluate_event(event: dict[str, Any], rules: list[LocalRule]) -> dict[str, Any]:
    return _evaluate_event_compiled(event, _compile_rules(rules))


def evaluate_events(events: list[dict[str, Any]], rules: list[LocalRule]) -> list[dict[str, Any]]:
    compiled = _compile_rules(rules)
    out: list[dict[str, Any]] = []
    for event in events:
        decision = _evaluate_event_compiled(event, compiled)
        row = dict(event)
        row["local_decision"] = decision
        out.append(row)
    return out


def _matches(event: dict[str, Any], rule: LocalRule) -> bool:
    event_type = str(event.get("event_type", ""))
    category = str(event.get("category", ""))
    severity = str(event.get("severity", "")).lower()
    labels = event.get("labels", [])
    score = float(event.get("score", 0.0))

    if rule.event_types and event_type not in rule.event_types:
        return False
    if rule.categories and category not in rule.categories:
        return False
    if rule.severities and severity not in rule.severities:
        return False
    if score < rule.min_score:
        return False
    if rule.labels_contains:
        label_set = {str(v) for v in labels} if isinstance(labels, list) else {str(labels)}
        if not all(req in label_set for req in rule.labels_contains):
            return False
    return True
