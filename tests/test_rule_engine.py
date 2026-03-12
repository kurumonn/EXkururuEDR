from exkururuedr.rule_engine import evaluate_event
from exkururuedr.rules import LocalRule


def test_rule_engine_picks_highest_priority_action() -> None:
    event = {
        "event_type": "PERSISTENCE_SURFACE_SUMMARY",
        "category": "persistence",
        "severity": "high",
        "score": 80,
        "labels": ["collector", "summary", "persistence"],
    }
    rules = [
        LocalRule(
            rule_id="r1",
            name="observe",
            enabled=True,
            event_types=(),
            categories=(),
            severities=(),
            labels_contains=("collector",),
            min_score=0,
            action="observe",
            reason="obs",
        ),
        LocalRule(
            rule_id="r2",
            name="block persistence",
            enabled=True,
            event_types=(),
            categories=("persistence",),
            severities=("high",),
            labels_contains=(),
            min_score=70,
            action="block",
            reason="block-persistence",
        ),
    ]
    decision = evaluate_event(event, rules)
    assert decision["final_action"] == "block"
    assert decision["reason"] == "block-persistence"


def test_rule_engine_returns_allow_when_no_match() -> None:
    event = {"event_type": "X", "category": "none", "severity": "low", "score": 10, "labels": []}
    rules = []
    decision = evaluate_event(event, rules)
    assert decision["final_action"] == "allow"

