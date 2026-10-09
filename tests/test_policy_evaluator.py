from importlib import import_module

import pytest

from app.api.schemas import Severity
from app.policies.schemas import PolicyRules


def evaluate(counts=None, *, sbom=True, **overrides):
    module = import_module("app.policies.evaluator")
    rules = PolicyRules(
        max_critical=overrides.get("max_critical", 0),
        max_high=overrides.get("max_high", 5),
        require_sbom=overrides.get("require_sbom", True),
        unknown_severity_action=overrides.get("unknown_severity_action", "fail"),
    )
    evidence = module.EvaluationEvidence(
        counts={} if counts is None else counts, sbom_available=sbom
    )
    return module.evaluate_policy(rules, evidence)


def explanation(decision, rule_id):
    return next(rule for rule in decision.rules if rule.rule_id == rule_id)


@pytest.mark.parametrize(
    "severity, rule", [(Severity.CRITICAL, "max_critical"), (Severity.HIGH, "max_high")]
)
@pytest.mark.parametrize(
    "maximum, actual, passes",
    [
        (0, 0, True),
        (0, 1, False),
        (5, 0, True),
        (5, 4, True),
        (5, 5, True),
        (5, 6, False),
    ],
)
def test_threshold_boundaries(severity, rule, maximum, actual, passes):
    decision = evaluate({severity: actual}, **{rule: maximum})
    assert decision.outcome == ("passed" if passes else "failed")
    result = explanation(decision, rule)
    assert (
        result.passed is passes
        and result.actual == actual
        and result.expected == maximum
    )
    assert result.reason
    assert len(decision.rules) == 4


@pytest.mark.parametrize("count", [0, 1])
@pytest.mark.parametrize("action", ["fail", "ignore"])
def test_unknown_severity_is_counted_even_when_ignored(count, action):
    decision = evaluate({Severity.UNKNOWN: count}, unknown_severity_action=action)
    passes = count == 0 or action == "ignore"
    assert decision.outcome == ("passed" if passes else "failed")
    rule = explanation(decision, "unknown_severity_action")
    assert rule.passed is passes and rule.actual == count and rule.expected == action
    assert decision.counts[Severity.UNKNOWN] == count
    if action == "ignore":
        assert "ignored" in rule.reason.lower()


@pytest.mark.parametrize("required", [True, False])
@pytest.mark.parametrize("available", [True, False])
def test_sbom_presence_and_optional_requirement(required, available):
    decision = evaluate(sbom=available, require_sbom=required)
    passes = available or not required
    assert decision.outcome == ("passed" if passes else "failed")
    rule = explanation(decision, "require_sbom")
    assert (
        rule.passed is passes and rule.actual is available and rule.expected is required
    )
    if not required:
        assert "not required" in rule.reason.lower()


def test_all_failures_keep_all_four_explanations():
    decision = evaluate(
        {Severity.CRITICAL: 1, Severity.HIGH: 6, Severity.UNKNOWN: 1}, sbom=False
    )
    assert decision.outcome == "failed"
    assert {rule.rule_id for rule in decision.rules} == {
        "max_critical",
        "max_high",
        "require_sbom",
        "unknown_severity_action",
    }
    assert all(rule.passed is False and rule.reason for rule in decision.rules)


def test_medium_and_low_are_visible_without_threshold_rejection():
    decision = evaluate({Severity.MEDIUM: 300, Severity.LOW: 400})
    assert decision.outcome == "passed"
    assert decision.counts == {
        Severity.CRITICAL: 0,
        Severity.HIGH: 0,
        Severity.MEDIUM: 300,
        Severity.LOW: 400,
        Severity.UNKNOWN: 0,
    }


def test_missing_severities_normalize_to_zero_and_version_is_recorded():
    decision = evaluate()
    assert decision.outcome == "passed"
    assert decision.counts == {
        Severity.CRITICAL: 0,
        Severity.HIGH: 0,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
        Severity.UNKNOWN: 0,
    }
    assert decision.evaluator_version == 1


@pytest.mark.parametrize(
    "counts",
    [
        {"bogus": 1},
        {"high": 1},
        {Severity.HIGH: True},
        {Severity.HIGH: False},
        {Severity.HIGH: "1"},
        {Severity.HIGH: 1.5},
        {Severity.HIGH: -1},
        {Severity.HIGH: None},
        [],
        1,
    ],
)
def test_unusable_counts_raise_safe_invalid_evidence(counts):
    with pytest.raises(ValueError, match="Invalid evaluation evidence"):
        evaluate(counts)


@pytest.mark.parametrize("available", ["true", 1, 0, None])
def test_sbom_evidence_is_boolean(available):
    with pytest.raises(ValueError, match="Invalid evaluation evidence"):
        evaluate(sbom=available)


def test_normalizes_known_string_severity_keys():
    decision = evaluate({"HIGH": 5})
    assert decision.outcome == "passed"
    assert decision.counts[Severity.HIGH] == 5


def test_repeatable_decision_does_not_mutate_or_retain_input_counts():
    counts = {Severity.HIGH: 5}
    first = evaluate(counts)
    second = evaluate(counts)
    assert first == second
    assert counts == {Severity.HIGH: 5}
    counts[Severity.HIGH] = 99
    assert first.counts[Severity.HIGH] == 5
    assert first.model_dump(mode="json")["counts"]["HIGH"] == 5
