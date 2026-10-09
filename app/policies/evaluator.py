"""Evaluate fixed policy rules using supplied evidence, without external access."""

from dataclasses import dataclass

from app.api.schemas import Severity
from app.policies.schemas import PolicyDecision, PolicyRules, RuleExplanation

EVALUATOR_VERSION = 1


@dataclass(frozen=True)
class EvaluationEvidence:
    counts: dict[Severity, int]
    sbom_available: bool


def evaluate_policy(rules: PolicyRules, evidence: EvaluationEvidence) -> PolicyDecision:
    if (
        not isinstance(evidence.counts, dict)
        or type(evidence.sbom_available) is not bool
    ):
        raise ValueError("Invalid evaluation evidence")
    counts = dict.fromkeys(Severity, 0)
    for key, count in evidence.counts.items():
        try:
            severity = Severity(key)
        except ValueError, TypeError:
            raise ValueError("Invalid evaluation evidence") from None
        if type(count) is not int or count < 0:
            raise ValueError("Invalid evaluation evidence")
        counts[severity] = count

    explanations = []
    for rule_id, severity, maximum in (
        ("max_critical", Severity.CRITICAL, rules.max_critical),
        ("max_high", Severity.HIGH, rules.max_high),
    ):
        passed = counts[severity] <= maximum
        reason = (
            f"{severity.value} count is within the allowed maximum."
            if passed
            else f"{severity.value} count exceeds the allowed maximum."
        )
        explanations.append(
            RuleExplanation(
                rule_id=rule_id,
                passed=passed,
                actual=counts[severity],
                expected=maximum,
                reason=reason,
            )
        )

    sbom_passed = evidence.sbom_available or not rules.require_sbom
    if not rules.require_sbom:
        sbom_reason = "An SBOM is not required by this policy."
    elif evidence.sbom_available:
        sbom_reason = "The required SBOM is available."
    else:
        sbom_reason = "The required SBOM is unavailable."
    explanations.append(
        RuleExplanation(
            rule_id="require_sbom",
            passed=sbom_passed,
            actual=evidence.sbom_available,
            expected=rules.require_sbom,
            reason=sbom_reason,
        )
    )

    unknown_passed = (
        counts[Severity.UNKNOWN] == 0 or rules.unknown_severity_action == "ignore"
    )
    if rules.unknown_severity_action == "ignore":
        unknown_reason = "UNKNOWN findings are ignored by this policy."
    elif counts[Severity.UNKNOWN] == 0:
        unknown_reason = "No UNKNOWN findings were found."
    else:
        unknown_reason = "UNKNOWN findings are not allowed by this policy."
    explanations.append(
        RuleExplanation(
            rule_id="unknown_severity_action",
            passed=unknown_passed,
            actual=counts[Severity.UNKNOWN],
            expected=rules.unknown_severity_action,
            reason=unknown_reason,
        )
    )

    return PolicyDecision(
        outcome="passed" if all(rule.passed for rule in explanations) else "failed",
        counts=counts,
        rules=explanations,
        evaluator_version=EVALUATOR_VERSION,
    )
