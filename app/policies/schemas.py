"""Strict policy inputs and immutable version records."""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    StringConstraints,
)

from app.api.schemas import Severity

Threshold = Annotated[int, Field(strict=True, ge=0, le=2147483647)]
PolicyName = Annotated[
    str,
    StringConstraints(strict=True, strip_whitespace=True, min_length=1, max_length=100),
]


class PolicyRules(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    max_critical: Threshold
    max_high: Threshold
    require_sbom: Annotated[bool, Field(strict=True)]
    unknown_severity_action: Literal["fail", "ignore"]


class PolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: PolicyName
    rules: PolicyRules


class PolicyVersionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rules: PolicyRules


class PolicyRecord(BaseModel):
    policy_id: UUID
    name: str
    created_at: datetime


class PolicyVersionRecord(BaseModel):
    policy_id: UUID
    policy_version_id: UUID
    version_number: int
    rules: PolicyRules
    created_at: datetime


class PolicyPage(BaseModel):
    items: list[PolicyRecord]
    total: int
    limit: int
    offset: int


class PolicyVersionPage(BaseModel):
    items: list[PolicyVersionRecord]
    total: int
    limit: int
    offset: int


class RuleExplanation(BaseModel):
    model_config = ConfigDict(frozen=True)
    rule_id: Literal[
        "max_critical", "max_high", "require_sbom", "unknown_severity_action"
    ]
    passed: bool
    actual: StrictInt | StrictBool | StrictStr
    expected: StrictInt | StrictBool | StrictStr
    reason: str


class PolicyDecision(BaseModel):
    model_config = ConfigDict(frozen=True)
    outcome: Literal["passed", "failed"]
    counts: dict[Severity, int]
    rules: list[RuleExplanation] = Field(min_length=4, max_length=4)
    evaluator_version: Literal[1] = 1


class EvaluationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy_version_id: UUID


class EvaluationRecord(BaseModel):
    evaluation_id: UUID
    scan_id: UUID
    policy_id: UUID
    policy_version_id: UUID
    version_number: int
    rule_snapshot: PolicyRules
    evaluator_version: int
    outcome: Literal["passed", "failed", "error"]
    counts: dict[Severity, int]
    rules: list[RuleExplanation]
    created_at: datetime
    error_code: Literal["invalid_evidence"] | None = None
    error_details: str | None = None


class EvaluationPage(BaseModel):
    items: list[EvaluationRecord]
    total: int
    limit: int
    offset: int
