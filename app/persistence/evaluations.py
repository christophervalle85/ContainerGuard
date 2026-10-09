"""Evaluate fixed scan evidence and preserve one result per policy version."""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.api.schemas import Severity
from app.persistence import artifacts
from app.persistence.models import Evaluation, Finding, Image, PolicyVersion, Scan
from app.policies.evaluator import (
    EVALUATOR_VERSION,
    EvaluationEvidence,
    evaluate_policy,
)
from app.policies.schemas import EvaluationPage, EvaluationRecord, PolicyRules
from app.scanning.trivy.runner import build_trivy_command

_INVALID_EVIDENCE_MESSAGE = "Saved scan evidence could not be verified"


class ScanNotFound(LookupError):
    pass


class PolicyVersionNotFound(LookupError):
    pass


class IneligibleScan(RuntimeError):
    pass


def _result_query():
    return select(
        Evaluation, PolicyVersion.policy_id, PolicyVersion.version_number
    ).join(PolicyVersion, PolicyVersion.id == Evaluation.policy_version_id)


def _record(result) -> EvaluationRecord:
    row, policy_id, number = result
    return EvaluationRecord(
        evaluation_id=row.id,
        scan_id=row.scan_id,
        policy_id=policy_id,
        policy_version_id=row.policy_version_id,
        version_number=number,
        rule_snapshot=row.rule_snapshot,
        evaluator_version=row.evaluator_version,
        outcome=row.outcome,
        counts=row.counts,
        rules=row.rules,
        created_at=row.created_at,
        error_code=row.error_code,
        error_details=row.error_details,
    )


def evaluate_scan(
    session: Session, scan_id: UUID, policy_version_id: UUID
) -> EvaluationRecord:
    with session.begin():
        pair = (
            Evaluation.scan_id == scan_id,
            Evaluation.policy_version_id == policy_version_id,
        )
        saved = session.execute(_result_query().where(*pair)).first()
        if saved is not None:
            return _record(saved)

        scan = session.get(Scan, scan_id)
        if scan is None:
            raise ScanNotFound
        version = session.get(PolicyVersion, policy_version_id)
        if version is None:
            raise PolicyVersionNotFound
        if (
            scan.status != "completed"
            or scan.scanner_name != "trivy"
            or scan.image_id is None
            or session.get(Image, scan.image_id) is None
        ):
            raise IneligibleScan
        image = session.get(Image, scan.image_id)
        rules = PolicyRules(
            max_critical=version.max_critical,
            max_high=version.max_high,
            require_sbom=version.require_sbom,
            unknown_severity_action=version.unknown_severity_action,
        )
        counts = dict.fromkeys(Severity, 0)
        decision = None
        try:
            groups = session.execute(
                select(Finding.severity, func.count())
                .where(Finding.scan_id == scan_id)
                .group_by(Finding.severity)
            )
            for severity, count in groups:
                counts[Severity(severity)] = count
            # Scan identity must be usable even when an SBOM is optional or absent.
            build_trivy_command(
                f"{image.registry_host}/{image.repository}@{image.digest}"
            )
            if (
                image.platform != "linux/amd64"
                or not isinstance(scan.scanner_version, str)
                or not scan.scanner_version.strip()
            ):
                raise ValueError("Invalid scan identity")
            sbom_available = False
            try:
                artifacts.load_verified_sbom(session, scan_id)
                sbom_available = True
            except artifacts.SbomUnavailable:
                pass
            decision = evaluate_policy(
                rules, EvaluationEvidence(counts, sbom_available)
            )
        except artifacts.SbomIntegrityError, ValueError:
            # Fixed public details; never persist scanner or database diagnostics.
            pass

        values = dict(
            scan_id=scan_id,
            policy_version_id=policy_version_id,
            evaluator_version=EVALUATOR_VERSION,
            rule_snapshot=rules.model_dump(mode="json"),
            outcome=decision.outcome if decision is not None else "error",
            counts={severity.value: count for severity, count in counts.items()},
            rules=[rule.model_dump(mode="json") for rule in decision.rules]
            if decision is not None
            else [],
            error_code=None if decision is not None else "invalid_evidence",
            error_details=None if decision is not None else _INVALID_EVIDENCE_MESSAGE,
        )
        session.execute(
            insert(Evaluation)
            .values(**values)
            .on_conflict_do_nothing(
                index_elements=[Evaluation.scan_id, Evaluation.policy_version_id]
            )
        )
        winner = session.execute(_result_query().where(*pair)).one()
        return _record(winner)


def list_evaluations(
    session: Session, scan_id: UUID, *, limit: int, offset: int
) -> EvaluationPage:
    if session.get(Scan, scan_id) is None:
        raise ScanNotFound
    total = session.scalar(
        select(func.count())
        .select_from(Evaluation)
        .where(Evaluation.scan_id == scan_id)
    )
    rows = session.execute(
        _result_query()
        .where(Evaluation.scan_id == scan_id)
        .order_by(Evaluation.created_at.desc(), Evaluation.id.desc())
        .limit(limit)
        .offset(offset)
    )
    return EvaluationPage(
        items=[_record(row) for row in rows], total=total, limit=limit, offset=offset
    )
