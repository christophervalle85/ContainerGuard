"""Collect real scanner results before a short persistence transaction."""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.schemas import ScanSubmission
from app.persistence import repository
from app.registries.docker_hub import RegistryRequestError
from app.registries.resolver import resolve_docker_tag
from app.scanning.trivy.parser import (
    ParsedFinding,
    ParsedScanMetadata,
    load_trivy_report,
    parse_trivy_findings,
    parse_trivy_metadata,
)
from app.scanning.trivy.process_runner import ProcessExecutionError
from app.scanning.trivy.runner import (
    read_trivy_database_metadata,
    run_trivy_scan,
)


class ScanWorkflowError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(repository.SCAN_FAILURE_MESSAGES[code])


@dataclass(frozen=True)
class TrivyResult:
    pinned_reference: str
    metadata: ParsedScanMetadata
    findings: list[ParsedFinding]
    database_metadata: dict | None = None


def collect_trivy_result(submission: ScanSubmission) -> TrivyResult:
    try:
        pinned_reference = resolve_docker_tag(submission.image_reference)
    except RegistryRequestError, ValueError:
        raise ScanWorkflowError("resolution_failed") from None

    try:
        raw_report = run_trivy_scan(pinned_reference)
    except ProcessExecutionError as error:
        code = {
            "timeout": "scanner_timeout",
            "unavailable": "scanner_unavailable",
            "execution_failed": "scanner_failed",
            "output_limit": "output_limit",
            "invalid_output": "invalid_report",
        }[error.code]
        raise ScanWorkflowError(code) from None

    try:
        report = load_trivy_report(raw_report)
        metadata = parse_trivy_metadata(report)
        findings = parse_trivy_findings(report)
        if metadata.reported_digest != pinned_reference.rpartition("@")[2]:
            raise ValueError("Report digest does not match the pinned reference")
    except ValueError:
        raise ScanWorkflowError("invalid_report") from None

    database_metadata = read_trivy_database_metadata(metadata.scanner_version)
    return TrivyResult(pinned_reference, metadata, findings, database_metadata)


def perform_trivy_scan(
    session: Session,
    submission: ScanSubmission,
) -> UUID:
    scan_id = repository.start_trivy_scan(session, submission)

    try:
        result = collect_trivy_result(submission)
        repository.complete_trivy_scan(
            session,
            scan_id,
            result.pinned_reference,
            result.metadata,
            result.findings,
            scanner_database_metadata=result.database_metadata,
        )
    except ScanWorkflowError as error:
        repository.fail_trivy_scan(session, scan_id, error.code)
    except ValueError:
        repository.fail_trivy_scan(session, scan_id, "invalid_report")
    except SQLAlchemyError:
        repository.fail_trivy_scan(session, scan_id, "persistence_failed")

    return scan_id
