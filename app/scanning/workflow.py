"""Collect real scanner results before a short persistence transaction."""

import logging
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
from app.scanning.trivy.sbom import SbomOutcome
from app.scanning.trivy.sbom_runner import collect_sbom

logger = logging.getLogger(__name__)


class ScanWorkflowError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool = False) -> None:
        self.code = code
        self.retryable = retryable
        super().__init__(repository.SCAN_FAILURE_MESSAGES[code])


@dataclass(frozen=True)
class TrivyResult:
    pinned_reference: str
    metadata: ParsedScanMetadata
    findings: list[ParsedFinding]
    database_metadata: dict | None = None
    sbom_outcome: SbomOutcome | None = None


def collect_trivy_result(submission: ScanSubmission) -> TrivyResult:
    try:
        pinned_reference = resolve_docker_tag(submission.image_reference)
    except RegistryRequestError as error:
        raise ScanWorkflowError(
            "resolution_failed",
            retryable=error.code in {"rate_limited", "unavailable"},
        ) from None
    except ValueError:
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
        raise ScanWorkflowError(
            code,
            retryable=error.code == "timeout",
        ) from None

    try:
        report = load_trivy_report(raw_report)
        metadata = parse_trivy_metadata(report)
        findings = parse_trivy_findings(report)
        if metadata.reported_digest != pinned_reference.rpartition("@")[2]:
            raise ValueError("Report digest does not match the pinned reference")
    except ValueError:
        raise ScanWorkflowError("invalid_report") from None

    database_metadata = read_trivy_database_metadata(metadata.scanner_version)
    sbom_outcome = collect_sbom(
        pinned_reference,
        platform=metadata.platform,
        scanner_version=metadata.scanner_version,
    )
    return TrivyResult(
        pinned_reference, metadata, findings, database_metadata, sbom_outcome
    )


def perform_trivy_scan(
    session: Session,
    submission: ScanSubmission,
) -> UUID:
    scan_id = repository.start_trivy_scan(session, submission)
    logger.info("scan_started", extra={"scan_id": str(scan_id)})
    return _finish_running_trivy_scan(session, scan_id, submission)


def _finish_running_trivy_scan(
    session: Session,
    scan_id: UUID,
    submission: ScanSubmission,
    *,
    allow_retry: bool = False,
) -> UUID:
    try:
        result = collect_trivy_result(submission)
        repository.complete_trivy_scan(
            session,
            scan_id,
            result.pinned_reference,
            result.metadata,
            result.findings,
            scanner_database_metadata=result.database_metadata,
            sbom_outcome=result.sbom_outcome,
        )
        if result.sbom_outcome is not None:
            if result.sbom_outcome.error_code is None:
                logger.info("sbom_available", extra={"scan_id": str(scan_id)})
            else:
                logger.warning(
                    "sbom_failed",
                    extra={
                        "scan_id": str(scan_id),
                        "error_code": result.sbom_outcome.error_code,
                    },
                )
        logger.info("scan_completed", extra={"scan_id": str(scan_id)})
    except ScanWorkflowError as error:
        if error.retryable and allow_retry:
            repository.requeue_trivy_scan(session, scan_id, error.code)
            logger.warning(
                "scan_retry_queued",
                extra={"scan_id": str(scan_id), "error_code": error.code},
            )
            raise
        repository.fail_trivy_scan(session, scan_id, error.code)
        logger.warning(
            "scan_failed", extra={"scan_id": str(scan_id), "error_code": error.code}
        )
    except ValueError:
        repository.fail_trivy_scan(session, scan_id, "invalid_report")
        logger.warning(
            "scan_failed",
            extra={"scan_id": str(scan_id), "error_code": "invalid_report"},
        )
    except SQLAlchemyError:
        repository.fail_trivy_scan(session, scan_id, "persistence_failed")
        logger.warning(
            "scan_failed",
            extra={"scan_id": str(scan_id), "error_code": "persistence_failed"},
        )

    return scan_id


def process_queued_trivy_scan(
    session: Session,
    scan_id: UUID,
    *,
    allow_retry: bool = False,
) -> UUID:
    submission = repository.claim_queued_trivy_scan(session, scan_id)

    if submission is None:
        logger.info("scan_claim_skipped", extra={"scan_id": str(scan_id)})
        return scan_id

    logger.info("scan_started", extra={"scan_id": str(scan_id)})
    return _finish_running_trivy_scan(
        session,
        scan_id,
        submission,
        allow_retry=allow_retry,
    )
