from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.orm import Session

from app.api.schemas import (
    Finding as FindingResponse,
)
from app.api.schemas import (
    FindingPage,
    ScanAccepted,
    ScanHistory,
    ScanRecord,
    ScanSubmission,
    Severity,
)
from app.persistence.models import Finding, Image, Scan
from app.scanning.mock_scanner import build_mock_findings
from app.scanning.trivy.parser import ParsedFinding, ParsedScanMetadata
from app.scanning.trivy.runner import build_trivy_command

SCAN_FAILURE_MESSAGES = {
    "resolution_failed": "Image reference could not be resolved",
    "scanner_timeout": "Scanner exceeded its execution deadline",
    "scanner_unavailable": "Scanner executable could not be started",
    "scanner_failed": "Scanner command failed",
    "output_limit": "Scanner exceeded its output limit",
    "invalid_report": "Scanner returned an invalid or mismatched report",
    "persistence_failed": "Scan results could not be saved",
}


def _build_scan_records(submission: ScanSubmission) -> tuple[Scan, list[Finding]]:
    now = datetime.now(UTC)
    scan = Scan(
        id=uuid4(),
        submitted_reference=submission.image_reference,
        status="completed",
        created_at=now,
        completed_at=now,
    )
    findings = [
        Finding(
            scan_id=scan.id,
            vulnerability_id=sample.vulnerability_id,
            package_name=sample.package_name,
            package_type="mock",
            target="fictional/sample",
            installed_version=sample.installed_version,
            fixed_version=sample.fixed_version,
            severity=sample.severity.value,
            title=sample.title,
            occurrence_order=position,
        )
        for position, sample in enumerate(build_mock_findings())
    ]
    return scan, findings


def create_scan(session: Session, submission: ScanSubmission) -> ScanAccepted:
    scan, findings = _build_scan_records(submission)
    scan_id = scan.id

    with session.begin():
        session.add(scan)
        session.flush()
        session.add_all(findings)

    return ScanAccepted(
        scan_id=scan_id,
        status="completed",
        status_url=f"/api/v1/scans/{scan_id}",
    )


def get_scan(session: Session, scan_id: UUID) -> ScanRecord | None:
    scan = session.get(Scan, scan_id)

    if scan is None:
        return None

    return ScanRecord(
        scan_id=scan.id,
        image_reference=scan.submitted_reference,
        status=scan.status,
    )


def get_scan_history(session: Session, limit: int, offset: int) -> ScanHistory:
    total = session.scalar(select(func.count()).select_from(Scan))

    statement = (
        select(Scan)
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(limit)
        .offset(offset)
    )
    scans = session.scalars(statement).all()

    return ScanHistory(
        items=[
            ScanRecord(
                scan_id=scan.id,
                image_reference=scan.submitted_reference,
                status=scan.status,
            )
            for scan in scans
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


def get_scan_findings(
    session: Session,
    scan_id: UUID,
    limit: int,
    offset: int,
    severity: Severity | None = None,
) -> FindingPage | None:
    scan = session.get(Scan, scan_id)
    if scan is None:
        return None

    conditions = [Finding.scan_id == scan_id]
    if severity is not None:
        conditions.append(Finding.severity == severity.value)

    total = session.scalar(select(func.count()).select_from(Finding).where(*conditions))

    statement = (
        select(Finding)
        .where(*conditions)
        .order_by(Finding.occurrence_order, Finding.id)
        .limit(limit)
        .offset(offset)
    )
    findings = session.scalars(statement).all()

    return FindingPage(
        items=[
            FindingResponse(
                vulnerability_id=finding.vulnerability_id,
                package_name=finding.package_name,
                installed_version=finding.installed_version,
                fixed_version=finding.fixed_version,
                severity=finding.severity,
                title=finding.title,
            )
            for finding in findings
        ],
        total=total,
        limit=limit,
        offset=offset,
        mock=scan.scanner_name is None,
    )


def create_queued_trivy_scan(session: Session, submission: ScanSubmission) -> UUID:
    scan_id = uuid4()

    scan = Scan(
        id=scan_id,
        submitted_reference=submission.image_reference,
        status="queued",
        created_at=datetime.now(UTC),
        scanner_name="trivy",
    )

    with session.begin():
        session.add(scan)

    return scan_id


def claim_queued_trivy_scan(session: Session, scan_id: UUID) -> ScanSubmission | None:
    with session.begin():
        scan = session.scalar(select(Scan).where(Scan.id == scan_id).with_for_update())

        if scan is None:
            raise ValueError("Scan does not exist")

        if scan.scanner_name != "trivy":
            raise ValueError("Scan is not a Trivy scan")

        if scan.status != "queued":
            return None

        submission = ScanSubmission(image_reference=scan.submitted_reference)
        scan.status = "running"
        scan.started_at = datetime.now(UTC)

    return submission


def start_trivy_scan(session: Session, submission: ScanSubmission) -> UUID:
    now = datetime.now(UTC)
    scan_id = uuid4()

    scan = Scan(
        id=scan_id,
        submitted_reference=submission.image_reference,
        status="running",
        created_at=now,
        started_at=now,
        scanner_name="trivy",
    )

    with session.begin():
        session.add(scan)

    return scan_id


def _get_or_create_trivy_image(
    session: Session,
    pinned_reference: str,
    metadata: ParsedScanMetadata,
) -> UUID:
    reference = build_trivy_command(pinned_reference)[-1]
    repository_reference, digest = reference.rsplit("@", 1)
    registry, repository = repository_reference.split("/", 1)
    if metadata.reported_digest != digest or metadata.platform != "linux/amd64":
        raise ValueError("Scanner report does not match the resolved image")

    statement = (
        postgresql_insert(Image.__table__)
        .values(
            id=uuid4(),
            registry=registry,
            repository=repository,
            digest=digest,
            platform=metadata.platform,
        )
        .on_conflict_do_nothing(constraint="uq_images_identity")
        .returning(Image.id)
    )
    image_id = session.scalar(statement)
    if image_id is not None:
        return image_id
    return session.execute(
        select(Image.id).where(
            Image.registry_host == registry,
            Image.repository == repository,
            Image.digest == digest,
            Image.platform == metadata.platform,
        )
    ).scalar_one()


def _build_trivy_finding_records(
    scan_id: UUID, findings: list[ParsedFinding]
) -> list[Finding]:
    return [
        Finding(
            scan_id=scan_id,
            vulnerability_id=finding.vulnerability_id,
            package_name=finding.package_name,
            package_type=finding.package_type,
            target=finding.target,
            installed_version=finding.installed_version,
            fixed_version=finding.fixed_version,
            severity=finding.severity.value,
            title=finding.title,
            occurrence_order=finding.occurrence_order,
        )
        for finding in findings
    ]


def complete_trivy_scan(
    session: Session,
    scan_id: UUID,
    pinned_reference: str,
    metadata: ParsedScanMetadata,
    findings: list[ParsedFinding],
    scanner_database_metadata: dict | None = None,
) -> None:
    with session.begin():
        scan = session.scalar(select(Scan).where(Scan.id == scan_id).with_for_update())

        if scan is None or scan.status != "running" or scan.scanner_name != "trivy":
            raise ValueError("Expected a running Trivy scan")

        scan.image_id = _get_or_create_trivy_image(session, pinned_reference, metadata)
        session.add_all(_build_trivy_finding_records(scan_id, findings))

        scan.scanner_version = metadata.scanner_version
        scan.scanner_database_metadata = scanner_database_metadata
        scan.completed_at = datetime.now(UTC)
        scan.error_details = None
        scan.status = "completed"


def fail_trivy_scan(
    session: Session,
    scan_id: UUID,
    error_code: str,
) -> None:
    message = SCAN_FAILURE_MESSAGES.get(error_code)
    if message is None:
        raise ValueError("Unknown scan error code")

    with session.begin():
        scan = session.scalar(select(Scan).where(Scan.id == scan_id).with_for_update())

        if scan is None or scan.status != "running" or scan.scanner_name != "trivy":
            raise ValueError("Expected a running Trivy scan")

        scan.error_details = f"{error_code}: {message}"
        scan.completed_at = datetime.now(UTC)
        scan.status = "failed"


def fail_queued_scan(session: Session, scan_id: UUID) -> None:
    with session.begin():
        scan = session.scalar(
            select(Scan)
            .where(Scan.id == scan_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if scan is None:
            raise ValueError("Scan does not exist")
        if scan.status != "queued":
            return
        if scan.scanner_name != "trivy":
            raise ValueError("Scan is not a Trivy scan")
        scan.status = "failed"
        scan.completed_at = datetime.now(UTC)
        scan.error_details = (
            "enqueue_failed: Scan could not be submitted to the worker queue"
        )


def requeue_trivy_scan(session: Session, scan_id: UUID, error_code: str) -> None:
    message = SCAN_FAILURE_MESSAGES.get(error_code)
    if message is None:
        raise ValueError("Unknown scan error code")

    with session.begin():
        scan = session.scalar(
            select(Scan)
            .where(Scan.id == scan_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )

        if scan is None or scan.status != "running" or scan.scanner_name != "trivy":
            raise ValueError("Expected a running Trivy scan")

        scan.status = "queued"
        scan.started_at = None
        scan.completed_at = None
        scan.error_details = f"{error_code}: {message}"


def prepare_scan_recovery(
    session: Session, scan_id: UUID, *, workers_stopped: bool = False
) -> None:
    if not workers_stopped:
        raise ValueError("Stop all scan workers before recovery")

    with session.begin():
        scan = session.scalar(
            select(Scan)
            .where(Scan.id == scan_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )

        if (
            scan is None
            or scan.status not in {"queued", "running"}
            or scan.scanner_name != "trivy"
        ):
            raise ValueError("Expected a queued or running Trivy scan")

        finding_count = session.scalar(
            select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id)
        )
        if scan.image_id is not None or finding_count:
            raise ValueError("Scan already has saved results")

        scan.status = "queued"
        scan.started_at = None
        scan.completed_at = None
        scan.error_details = "recovery_requested: Scan was manually prepared for retry"
