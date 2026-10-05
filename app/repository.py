from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.mock_scanner import build_mock_findings
from app.models import Finding, Scan
from app.schemas import (
    Finding as FindingResponse,
)
from app.schemas import (
    FindingPage,
    ScanAccepted,
    ScanHistory,
    ScanRecord,
    ScanSubmission,
    Severity,
)


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
    if session.get(Scan, scan_id) is None:
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
        mock=True,
    )
