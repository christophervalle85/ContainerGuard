"""Store artifact outcomes within the scan completion transaction."""

from uuid import UUID

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.api.sbom_schemas import SbomMetadata
from app.persistence.models import Image, SbomArtifact, Scan
from app.scanning.trivy.sbom import MAX_SBOM_BYTES, ParsedSbom, SbomOutcome, parse_sbom

SBOM_ERROR_MESSAGES = {
    "sbom_timeout": "SBOM generation exceeded its time limit",
    "sbom_unavailable": "SBOM generator is unavailable",
    "sbom_execution_failed": "SBOM generation failed",
    "sbom_output_limit": "SBOM output exceeded its size limit",
    "sbom_invalid_report": "SBOM output could not be validated",
}


def add_sbom_outcome(session: Session, scan_id: UUID, outcome: SbomOutcome) -> None:
    """Flush an outcome; the caller owns commit or rollback."""
    if outcome.artifact is not None:
        artifact = outcome.artifact
        row = SbomArtifact(
            scan_id=scan_id,
            status="available",
            payload=artifact.payload,
            size_bytes=artifact.size_bytes,
            sha256=artifact.sha256,
            format=artifact.format,
            format_version=artifact.format_version,
            scanner_version=artifact.scanner_version,
            pinned_reference=artifact.pinned_reference,
            platform=artifact.platform,
        )
    else:
        if outcome.error_code not in SBOM_ERROR_MESSAGES:
            raise ValueError("Unknown SBOM failure code")
        row = SbomArtifact(
            scan_id=scan_id,
            status="failed",
            error_code=outcome.error_code,
            error_details=SBOM_ERROR_MESSAGES[outcome.error_code],
        )
    session.add(row)
    session.flush()


class ScanNotFound(LookupError):
    pass


class SbomNotReady(RuntimeError):
    pass


class SbomUnavailable(LookupError):
    pass


class SbomIntegrityError(RuntimeError):
    pass


def get_sbom_metadata(session: Session, scan_id: UUID) -> SbomMetadata | None:
    scan = session.get(Scan, scan_id)
    if scan is None:
        return None
    if scan.status in {"queued", "running"}:
        return SbomMetadata(scan_id=scan_id, status="pending")
    artifact = session.scalar(
        select(SbomArtifact).where(SbomArtifact.scan_id == scan_id)
    )
    if artifact is None:
        return SbomMetadata(scan_id=scan_id, status="not_generated")
    return SbomMetadata(
        scan_id=scan_id,
        status=artifact.status,
        format=artifact.format,
        format_version=artifact.format_version,
        scanner_version=artifact.scanner_version,
        pinned_reference=artifact.pinned_reference,
        digest=artifact.pinned_reference.rpartition("@")[2]
        if artifact.pinned_reference
        else None,
        platform=artifact.platform,
        size_bytes=artifact.size_bytes,
        sha256=artifact.sha256,
        created_at=artifact.created_at,
        error_code=artifact.error_code,
        error_details=SBOM_ERROR_MESSAGES.get(artifact.error_code)
        if artifact.error_code
        else None,
    )


def load_verified_sbom(session: Session, scan_id: UUID) -> ParsedSbom:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise ScanNotFound
    if scan.status in {"queued", "running"}:
        raise SbomNotReady
    artifact = session.scalar(
        select(SbomArtifact).where(SbomArtifact.scan_id == scan_id)
    )
    if scan.status != "completed" or artifact is None or artifact.status != "available":
        raise SbomUnavailable

    image = session.get(Image, scan.image_id) if scan.image_id is not None else None
    if image is None or scan.scanner_name != "trivy":
        raise SbomIntegrityError
    reference = f"{image.registry_host}/{image.repository}@{image.digest}"
    if (
        artifact.pinned_reference != reference
        or artifact.platform != image.platform
        or artifact.scanner_version != scan.scanner_version
    ):
        raise SbomIntegrityError

    # Bound transfer even if stored data was altered outside normal constraints.
    bounded_payload = case(
        (
            func.octet_length(SbomArtifact.payload).between(1, MAX_SBOM_BYTES),
            SbomArtifact.payload,
        ),
        else_=None,
    )
    payload = session.scalar(
        select(bounded_payload).where(SbomArtifact.id == artifact.id)
    )
    try:
        parsed = parse_sbom(
            payload,
            pinned_reference=reference,
            platform=image.platform,
            scanner_version=scan.scanner_version,
        )
    except ValueError:
        raise SbomIntegrityError from None
    if (
        parsed.size_bytes != artifact.size_bytes
        or parsed.sha256 != artifact.sha256
        or parsed.format != artifact.format
        or parsed.format_version != artifact.format_version
    ):
        raise SbomIntegrityError
    return parsed
