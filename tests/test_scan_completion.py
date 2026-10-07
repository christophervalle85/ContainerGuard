from dataclasses import replace
from importlib import import_module
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.schemas import ScanSubmission
from app.persistence.models import Finding, Image, Scan
from app.scanning.trivy.parser import (
    ParsedScanMetadata,
    load_trivy_report,
    parse_trivy_findings,
)
from tests.database_support import isolated_repository_engine

DIGEST = "sha256:" + "a" * 64
PINNED = f"docker.io/library/alpine@{DIGEST}"
METADATA = ParsedScanMetadata(PINNED, DIGEST, "linux/amd64", "0.75.0")
SUBMISSION = ScanSubmission(image_reference="docker.io/library/alpine:3.20")


def sample_findings():
    fixture = Path(__file__).parent / "fixtures" / "trivy" / "findings.json"
    return parse_trivy_findings(load_trivy_report(fixture.read_text()))


def test_image_identity_is_reused_across_committed_sessions():
    repository = import_module("app.persistence.repository")
    with isolated_repository_engine() as engine:
        with Session(engine) as session, session.begin():
            first = repository._get_or_create_trivy_image(session, PINNED, METADATA)
        with Session(engine) as session, session.begin():
            second = repository._get_or_create_trivy_image(session, PINNED, METADATA)
        assert first == second
        with Session(engine) as session:
            assert session.scalar(select(func.count()).select_from(Image)) == 1
            image = session.get(Image, first)
            assert (
                image.registry_host,
                image.repository,
                image.digest,
                image.platform,
            ) == ("docker.io", "library/alpine", DIGEST, "linux/amd64")


@pytest.mark.parametrize(
    "metadata",
    [
        replace(METADATA, reported_digest="sha256:" + "b" * 64),
        replace(METADATA, platform="linux/arm64"),
    ],
)
def test_image_identity_rejects_report_mismatches(metadata):
    repository = import_module("app.persistence.repository")
    with isolated_repository_engine() as engine:
        with Session(engine) as session, session.begin():
            with pytest.raises(ValueError):
                repository._get_or_create_trivy_image(session, PINNED, metadata)
        with Session(engine) as session:
            assert session.scalar(select(func.count()).select_from(Image)) == 0


@pytest.mark.parametrize("with_findings", [True, False])
def test_completion_commits_image_metadata_and_all_findings(with_findings):
    repository = import_module("app.persistence.repository")
    findings = sample_findings() if with_findings else []
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.start_trivy_scan(session, SUBMISSION)
            repository.complete_trivy_scan(session, scan_id, PINNED, METADATA, findings)
            assert not session.in_transaction()
        with Session(engine) as session:
            scan = session.get(Scan, scan_id)
            assert scan.status == "completed"
            assert scan.submitted_reference == SUBMISSION.image_reference
            assert scan.completed_at >= scan.started_at
            assert scan.scanner_name == "trivy"
            assert scan.scanner_version == "0.75.0"
            assert scan.scanner_database_metadata is None
            assert scan.error_details is None
            image = session.get(Image, scan.image_id)
            assert image.digest == DIGEST
            assert image.platform == "linux/amd64"
            rows = session.scalars(
                select(Finding)
                .where(Finding.scan_id == scan_id)
                .order_by(Finding.occurrence_order)
            ).all()
            assert len(rows) == len(findings)
            for stored, expected in zip(rows, findings, strict=True):
                assert (
                    stored.vulnerability_id,
                    stored.package_name,
                    stored.package_type,
                    stored.target,
                    stored.installed_version,
                    stored.fixed_version,
                    stored.severity,
                    stored.title,
                    stored.occurrence_order,
                ) == (
                    expected.vulnerability_id,
                    expected.package_name,
                    expected.package_type,
                    expected.target,
                    expected.installed_version,
                    expected.fixed_version,
                    expected.severity.value,
                    expected.title,
                    expected.occurrence_order,
                )


def test_two_completed_scans_share_image_identity_but_keep_separate_findings():
    repository = import_module("app.persistence.repository")
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            first = repository.start_trivy_scan(session, SUBMISSION)
            repository.complete_trivy_scan(
                session, first, PINNED, METADATA, sample_findings()
            )
            second = repository.start_trivy_scan(session, SUBMISSION)
            repository.complete_trivy_scan(
                session, second, PINNED, METADATA, sample_findings()
            )
        with Session(engine) as session:
            assert (
                session.get(Scan, first).image_id == session.get(Scan, second).image_id
            )
            assert session.scalar(select(func.count()).select_from(Image)) == 1
            for scan_id in (first, second):
                assert (
                    session.scalar(
                        select(func.count())
                        .select_from(Finding)
                        .where(Finding.scan_id == scan_id)
                    )
                    == 3
                )


def test_failed_finding_insert_rolls_back_completion_but_preserves_attempt():
    repository = import_module("app.persistence.repository")
    sample = sample_findings()[0]
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.start_trivy_scan(session, SUBMISSION)
            with pytest.raises(IntegrityError):
                repository.complete_trivy_scan(
                    session, scan_id, PINNED, METADATA, [sample, sample]
                )
            assert not session.in_transaction()
        with Session(engine) as session:
            scan = session.get(Scan, scan_id)
            assert scan.status == "running"
            assert scan.image_id is None
            assert scan.completed_at is None
            assert scan.scanner_version is None
            assert session.scalar(select(func.count()).select_from(Finding)) == 0
            assert session.scalar(select(func.count()).select_from(Image)) == 0


def test_unknown_scan_cannot_create_orphan_image_or_findings():
    repository = import_module("app.persistence.repository")
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            with pytest.raises(ValueError, match="running Trivy scan"):
                repository.complete_trivy_scan(
                    session, uuid4(), PINNED, METADATA, sample_findings()
                )
        with Session(engine) as session:
            assert session.scalar(select(func.count()).select_from(Image)) == 0
            assert session.scalar(select(func.count()).select_from(Finding)) == 0


def test_completed_scan_cannot_be_completed_again():
    repository = import_module("app.persistence.repository")
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.start_trivy_scan(session, SUBMISSION)
            repository.complete_trivy_scan(
                session, scan_id, PINNED, METADATA, sample_findings()
            )
            with pytest.raises(ValueError, match="running Trivy scan"):
                repository.complete_trivy_scan(session, scan_id, PINNED, METADATA, [])
        with Session(engine) as session:
            assert session.get(Scan, scan_id).status == "completed"
            assert session.scalar(select(func.count()).select_from(Finding)) == 3


def test_completion_persists_available_database_metadata():
    repository = import_module("app.persistence.repository")
    database_metadata = {"Version": 2, "UpdatedAt": "2026-10-06T13:07:05Z"}
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.start_trivy_scan(session, SUBMISSION)
            repository.complete_trivy_scan(
                session,
                scan_id,
                PINNED,
                METADATA,
                [],
                scanner_database_metadata=database_metadata,
            )
        with Session(engine) as session:
            stored = session.get(Scan, scan_id)
            assert stored.status == "completed"
            assert stored.scanner_database_metadata == database_metadata
