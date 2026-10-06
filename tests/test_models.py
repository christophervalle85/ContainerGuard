from collections.abc import Iterator
from importlib import import_module
from types import ModuleType
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from tests.database_support import isolated_model_connection

IMAGE_IDENTITY = {
    "registry_host": "docker.io",
    "repository": "library/alpine",
    "digest": "sha256:" + "a" * 64,
    "platform": "linux/amd64",
}


def test_image_identity_survives_a_new_session() -> None:
    models = import_module("app.models")
    with isolated_model_connection() as connection:
        models.Base.metadata.create_all(connection)
        with Session(connection, join_transaction_mode="create_savepoint") as session:
            image = models.Image(**IMAGE_IDENTITY)
            session.add(image)
            session.flush()
            image_id = image.id
            assert isinstance(image_id, UUID)
            session.commit()

        with Session(connection, join_transaction_mode="create_savepoint") as session:
            stored = session.get(models.Image, image_id)
            assert stored is not None
            for field, expected in IMAGE_IDENTITY.items():
                assert getattr(stored, field) == expected


def test_duplicate_image_identity_is_rejected() -> None:
    models = import_module("app.models")
    with isolated_model_connection() as connection:
        models.Base.metadata.create_all(connection)
        with Session(connection, join_transaction_mode="create_savepoint") as session:
            session.add(models.Image(**IMAGE_IDENTITY))
            session.flush()
            session.add(models.Image(**IMAGE_IDENTITY))
            with pytest.raises(IntegrityError):
                session.flush()


def test_same_digest_can_have_a_different_platform() -> None:
    models = import_module("app.models")
    with isolated_model_connection() as connection:
        models.Base.metadata.create_all(connection)
        with Session(connection, join_transaction_mode="create_savepoint") as session:
            first = models.Image(**IMAGE_IDENTITY)
            second = models.Image(**(IMAGE_IDENTITY | {"platform": "linux/arm64"}))
            session.add_all([first, second])
            session.flush()
            assert first.id != second.id


def test_failed_unresolved_scan_can_be_stored_without_image() -> None:
    models = import_module("app.models")
    scan_class = models.Scan
    with isolated_model_connection() as connection:
        models.Base.metadata.create_all(connection)
        with Session(connection, join_transaction_mode="create_savepoint") as session:
            scan = scan_class(
                submitted_reference="docker.io/library/missing:example",
                status="failed",
                error_details="Image could not be resolved",
                scanner_name="fixture",
                scanner_version="1.0",
                scanner_database_metadata={"source": "test-fixture"},
            )
            session.add(scan)
            session.flush()
            scan_id = scan.id
            assert isinstance(scan_id, UUID)
            session.commit()

        with Session(connection, join_transaction_mode="create_savepoint") as session:
            stored = session.get(scan_class, scan_id)
            assert stored is not None
            assert stored.image_id is None
            assert stored.submitted_reference == "docker.io/library/missing:example"
            assert stored.status == "failed"
            assert stored.error_details == "Image could not be resolved"
            assert stored.created_at.utcoffset().total_seconds() == 0
            assert stored.started_at is None
            assert stored.completed_at is None
            assert stored.scanner_name == "fixture"
            assert stored.scanner_version == "1.0"
            assert stored.scanner_database_metadata == {"source": "test-fixture"}


def test_scan_can_reference_an_existing_image() -> None:
    models = import_module("app.models")
    scan_class = models.Scan
    with isolated_model_connection() as connection:
        models.Base.metadata.create_all(connection)
        with Session(connection, join_transaction_mode="create_savepoint") as session:
            image = models.Image(**IMAGE_IDENTITY)
            session.add(image)
            session.flush()
            scan = scan_class(
                submitted_reference="docker.io/library/alpine:3.20", image_id=image.id
            )
            session.add(scan)
            session.flush()
            scan_id, image_id = scan.id, image.id
            session.commit()

        with Session(connection, join_transaction_mode="create_savepoint") as session:
            stored = session.get(scan_class, scan_id)
            assert stored.image_id == image_id
            assert stored.status == "queued"


def test_scan_rejects_nonexistent_image_id() -> None:
    models = import_module("app.models")
    scan_class = models.Scan
    with isolated_model_connection() as connection:
        models.Base.metadata.create_all(connection)
        with Session(connection, join_transaction_mode="create_savepoint") as session:
            session.add(
                scan_class(
                    submitted_reference="docker.io/library/alpine:3.20",
                    image_id=uuid4(),
                )
            )
            with pytest.raises(IntegrityError):
                session.flush()


def test_scan_rejects_invalid_status() -> None:
    models = import_module("app.models")
    scan_class = models.Scan
    with isolated_model_connection() as connection:
        models.Base.metadata.create_all(connection)
        with Session(connection, join_transaction_mode="create_savepoint") as session:
            session.add(
                scan_class(
                    submitted_reference="docker.io/library/alpine:3.20",
                    status="invalid",
                )
            )
            with pytest.raises(IntegrityError):
                session.flush()


FINDING_DATA = {
    "vulnerability_id": "MOCK-001",
    "package_name": "demo-library",
    "package_type": "fixture",
    "target": "/fictional/package-list",
    "installed_version": "1.0",
    "fixed_version": None,
    "severity": "UNKNOWN",
    "title": "Fictional finding",
    "occurrence_order": 0,
}


@pytest.fixture
def finding_session() -> Iterator[tuple[ModuleType, Session, object]]:
    models = import_module("app.models")
    assert hasattr(models, "Finding"), "The Finding model has not been implemented"
    with isolated_model_connection() as connection:
        models.Base.metadata.create_all(connection)
        with Session(connection, join_transaction_mode="create_savepoint") as session:
            scan = models.Scan(submitted_reference="docker.io/library/alpine:3.20")
            session.add(scan)
            session.flush()
            yield models, session, scan


def test_finding_preserves_unknown_severity_and_missing_fix(finding_session) -> None:
    models, session, scan = finding_session
    finding = models.Finding(scan_id=scan.id, **FINDING_DATA)
    session.add(finding)
    session.flush()
    finding_id = finding.id
    assert isinstance(finding_id, UUID)
    session.commit()
    session.expire_all()
    stored = session.get(models.Finding, finding_id)
    assert stored.scan_id == scan.id
    for field, expected in FINDING_DATA.items():
        assert getattr(stored, field) == expected


@pytest.mark.parametrize(
    "difference",
    [
        {"package_name": "another-library"},
        {"package_type": "another-type"},
        {"target": "/another/fictional-target"},
        {"installed_version": "2.0"},
    ],
    ids=["package", "package-type", "target", "installed-version"],
)
def test_same_vulnerability_can_have_distinct_occurrences(
    finding_session, difference: dict
) -> None:
    models, session, scan = finding_session
    first = models.Finding(scan_id=scan.id, **FINDING_DATA)
    second = models.Finding(
        scan_id=scan.id, **(FINDING_DATA | difference | {"occurrence_order": 1})
    )
    session.add_all([first, second])
    session.flush()
    assert first.id != second.id


def test_duplicate_finding_occurrence_is_rejected(finding_session) -> None:
    models, session, scan = finding_session
    session.add(models.Finding(scan_id=scan.id, **FINDING_DATA))
    session.flush()
    session.add(models.Finding(scan_id=scan.id, **FINDING_DATA))
    with pytest.raises(IntegrityError):
        session.flush()


def test_finding_rejects_nonexistent_scan(finding_session) -> None:
    models, session, scan = finding_session
    session.add(models.Finding(scan_id=uuid4(), **FINDING_DATA))
    with pytest.raises(IntegrityError):
        session.flush()


def test_finding_rejects_invalid_severity(finding_session) -> None:
    models, session, scan = finding_session
    session.add(
        models.Finding(scan_id=scan.id, **(FINDING_DATA | {"severity": "INVALID"}))
    )
    with pytest.raises(IntegrityError):
        session.flush()


def test_deleting_scan_removes_its_findings(finding_session) -> None:
    models, session, scan = finding_session
    session.add(models.Finding(scan_id=scan.id, **FINDING_DATA))
    session.flush()
    session.execute(delete(models.Scan).where(models.Scan.id == scan.id))
    assert (
        session.scalars(
            select(models.Finding).where(models.Finding.scan_id == scan.id)
        ).all()
        == []
    )
