from datetime import UTC, datetime
from importlib import import_module
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas import ScanSubmission
from app.persistence.models import Finding, Image, Scan
from tests.database_support import isolated_repository_engine

SUBMISSION = ScanSubmission(image_reference="docker.io/library/alpine:3.20")


@pytest.mark.parametrize(
    "error_code,expected_detail",
    [
        (
            "resolution_failed",
            "resolution_failed: Image reference could not be resolved",
        ),
        ("scanner_timeout", "scanner_timeout: Scanner exceeded its execution deadline"),
    ],
)
def test_failure_is_committed_and_visible_in_history(error_code, expected_detail):
    repository = import_module("app.persistence.repository")
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.start_trivy_scan(session, SUBMISSION)
            repository.fail_trivy_scan(session, scan_id, error_code)
            assert not session.in_transaction()
        with Session(engine) as session:
            stored = session.get(Scan, scan_id)
            assert stored.status == "failed"
            assert stored.submitted_reference == SUBMISSION.image_reference
            assert stored.completed_at >= stored.started_at
            assert stored.completed_at.tzinfo is not None
            assert stored.error_details == expected_detail
            assert stored.scanner_name == "trivy"
            assert stored.image_id is None
            assert stored.scanner_version is None
            assert session.scalar(select(func.count()).select_from(Image)) == 0
            assert session.scalar(select(func.count()).select_from(Finding)) == 0
            page = repository.get_scan_history(session, limit=20, offset=0)
            assert page.total == 1
            assert page.items[0].scan_id == scan_id
            assert page.items[0].status == "failed"


def test_unknown_scan_is_not_created_by_failure_handling():
    repository = import_module("app.persistence.repository")
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            with pytest.raises(ValueError, match="running Trivy scan"):
                repository.fail_trivy_scan(session, uuid4(), "scanner_timeout")
        with Session(engine) as session:
            assert session.scalar(select(func.count()).select_from(Scan)) == 0


@pytest.mark.parametrize("status", ["completed", "failed"])
def test_failure_cannot_overwrite_a_terminal_scan(status):
    repository = import_module("app.persistence.repository")
    scan_id = uuid4()
    completed_at = datetime(2026, 1, 1, tzinfo=UTC)
    with isolated_repository_engine() as engine:
        with Session(engine) as session, session.begin():
            session.add(
                Scan(
                    id=scan_id,
                    submitted_reference=SUBMISSION.image_reference,
                    status=status,
                    scanner_name="trivy",
                    completed_at=completed_at,
                    error_details="existing detail",
                )
            )
        with Session(engine) as session:
            with pytest.raises(ValueError, match="running Trivy scan"):
                repository.fail_trivy_scan(session, scan_id, "scanner_timeout")
        with Session(engine) as session:
            stored = session.get(Scan, scan_id)
            assert stored.status == status
            assert stored.completed_at == completed_at
            assert stored.error_details == "existing detail"


def test_failure_handler_rejects_a_non_trivy_attempt():
    repository = import_module("app.persistence.repository")
    scan_id = uuid4()
    with isolated_repository_engine() as engine:
        with Session(engine) as session, session.begin():
            session.add(
                Scan(
                    id=scan_id,
                    submitted_reference=SUBMISSION.image_reference,
                    status="running",
                )
            )
        with Session(engine) as session:
            with pytest.raises(ValueError, match="running Trivy scan"):
                repository.fail_trivy_scan(session, scan_id, "scanner_timeout")
        with Session(engine) as session:
            assert session.get(Scan, scan_id).status == "running"


def test_arbitrary_exception_text_cannot_be_saved_as_an_error_code():
    repository = import_module("app.persistence.repository")
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.start_trivy_scan(session, SUBMISSION)
            with pytest.raises(ValueError, match="error code"):
                repository.fail_trivy_scan(session, scan_id, "secret-token raw stderr")
            assert not session.in_transaction()
        with Session(engine) as session:
            stored = session.get(Scan, scan_id)
            assert stored.status == "running"
            assert stored.completed_at is None
            assert stored.error_details is None


def test_failure_updates_only_the_requested_attempt():
    repository = import_module("app.persistence.repository")
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            first = repository.start_trivy_scan(session, SUBMISSION)
            second = repository.start_trivy_scan(session, SUBMISSION)
            repository.fail_trivy_scan(session, first, "scanner_timeout")
        with Session(engine) as session:
            assert session.get(Scan, first).status == "failed"
            untouched = session.get(Scan, second)
            assert untouched.status == "running"
            assert untouched.completed_at is None
            assert untouched.error_details is None
