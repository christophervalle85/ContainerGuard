from concurrent.futures import ThreadPoolExecutor
from importlib import import_module
from threading import Barrier
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.api.schemas import ScanSubmission
from app.main import app
from app.persistence import repository
from app.persistence.database import get_session
from app.persistence.models import Scan
from tests.database_support import isolated_repository_engine

SUBMISSION = ScanSubmission(image_reference="docker.io/library/alpine:3.20")


@pytest.mark.parametrize("value,expected", [(None, 20), ("1", 1), ("1000", 1000)])
def test_capacity_configuration(monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv("MAX_ACTIVE_SCANS", raising=False)
    else:
        monkeypatch.setenv("MAX_ACTIVE_SCANS", value)
    assert import_module("app.persistence.admission").get_max_active_scans() == expected


@pytest.mark.parametrize("value", ["0", "1001", "true", "1.5", "", "bad"])
def test_invalid_capacity_configuration_is_rejected(monkeypatch, value):
    monkeypatch.setenv("MAX_ACTIVE_SCANS", value)
    with pytest.raises(ValueError):
        import_module("app.persistence.admission").get_max_active_scans()


def test_simultaneous_creations_share_one_last_slot(monkeypatch):
    monkeypatch.setenv("MAX_ACTIVE_SCANS", "1")
    admission = import_module("app.persistence.admission")
    with isolated_repository_engine() as engine:
        barrier = Barrier(2)

        def create(start):
            with Session(engine) as session:
                barrier.wait(timeout=5)
                try:
                    return start(session, SUBMISSION)
                except admission.ScanCapacityExceeded:
                    return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(create, repository.create_queued_trivy_scan)
            second = pool.submit(create, repository.start_trivy_scan)
            results = [first.result(timeout=10), second.result(timeout=10)]
        assert sum(value is not None for value in results) == 1
        with Session(engine) as session:
            assert session.scalar(select(func.count()).select_from(Scan)) == 1


@pytest.mark.parametrize(
    "status,scanner,blocked",
    [
        ("queued", "trivy", True),
        ("running", "trivy", True),
        ("completed", "trivy", False),
        ("failed", "trivy", False),
        ("queued", "mock", False),
    ],
)
def test_only_real_active_scans_occupy_capacity(monkeypatch, status, scanner, blocked):
    monkeypatch.setenv("MAX_ACTIVE_SCANS", "1")
    admission = import_module("app.persistence.admission")
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            with session.begin():
                session.add(
                    Scan(
                        id=uuid4(),
                        submitted_reference=SUBMISSION.image_reference,
                        status=status,
                        scanner_name=scanner,
                    )
                )
        with Session(engine) as session:
            if blocked:
                with pytest.raises(admission.ScanCapacityExceeded):
                    repository.create_queued_trivy_scan(session, SUBMISSION)
                assert not session.in_transaction()
            else:
                assert repository.create_queued_trivy_scan(session, SUBMISSION)


def test_enqueue_failure_releases_slot_but_interruption_does_not(monkeypatch):
    monkeypatch.setenv("MAX_ACTIVE_SCANS", "1")
    admission = import_module("app.persistence.admission")
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            first = repository.create_queued_trivy_scan(session, SUBMISSION)
            with pytest.raises(admission.ScanCapacityExceeded):
                repository.create_queued_trivy_scan(session, SUBMISSION)
            repository.fail_queued_scan(session, first)
            second = repository.create_queued_trivy_scan(session, SUBMISSION)
            assert first != second
            repository.prepare_scan_recovery(session, second, workers_stopped=True)
            with pytest.raises(admission.ScanCapacityExceeded):
                repository.create_queued_trivy_scan(session, SUBMISSION)


def test_lock_contention_rolls_back_with_safe_error(monkeypatch):
    monkeypatch.setenv("MAX_ACTIVE_SCANS", "1")
    admission = import_module("app.persistence.admission")
    with isolated_repository_engine() as engine:
        with engine.begin() as blocker:
            blocker.execute(text("SELECT pg_advisory_xact_lock(1128746545)"))
            with Session(engine) as session:
                with pytest.raises(admission.ScanAdmissionUnavailable):
                    repository.create_queued_trivy_scan(session, SUBMISSION)
                assert not session.in_transaction()
        with Session(engine) as session:
            assert session.scalar(select(func.count()).select_from(Scan)) == 0


def test_api_capacity_rejection_has_no_row_or_queue_job(monkeypatch):
    monkeypatch.setenv("MAX_ACTIVE_SCANS", "1")
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            repository.create_queued_trivy_scan(session, SUBMISSION)

        def test_session():
            with Session(engine) as session:
                yield session

        previous = app.dependency_overrides.copy()
        app.dependency_overrides[get_session] = test_session
        try:
            with TestClient(app, raise_server_exceptions=False) as client:
                response = client.post(
                    "/api/v1/scans",
                    json={"image_reference": SUBMISSION.image_reference},
                )
            assert response.status_code == 429
            assert response.headers["Retry-After"] == "30"
            with Session(engine) as session:
                assert session.scalar(select(func.count()).select_from(Scan)) == 1
        finally:
            app.dependency_overrides.clear()
            app.dependency_overrides.update(previous)


def test_api_refuses_invalid_capacity_at_startup(monkeypatch):
    monkeypatch.setenv("MAX_ACTIVE_SCANS", "0")
    with pytest.raises(ValueError, match="MAX_ACTIVE_SCANS"):
        with TestClient(app):
            pass


def test_retry_retains_capacity_until_terminal_failure(monkeypatch):
    monkeypatch.setenv("MAX_ACTIVE_SCANS", "1")
    admission = import_module("app.persistence.admission")
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.start_trivy_scan(session, SUBMISSION)
            repository.requeue_trivy_scan(session, scan_id, "scanner_timeout")
            with pytest.raises(admission.ScanCapacityExceeded):
                repository.create_queued_trivy_scan(session, SUBMISSION)
            repository.claim_queued_trivy_scan(session, scan_id)
            repository.fail_trivy_scan(session, scan_id, "scanner_timeout")
            assert repository.create_queued_trivy_scan(session, SUBMISSION) != scan_id
