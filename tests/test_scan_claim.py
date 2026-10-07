from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas import ScanSubmission
from app.persistence import repository
from app.persistence.models import Scan
from tests.database_support import isolated_repository_engine

SUBMISSION = ScanSubmission(image_reference="docker.io/library/alpine:3.20")


def test_claim_commits_running_state_before_returning_work():
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.create_queued_trivy_scan(session, SUBMISSION)
            work = repository.claim_queued_trivy_scan(session, scan_id)
            assert work == SUBMISSION
            assert not session.in_transaction()
            with Session(engine) as observer:
                stored = observer.get(Scan, scan_id)
                assert stored.status == "running"
                assert stored.started_at.tzinfo is not None
                assert stored.started_at >= stored.created_at
                assert stored.completed_at is None
                assert stored.error_details is None
                assert observer.scalar(select(func.count()).select_from(Scan)) == 1


@pytest.mark.parametrize("status", ["running", "completed", "failed"])
def test_redelivery_does_not_claim_or_rewrite_an_existing_attempt(status):
    timestamp = datetime(2026, 1, 1, tzinfo=UTC)
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.create_queued_trivy_scan(session, SUBMISSION)
            with session.begin():
                stored = session.get(Scan, scan_id)
                stored.status = status
                stored.started_at = timestamp
                stored.completed_at = timestamp if status != "running" else None
                stored.error_details = (
                    "scanner_timeout: saved failure" if status == "failed" else None
                )
            assert repository.claim_queued_trivy_scan(session, scan_id) is None
            assert not session.in_transaction()
        with Session(engine) as observer:
            stored = observer.get(Scan, scan_id)
            assert stored.status == status
            assert stored.started_at == timestamp
            assert stored.completed_at == (timestamp if status != "running" else None)
            assert stored.error_details == (
                "scanner_timeout: saved failure" if status == "failed" else None
            )


def test_unknown_scan_cannot_be_claimed():
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            with pytest.raises(ValueError, match="Scan does not exist"):
                repository.claim_queued_trivy_scan(session, uuid4())
            assert not session.in_transaction()
        with Session(engine) as observer:
            assert observer.scalar(select(func.count()).select_from(Scan)) == 0


def test_non_trivy_scan_cannot_be_claimed_by_the_trivy_worker():
    scan_id = uuid4()
    with isolated_repository_engine() as engine:
        with Session(engine) as session, session.begin():
            session.add(
                Scan(id=scan_id, submitted_reference="demo/image:mock", status="queued")
            )
        with Session(engine) as session:
            with pytest.raises(ValueError, match="Scan is not a Trivy scan"):
                repository.claim_queued_trivy_scan(session, scan_id)
        with Session(engine) as observer:
            stored = observer.get(Scan, scan_id)
            assert stored.status == "queued"
            assert stored.started_at is None


def test_simultaneous_workers_only_claim_a_queued_scan_once():
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.create_queued_trivy_scan(session, SUBMISSION)
        ready = Barrier(2)

        def claim():
            with Session(engine) as session:
                ready.wait(timeout=5)
                return repository.claim_queued_trivy_scan(session, scan_id)

        with ThreadPoolExecutor(max_workers=2) as workers:
            futures = [workers.submit(claim) for _ in range(2)]
            results = [future.result(timeout=10) for future in futures]
        assert sum(result == SUBMISSION for result in results) == 1
        assert sum(result is None for result in results) == 1
        with Session(engine) as observer:
            assert observer.get(Scan, scan_id).status == "running"
