from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas import ScanSubmission
from app.persistence import repository
from app.persistence.models import Finding, Scan
from tests.database_support import isolated_repository_engine

SUBMISSION = ScanSubmission(image_reference="docker.io/library/alpine:3.20")


def test_retry_keeps_the_same_record_and_allows_it_to_be_claimed_again():
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.start_trivy_scan(session, SUBMISSION)
        with Session(engine) as observer:
            created_at = observer.get(Scan, scan_id).created_at
        with Session(engine) as session:
            repository.requeue_trivy_scan(session, scan_id, "scanner_timeout")
            assert not session.in_transaction()
        with Session(engine) as observer:
            stored = observer.get(Scan, scan_id)
            assert stored.status == "queued"
            assert stored.created_at == created_at
            assert stored.started_at is None
            assert stored.completed_at is None
            assert stored.error_details.startswith("scanner_timeout: ")
            assert stored.image_id is None
            assert observer.scalar(select(func.count()).select_from(Scan)) == 1
            assert observer.scalar(select(func.count()).select_from(Finding)) == 0
        with Session(engine) as session:
            assert repository.claim_queued_trivy_scan(session, scan_id) == SUBMISSION
        with Session(engine) as observer:
            assert observer.get(Scan, scan_id).status == "running"


@pytest.mark.parametrize("status", ["queued", "completed", "failed"])
def test_retry_transition_rejects_a_scan_that_is_not_running(status):
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.start_trivy_scan(session, SUBMISSION)
            with session.begin():
                stored = session.get(Scan, scan_id)
                stored.status = status
                stored.error_details = "existing details"
            with pytest.raises(ValueError, match="Expected a running Trivy scan"):
                repository.requeue_trivy_scan(session, scan_id, "scanner_timeout")
        with Session(engine) as observer:
            stored = observer.get(Scan, scan_id)
            assert stored.status == status
            assert stored.error_details == "existing details"


def test_retry_transition_rejects_an_unknown_scan():
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            with pytest.raises(ValueError, match="Expected a running Trivy scan"):
                repository.requeue_trivy_scan(session, uuid4(), "scanner_timeout")
        with Session(engine) as observer:
            assert observer.scalar(select(func.count()).select_from(Scan)) == 0


def test_retry_transition_rejects_a_non_trivy_scan():
    scan_id = uuid4()
    with isolated_repository_engine() as engine:
        with Session(engine) as session, session.begin():
            session.add(
                Scan(
                    id=scan_id, submitted_reference="demo/image:other", status="running"
                )
            )
        with Session(engine) as session:
            with pytest.raises(ValueError, match="Expected a running Trivy scan"):
                repository.requeue_trivy_scan(session, scan_id, "scanner_timeout")
        with Session(engine) as observer:
            assert observer.get(Scan, scan_id).status == "running"


def test_retry_transition_rejects_unknown_error_details():
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.start_trivy_scan(session, SUBMISSION)
            with pytest.raises(ValueError, match="Unknown scan error code"):
                repository.requeue_trivy_scan(session, scan_id, "private raw exception")
        with Session(engine) as observer:
            stored = observer.get(Scan, scan_id)
            assert stored.status == "running"
            assert stored.error_details is None
