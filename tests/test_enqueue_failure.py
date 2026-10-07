import pytest
from sqlalchemy.orm import Session

from app.api.schemas import ScanSubmission
from app.persistence import repository
from app.persistence.models import Scan
from tests.database_support import isolated_repository_engine


def test_enqueue_failure_is_saved_on_a_queued_scan():
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.create_queued_trivy_scan(
                session, ScanSubmission(image_reference="docker.io/library/alpine:3.20")
            )
            repository.fail_queued_scan(session, scan_id)
        with Session(engine) as observer:
            stored = observer.get(Scan, scan_id)
            assert stored.status == "failed"
            assert stored.error_details.startswith("enqueue_failed: ")
            assert stored.completed_at is not None
            assert stored.started_at is None


@pytest.mark.parametrize("status", ["running", "completed", "failed"])
def test_enqueue_error_does_not_overwrite_a_worker_outcome(status):
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.create_queued_trivy_scan(
                session, ScanSubmission(image_reference="docker.io/library/alpine:3.20")
            )
            with session.begin():
                stored = session.get(Scan, scan_id)
                stored.status = status
                stored.error_details = "original saved details"
            repository.fail_queued_scan(session, scan_id)
        with Session(engine) as observer:
            stored = observer.get(Scan, scan_id)
            assert stored.status == status
            assert stored.error_details == "original saved details"
