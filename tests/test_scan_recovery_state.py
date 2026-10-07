from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas import ScanSubmission
from app.persistence import repository
from app.persistence.models import Finding, Image, Scan
from tests.database_support import isolated_repository_engine

SUBMISSION = ScanSubmission(image_reference="docker.io/library/alpine:3.20")


@pytest.mark.parametrize("status", ["queued", "running"])
def test_manual_recovery_preserves_identity_and_makes_an_attempt_claimable(status):
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.start_trivy_scan(session, SUBMISSION)
            with session.begin():
                stored = session.get(Scan, scan_id)
                stored.status = status
        with Session(engine) as observer:
            created_at = observer.get(Scan, scan_id).created_at
        with Session(engine) as session:
            repository.prepare_scan_recovery(session, scan_id, workers_stopped=True)
            assert not session.in_transaction()
        with Session(engine) as observer:
            stored = observer.get(Scan, scan_id)
            assert stored.status == "queued"
            assert stored.created_at == created_at
            assert stored.started_at is None
            assert stored.completed_at is None
            assert stored.error_details.startswith("recovery_requested: ")
            assert observer.scalar(select(func.count()).select_from(Scan)) == 1
        with Session(engine) as session:
            assert repository.claim_queued_trivy_scan(session, scan_id) == SUBMISSION


@pytest.mark.parametrize("status", ["completed", "failed"])
def test_manual_recovery_cannot_reopen_a_terminal_scan(status):
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.start_trivy_scan(session, SUBMISSION)
            with session.begin():
                stored = session.get(Scan, scan_id)
                stored.status = status
                stored.error_details = "original saved details"
            with pytest.raises(
                ValueError, match="Expected a queued or running Trivy scan"
            ):
                repository.prepare_scan_recovery(session, scan_id, workers_stopped=True)
        with Session(engine) as observer:
            stored = observer.get(Scan, scan_id)
            assert stored.status == status
            assert stored.error_details == "original saved details"


def test_recovery_requires_confirmation_that_workers_have_stopped():
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.start_trivy_scan(session, SUBMISSION)
            with pytest.raises(
                ValueError, match="Stop all scan workers before recovery"
            ):
                repository.prepare_scan_recovery(session, scan_id)
        with Session(engine) as observer:
            assert observer.get(Scan, scan_id).status == "running"


def test_unknown_scan_cannot_be_recovered():
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            with pytest.raises(
                ValueError, match="Expected a queued or running Trivy scan"
            ):
                repository.prepare_scan_recovery(session, uuid4(), workers_stopped=True)


def test_non_trivy_scan_cannot_be_recovered():
    scan_id = uuid4()
    with isolated_repository_engine() as engine:
        with Session(engine) as session, session.begin():
            session.add(
                Scan(
                    id=scan_id, submitted_reference="demo/image:other", status="running"
                )
            )
        with Session(engine) as session:
            with pytest.raises(
                ValueError, match="Expected a queued or running Trivy scan"
            ):
                repository.prepare_scan_recovery(session, scan_id, workers_stopped=True)


@pytest.mark.parametrize("saved_result", ["image", "finding"])
def test_recovery_refuses_inconsistent_attempts_with_saved_results(saved_result):
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.start_trivy_scan(session, SUBMISSION)
            with session.begin():
                if saved_result == "image":
                    image = Image(
                        registry_host="docker.io",
                        repository="library/alpine",
                        digest="sha256:" + "a" * 64,
                        platform="linux/amd64",
                    )
                    session.add(image)
                    session.flush()
                    session.get(Scan, scan_id).image_id = image.id
                else:
                    session.add(
                        Finding(
                            scan_id=scan_id,
                            vulnerability_id="DEMO-001",
                            package_name="demo",
                            package_type="alpine",
                            target="demo",
                            installed_version="1",
                            fixed_version=None,
                            severity="LOW",
                            title="Sample saved finding",
                            occurrence_order=0,
                        )
                    )
            with pytest.raises(ValueError, match="Scan already has saved results"):
                repository.prepare_scan_recovery(session, scan_id, workers_stopped=True)
        with Session(engine) as observer:
            assert observer.get(Scan, scan_id).status == "running"
