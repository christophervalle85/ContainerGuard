import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas import ScanSubmission
from app.jobs import tasks
from app.persistence import repository
from app.persistence.models import Scan
from app.scanning import workflow
from app.scanning.trivy.parser import ParsedScanMetadata
from tests.database_support import isolated_repository_engine

SUBMISSION = ScanSubmission(image_reference="docker.io/library/alpine:3.20")
DIGEST = "sha256:" + "a" * 64
PINNED = f"docker.io/library/alpine@{DIGEST}"


@pytest.mark.parametrize("outcome", ["completed", "failed"])
def test_job_opens_its_own_session_and_preserves_the_scan_on_redelivery(
    monkeypatch, outcome
):
    attempts = []

    def collect(submission):
        assert submission == SUBMISSION
        attempts.append(submission)
        if outcome == "failed":
            raise workflow.ScanWorkflowError("resolution_failed")
        return workflow.TrivyResult(
            pinned_reference=PINNED,
            metadata=ParsedScanMetadata(
                image_reference=SUBMISSION.image_reference,
                reported_digest=DIGEST,
                platform="linux/amd64",
                scanner_version="0.75.0",
            ),
            findings=[],
        )

    monkeypatch.setattr(workflow, "collect_trivy_result", collect)
    with isolated_repository_engine() as engine:
        monkeypatch.setattr(tasks, "get_engine", lambda: engine)
        with Session(engine) as submitter:
            scan_id = repository.create_queued_trivy_scan(submitter, SUBMISSION)

        assert tasks.run_scan(str(scan_id)) == str(scan_id)
        assert tasks.run_scan(str(scan_id)) == str(scan_id)
        assert len(attempts) == 1
        with Session(engine) as observer:
            stored = observer.get(Scan, scan_id)
            assert stored.status == outcome
            assert stored.completed_at is not None
            assert observer.scalar(select(func.count()).select_from(Scan)) == 1
            if outcome == "failed":
                assert stored.error_details.startswith("resolution_failed: ")
            else:
                assert stored.error_details is None
                assert stored.scanner_version == "0.75.0"


def test_malformed_job_scan_id_is_rejected_before_database_access(monkeypatch):
    def unexpected_database():
        raise AssertionError("An invalid scan ID must not open a database session")

    monkeypatch.setattr(tasks, "get_engine", unexpected_database)
    with pytest.raises(ValueError):
        tasks.run_scan("not-a-uuid")


@pytest.mark.parametrize(
    "sensitive",
    [
        "postgresql://operator:sentinel_database_password@db/private",
        "redis://:sentinel_queue_password@redis/0",
        "Bearer sentinel_registry_token",
        "raw scanner stderr sentinel_output",
    ],
)
def test_rq_failure_traceback_does_not_store_sensitive_exception_text(
    monkeypatch, caplog, sensitive
):
    from rq import SimpleWorker

    from tests.queue_support import isolated_scan_queue

    def fail(*args, **kwargs):
        raise RuntimeError(sensitive)

    monkeypatch.setattr(tasks, "process_queued_trivy_scan", fail)
    with isolated_repository_engine() as engine, isolated_scan_queue() as (queue, url):
        monkeypatch.setattr(tasks, "get_engine", lambda: engine)
        with Session(engine) as session:
            scan_id = repository.create_queued_trivy_scan(session, SUBMISSION)
        job = queue.enqueue(tasks.run_scan, str(scan_id), job_id=str(scan_id))
        SimpleWorker([queue], connection=queue.connection).work(burst=True)
        job.refresh()
        assert job.get_status().value == "failed"
        assert sensitive not in (job.latest_result().exc_string or "")
        assert sensitive not in caplog.text
        assert "Scan job interrupted" in (job.latest_result().exc_string or "")
        with Session(engine) as session:
            assert session.get(Scan, scan_id).status == "queued"
