import time

import pytest
from redis import Redis
from rq import Queue, SimpleWorker
from rq.job import Job
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas import ScanSubmission
from app.jobs import submission, tasks
from app.persistence import repository
from app.persistence.models import Scan
from app.scanning import workflow
from app.scanning.trivy.parser import ParsedScanMetadata
from tests.database_support import isolated_repository_engine
from tests.queue_support import isolated_scan_queue

SUBMISSION = ScanSubmission(image_reference="docker.io/library/alpine:3.20")
DIGEST = "sha256:" + "a" * 64
PINNED = f"docker.io/library/alpine@{DIGEST}"


@pytest.mark.parametrize(
    "outcome,expected_attempts,expected_status",
    [
        ("temporary_then_success", 2, "completed"),
        ("temporary_always", 3, "failed"),
        ("permanent", 1, "failed"),
    ],
)
def test_rq_executes_only_the_allowed_scan_attempts(
    monkeypatch, outcome, expected_attempts, expected_status
):
    attempts = []

    def collect(image):
        assert image == SUBMISSION
        attempts.append(image)
        if outcome == "permanent":
            raise workflow.ScanWorkflowError("resolution_failed", retryable=False)
        if outcome == "temporary_always" or len(attempts) == 1:
            raise workflow.ScanWorkflowError("scanner_timeout", retryable=True)
        return workflow.TrivyResult(
            PINNED, ParsedScanMetadata(PINNED, DIGEST, "linux/amd64", "0.75.0"), []
        )

    monkeypatch.setattr(workflow, "collect_trivy_result", collect)
    with isolated_repository_engine() as engine, isolated_scan_queue() as (queue, url):
        monkeypatch.setattr(tasks, "get_engine", lambda: engine)
        monkeypatch.setattr(
            submission,
            "get_redis_connection",
            lambda: Redis.from_url(url, socket_connect_timeout=5, socket_timeout=5),
        )
        monkeypatch.setattr(
            submission,
            "get_scan_queue",
            lambda connection: Queue(
                queue.name, connection=connection, default_timeout=600
            ),
        )
        with Session(engine) as session:
            scan_id = repository.create_queued_trivy_scan(session, SUBMISSION)
        job_id = submission.enqueue_scan(scan_id)
        job = Job.fetch(job_id, connection=queue.connection)
        # Keep the application's retry budget, but avoid waiting in these tests.
        job.retry_intervals = [0, 0]
        job.save()
        worker = SimpleWorker([queue], connection=queue.connection)
        worker.work(burst=True)
        assert len(attempts) == expected_attempts
        assert queue.count == 0
        with Session(engine) as observer:
            stored = observer.get(Scan, scan_id)
            assert stored.status == expected_status
            assert stored.completed_at is not None
            assert observer.scalar(select(func.count()).select_from(Scan)) == 1
            if expected_status == "completed":
                assert stored.error_details is None
            else:
                assert stored.error_details is not None


def test_rq_schedules_the_configured_delays_before_the_final_attempt(monkeypatch):
    attempts = []

    def fail(image):
        attempts.append(image)
        raise workflow.ScanWorkflowError("scanner_timeout", retryable=True)

    monkeypatch.setattr(workflow, "collect_trivy_result", fail)
    with isolated_repository_engine() as engine, isolated_scan_queue() as (queue, url):
        monkeypatch.setattr(tasks, "get_engine", lambda: engine)
        monkeypatch.setattr(
            submission,
            "get_redis_connection",
            lambda: Redis.from_url(url, socket_connect_timeout=5, socket_timeout=5),
        )
        monkeypatch.setattr(
            submission,
            "get_scan_queue",
            lambda connection: Queue(
                queue.name, connection=connection, default_timeout=600
            ),
        )
        with Session(engine) as session:
            scan_id = repository.create_queued_trivy_scan(session, SUBMISSION)
        job_id = submission.enqueue_scan(scan_id)

        for delay, retries_left in [(5, 1), (15, 0)]:
            before = time.time()
            SimpleWorker([queue], connection=queue.connection).work(
                burst=True, max_jobs=1
            )
            after = time.time()
            job = Job.fetch(job_id, connection=queue.connection)
            assert job.get_status().value == "scheduled"
            assert job.retries_left == retries_left
            scheduled_at = queue.scheduled_job_registry.get_scheduled_time(
                job
            ).timestamp()
            # RQ stores scheduling times rounded to whole seconds.
            assert before + delay - 1 <= scheduled_at <= after + delay + 1
            assert queue.count == 0
            with Session(engine) as observer:
                assert observer.get(Scan, scan_id).status == "queued"
            # Simulate the scheduler releasing the due job, without sleeping.
            queue.scheduled_job_registry.remove(job)
            queue.enqueue_job(job)

        SimpleWorker([queue], connection=queue.connection).work(burst=True)
        assert len(attempts) == 3
        assert queue.scheduled_job_registry.get_job_ids() == []
        with Session(engine) as observer:
            assert observer.get(Scan, scan_id).status == "failed"
