from operator import add
from uuid import uuid4

import pytest
from redis import Redis
from redis.backoff import NoBackoff
from redis.exceptions import RedisError
from redis.retry import Retry
from rq import Queue, SimpleWorker
from rq.executions import Execution
from rq.job import Job, JobStatus
from sqlalchemy.orm import Session

from app.api.schemas import ScanSubmission
from app.jobs import recovery, submission
from app.persistence import repository
from app.persistence.models import Scan
from tests.database_support import isolated_repository_engine
from tests.queue_support import isolated_scan_queue

SUBMISSION = ScanSubmission(image_reference="docker.io/library/alpine:3.20")


@pytest.fixture
def targets(monkeypatch):
    with isolated_repository_engine() as engine, isolated_scan_queue() as (queue, url):
        for module in (recovery, submission):
            monkeypatch.setattr(
                module,
                "get_redis_connection",
                lambda: Redis.from_url(url, socket_connect_timeout=5, socket_timeout=5),
            )
            monkeypatch.setattr(
                module,
                "get_scan_queue",
                lambda connection: Queue(
                    queue.name, connection=connection, default_timeout=600
                ),
            )
        yield engine, queue


@pytest.mark.parametrize("state", ["queued", "running"])
def test_recovery_replaces_the_old_job_under_the_same_scan_id(targets, state):
    engine, queue = targets
    with Session(engine) as session:
        scan_id = repository.create_queued_trivy_scan(session, SUBMISSION)
    submission.enqueue_scan(scan_id)
    old_job = Job.fetch(str(scan_id), connection=queue.connection)
    execution = None
    if state == "running":
        with Session(engine) as session:
            repository.claim_queued_trivy_scan(session, scan_id)
        queue.remove(old_job)
        old_job.set_status(JobStatus.STARTED)
        with queue.connection.pipeline() as pipeline:
            execution = Execution.create(old_job, ttl=600, pipeline=pipeline)
            pipeline.execute()
    with Session(engine) as session:
        assert recovery.recover_scan(session, scan_id, workers_stopped=True) == str(
            scan_id
        )
    job = Job.fetch(str(scan_id), connection=queue.connection)
    assert queue.job_ids == [str(scan_id)]
    assert job.get_status().value == "queued"
    assert job.args == (str(scan_id),)
    assert job.retries_left == 2
    assert job.get_executions() == []
    assert queue.started_job_registry.get_job_ids(cleanup=False) == []
    if execution is not None:
        assert not queue.connection.exists(execution.key)
    with Session(engine) as observer:
        assert observer.get(Scan, scan_id).status == "queued"


def test_recovery_requires_explicit_stopped_worker_confirmation(targets):
    engine, queue = targets
    with Session(engine) as session:
        scan_id = repository.start_trivy_scan(session, SUBMISSION)
        with pytest.raises(ValueError, match="Stop all scan workers before recovery"):
            recovery.recover_scan(session, scan_id)
    assert queue.count == 0
    with Session(engine) as observer:
        assert observer.get(Scan, scan_id).status == "running"


def test_registered_worker_blocks_recovery_even_with_confirmation(targets):
    engine, queue = targets
    with Session(engine) as session:
        scan_id = repository.start_trivy_scan(session, SUBMISSION)
    worker = SimpleWorker([queue], connection=queue.connection)
    worker.register_birth()
    try:
        with Session(engine) as session:
            with pytest.raises(ValueError, match="Scan workers are still registered"):
                recovery.recover_scan(session, scan_id, workers_stopped=True)
        with Session(engine) as observer:
            assert observer.get(Scan, scan_id).status == "running"
        assert queue.count == 0
    finally:
        worker.register_death()


@pytest.mark.parametrize("state", ["completed", "failed"])
def test_recovery_preserves_terminal_scan_and_existing_job(targets, state):
    engine, queue = targets
    with Session(engine) as session:
        scan_id = repository.create_queued_trivy_scan(session, SUBMISSION)
        with session.begin():
            session.get(Scan, scan_id).status = state
    submission.enqueue_scan(scan_id)
    with Session(engine) as session:
        with pytest.raises(ValueError, match="Expected a queued or running Trivy scan"):
            recovery.recover_scan(session, scan_id, workers_stopped=True)
    assert queue.job_ids == [str(scan_id)]
    with Session(engine) as observer:
        assert observer.get(Scan, scan_id).status == state


def test_recovery_refuses_a_job_with_an_unexpected_payload(targets):
    engine, queue = targets
    with Session(engine) as session:
        scan_id = repository.start_trivy_scan(session, SUBMISSION)
    queue.enqueue(add, 2, 3, job_id=str(scan_id))
    with Session(engine) as session:
        with pytest.raises(ValueError, match="Existing job does not match the scan"):
            recovery.recover_scan(session, scan_id, workers_stopped=True)
    assert (
        Job.fetch(str(scan_id), connection=queue.connection).func_name
        == "_operator.add"
    )
    with Session(engine) as observer:
        assert observer.get(Scan, scan_id).status == "running"


def test_unknown_scan_cannot_be_recovered(targets):
    engine, queue = targets
    with Session(engine) as session:
        with pytest.raises(ValueError, match="Expected a queued or running Trivy scan"):
            recovery.recover_scan(session, uuid4(), workers_stopped=True)
    assert queue.count == 0


def test_recovery_recreates_a_missing_redis_job(targets):
    engine, queue = targets
    with Session(engine) as session:
        scan_id = repository.start_trivy_scan(session, SUBMISSION)
        assert recovery.recover_scan(session, scan_id, workers_stopped=True) == str(
            scan_id
        )
    assert queue.job_ids == [str(scan_id)]


def test_recovery_enqueue_failure_leaves_a_record_that_can_be_recovered_again(
    targets, monkeypatch
):
    engine, queue = targets
    with Session(engine) as session:
        scan_id = repository.start_trivy_scan(session, SUBMISSION)
    submission.enqueue_scan(scan_id)
    original_connection = submission.get_redis_connection
    monkeypatch.setattr(
        submission,
        "get_redis_connection",
        lambda: Redis.from_url(
            "redis://127.0.0.1:1/0",
            socket_connect_timeout=1,
            socket_timeout=1,
            retry=Retry(NoBackoff(), 0),
        ),
    )
    with Session(engine) as session:
        with pytest.raises(RedisError):
            recovery.recover_scan(session, scan_id, workers_stopped=True)
    assert queue.count == 0
    with Session(engine) as observer:
        assert observer.get(Scan, scan_id).status == "queued"
    monkeypatch.setattr(submission, "get_redis_connection", original_connection)
    with Session(engine) as session:
        assert recovery.recover_scan(session, scan_id, workers_stopped=True) == str(
            scan_id
        )
    assert queue.job_ids == [str(scan_id)]
