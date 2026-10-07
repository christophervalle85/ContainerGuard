from uuid import uuid4

import pytest
from redis import Redis
from redis.backoff import NoBackoff
from redis.exceptions import RedisError
from redis.retry import Retry
from rq.exceptions import DuplicateJobError
from rq.job import Job

from app.jobs import submission
from tests.queue_support import isolated_scan_queue, validate_test_redis_url


@pytest.fixture
def queue_target(monkeypatch):
    with isolated_scan_queue() as (queue, url):
        monkeypatch.setattr(
            submission,
            "get_redis_connection",
            lambda: Redis.from_url(url, socket_connect_timeout=5, socket_timeout=5),
        )
        monkeypatch.setattr(
            submission,
            "get_scan_queue",
            lambda connection: type(queue)(
                queue.name, connection=connection, default_timeout=600
            ),
        )
        yield queue


def test_enqueue_saves_the_worker_function_and_only_the_scan_id(queue_target):
    scan_id = uuid4()
    job_id = submission.enqueue_scan(scan_id)
    job = Job.fetch(job_id, connection=queue_target.connection)
    assert job_id == str(scan_id)
    assert job.func_name == "app.jobs.tasks.run_scan"
    assert job.args == (str(scan_id),)
    assert job.kwargs == {}
    assert job.get_status().value == "queued"
    assert queue_target.job_ids == [str(scan_id)]


def test_duplicate_submission_does_not_add_a_second_job(queue_target):
    scan_id = uuid4()
    submission.enqueue_scan(scan_id)
    with pytest.raises(DuplicateJobError):
        submission.enqueue_scan(scan_id)
    assert queue_target.job_ids == [str(scan_id)]


def test_redis_unavailable_is_reported_to_the_caller(monkeypatch):
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
    with pytest.raises(RedisError):
        submission.enqueue_scan(uuid4())


@pytest.mark.parametrize(
    "test_url",
    [
        None,
        "redis://localhost:6380/1",
        "redis://127.0.0.1:6381/0?host=127.0.0.1",
        "http://127.0.0.1:6381",
    ],
)
def test_unsafe_test_queue_target_is_rejected(test_url):
    with pytest.raises(ValueError):
        validate_test_redis_url(test_url, "redis://127.0.0.1:6380/0")
