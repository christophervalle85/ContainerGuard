import os
from contextlib import contextmanager
from urllib.parse import urlsplit
from uuid import uuid4

from redis import Redis
from rq import Queue


def validate_test_redis_url(test_url: str | None, development_url: str | None) -> str:
    if not test_url or not development_url:
        raise ValueError("Both test and development Redis settings are required")

    try:
        test = urlsplit(test_url)
        development = urlsplit(development_url)
        targets = []
        for url in (test, development):
            if (
                url.scheme not in {"redis", "rediss"}
                or not url.hostname
                or url.query
                or url.fragment
            ):
                raise ValueError
            host = url.hostname
            if host in {"localhost", "127.0.0.1", "::1"}:
                host = "loopback"
            targets.append((host, url.port or 6379))
        if targets[0] == targets[1]:
            raise ValueError
    except ValueError:
        raise ValueError(
            "Tests require a separate Redis server without URL overrides"
        ) from None
    return test_url


@contextmanager
def isolated_scan_queue():
    url = validate_test_redis_url(
        os.environ.get("TEST_REDIS_URL"), os.environ.get("REDIS_URL")
    )
    with Redis.from_url(url, socket_connect_timeout=5, socket_timeout=5) as connection:
        queue = Queue(f"test_scans_{uuid4().hex}", connection=connection)
        try:
            yield queue, url
        finally:
            # Remove only this test's queue and jobs; never flush a Redis database.
            job_ids = set(queue.job_ids)
            for registry in (
                queue.finished_job_registry,
                queue.failed_job_registry,
                queue.scheduled_job_registry,
            ):
                job_ids.update(registry.get_job_ids(cleanup=False))
            for job_id in job_ids:
                job = queue.fetch_job(job_id)
                if job is not None:
                    job.delete()
            queue.delete(delete_jobs=True)
