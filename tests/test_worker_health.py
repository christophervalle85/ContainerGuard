from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from redis import Redis
from redis.backoff import NoBackoff
from redis.retry import Retry
from rq import SimpleWorker
from rq.utils import utcformat

from app.jobs import health
from tests.queue_support import isolated_scan_queue


@pytest.fixture
def registered_worker():
    with isolated_scan_queue() as (queue, _):
        worker = SimpleWorker(
            [queue], name=f"health_test_{uuid4().hex}", connection=queue.connection
        )
        worker.register_birth()
        worker.set_state("idle")
        try:
            yield worker
        finally:
            worker.register_death()
            queue.connection.delete(worker.key)


@pytest.mark.parametrize("state", ["idle", "busy"])
def test_fresh_matching_worker_is_healthy(registered_worker, state):
    worker = registered_worker
    worker.set_state(state)
    assert health.worker_is_healthy(worker.connection, worker.name)


def test_fresh_unrelated_worker_does_not_hide_a_missing_worker(registered_worker):
    worker = registered_worker
    assert not health.worker_is_healthy(worker.connection, "missing_" + uuid4().hex)


@pytest.mark.parametrize("name", ["", "   "])
def test_blank_worker_name_is_unhealthy(registered_worker, name):
    assert not health.worker_is_healthy(registered_worker.connection, name)


@pytest.mark.parametrize("age, expected", [(119, True), (121, False), (-60, False)])
def test_health_depends_on_heartbeat_age(registered_worker, age, expected):
    worker = registered_worker
    timestamp = datetime.now(UTC) - timedelta(seconds=age)
    worker.connection.hset(worker.key, "last_heartbeat", utcformat(timestamp))
    assert health.worker_is_healthy(worker.connection, worker.name) is expected


@pytest.mark.parametrize("value", ["", "not-a-timestamp"])
def test_unusable_heartbeat_is_unhealthy(registered_worker, value):
    worker = registered_worker
    worker.connection.hset(worker.key, "last_heartbeat", value)
    assert not health.worker_is_healthy(worker.connection, worker.name)


def test_shutdown_worker_is_unhealthy_even_with_recent_heartbeat(registered_worker):
    worker = registered_worker
    worker.register_death()
    assert not health.worker_is_healthy(worker.connection, worker.name)


def test_suspended_worker_is_unhealthy(registered_worker):
    worker = registered_worker
    worker.set_state("suspended")
    assert not health.worker_is_healthy(worker.connection, worker.name)


def test_probe_does_not_refresh_a_stale_worker(registered_worker):
    worker = registered_worker
    timestamp = utcformat(datetime.now(UTC) - timedelta(seconds=121))
    worker.connection.hset(worker.key, "last_heartbeat", timestamp)
    before = worker.connection.hgetall(worker.key)
    assert not health.worker_is_healthy(worker.connection, worker.name)
    assert worker.connection.hgetall(worker.key) == before


def test_redis_unavailable_is_unhealthy():
    with Redis.from_url(
        "redis://127.0.0.1:1/0",
        socket_connect_timeout=1,
        socket_timeout=1,
        retry=Retry(NoBackoff(), 0),
    ) as connection:
        assert not health.worker_is_healthy(connection, "unreachable")


@pytest.mark.parametrize("age", [0, -1, True])
def test_invalid_heartbeat_threshold_is_unhealthy(registered_worker, age):
    worker = registered_worker
    assert not health.worker_is_healthy(
        worker.connection, worker.name, max_heartbeat_age_seconds=age
    )


@pytest.mark.parametrize("configured", [None, "", "   "])
def test_health_cli_requires_its_own_worker_name(monkeypatch, configured):
    if configured is None:
        monkeypatch.delenv("RQ_WORKER_NAME", raising=False)
    else:
        monkeypatch.setenv("RQ_WORKER_NAME", configured)
    monkeypatch.delenv("REDIS_URL", raising=False)
    with pytest.raises(SystemExit) as error:
        health.main()
    assert error.value.code == 1


@pytest.mark.parametrize("matches, expected_exit", [(True, 0), (False, 1)])
def test_health_cli_checks_configured_registration(
    registered_worker, monkeypatch, matches, expected_exit
):
    worker = registered_worker
    monkeypatch.setattr(health, "get_redis_connection", lambda: worker.connection)
    name = worker.name if matches else "missing_" + uuid4().hex
    monkeypatch.setenv("RQ_WORKER_NAME", name)
    with pytest.raises(SystemExit) as error:
        health.main()
    assert error.value.code == expected_exit


def test_health_cli_does_not_expose_bad_connection_configuration(monkeypatch, capsys):
    monkeypatch.setenv("RQ_WORKER_NAME", "configured-worker")
    monkeypatch.setenv("REDIS_URL", "redis://user:private-password@host:bad-port/0")
    with pytest.raises(SystemExit) as error:
        health.main()
    assert error.value.code == 1
    output = capsys.readouterr()
    assert "private-password" not in output.out + output.err
