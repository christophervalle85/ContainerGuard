"""Read the registration and heartbeat of one configured scan worker."""

import os
from datetime import UTC, datetime

from redis import Redis
from redis.exceptions import RedisError
from rq import Worker
from rq.utils import utcparse

from app.jobs.connection import get_redis_connection


def worker_is_healthy(
    connection: Redis, worker_name: str, *, max_heartbeat_age_seconds: int = 120
) -> bool:
    if (
        not isinstance(worker_name, str)
        or not worker_name.strip()
        or type(max_heartbeat_age_seconds) is not int
        or max_heartbeat_age_seconds <= 0
    ):
        return False

    key = Worker.redis_worker_namespace_prefix + worker_name.strip()
    try:
        with connection.pipeline(transaction=False) as pipeline:
            pipeline.hgetall(key)
            pipeline.sismember(Worker.redis_workers_keys, key)
            raw, registered = pipeline.execute()
        data = {
            k.decode() if isinstance(k, bytes) else k: (
                v.decode() if isinstance(v, bytes) else v
            )
            for k, v in raw.items()
        }
        if (
            not registered
            or "death" in data
            or data.get("state") not in {"idle", "busy"}
        ):
            return False
        if not data.get("last_heartbeat"):
            return False
        heartbeat = utcparse(data["last_heartbeat"])
        age = (datetime.now(UTC) - heartbeat).total_seconds()
        return 0 <= age <= max_heartbeat_age_seconds
    except RedisError, ValueError, TypeError:
        return False


def main() -> None:
    name = os.environ.get("RQ_WORKER_NAME", "").strip()
    healthy = False
    if name:
        try:
            with get_redis_connection() as connection:
                healthy = worker_is_healthy(connection, name)
        except RedisError, ValueError:
            pass
    print("Worker health:", "healthy" if healthy else "unhealthy")
    raise SystemExit(0 if healthy else 1)


if __name__ == "__main__":
    main()
