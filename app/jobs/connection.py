import os

from redis import Redis
from rq import Queue


def get_redis_connection() -> Redis:
    url = os.environ.get("REDIS_URL", "").strip()
    if not url:
        raise ValueError("REDIS_URL must be configured")

    return Redis.from_url(
        url,
        socket_connect_timeout=5,
        socket_timeout=5,
    )


def get_scan_queue(connection: Redis) -> Queue:
    return Queue(
        "scans",
        connection=connection,
        default_timeout=600,
    )
