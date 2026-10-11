"""Run the background scan worker using the application's Redis settings."""

import argparse
import os

from rq import SpawnWorker

from app.jobs.connection import get_redis_connection, get_scan_queue
from app.logging_config import configure_logging
from app.persistence.admission import get_max_active_scans


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the ContainerGuard scan worker")
    parser.add_argument(
        "--burst",
        action="store_true",
        help="Process waiting jobs, then exit when the queue is empty",
    )
    args = parser.parse_args()
    get_max_active_scans()
    configure_logging()

    with get_redis_connection() as connection:
        worker = SpawnWorker(
            [get_scan_queue(connection)],
            connection=connection,
            name=os.environ.get("RQ_WORKER_NAME", "").strip() or None,
            # Idle dequeue waits 75 seconds; busy jobs heartbeat every 30 seconds.
            # Both fit within the health probe's 120-second freshness window.
            worker_ttl=90,
        )
        worker.work(burst=args.burst, with_scheduler=True)


if __name__ == "__main__":
    main()
