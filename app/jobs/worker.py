"""Run the background scan worker using the application's Redis settings."""

import argparse

from rq import SpawnWorker

from app.jobs.connection import get_redis_connection, get_scan_queue


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the ContainerGuard scan worker")
    parser.add_argument(
        "--burst",
        action="store_true",
        help="Process waiting jobs, then exit when the queue is empty",
    )
    args = parser.parse_args()

    with get_redis_connection() as connection:
        worker = SpawnWorker(
            [get_scan_queue(connection)],
            connection=connection,
        )
        worker.work(burst=args.burst, with_scheduler=True)


if __name__ == "__main__":
    main()
