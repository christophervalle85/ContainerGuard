"""Manually recover interrupted scans after stopping all scan worker processes."""

import argparse
import logging
from uuid import UUID

from redis.exceptions import RedisError
from rq import Worker
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.jobs.connection import get_redis_connection, get_scan_queue
from app.jobs.submission import enqueue_scan
from app.logging_config import configure_logging
from app.persistence import repository
from app.persistence.database import get_engine

logger = logging.getLogger(__name__)


def recover_scan(
    session: Session, scan_id: UUID, *, workers_stopped: bool = False
) -> str:
    if not workers_stopped:
        raise ValueError("Stop all scan workers before recovery")

    with get_redis_connection() as connection:
        queue = get_scan_queue(connection)

        if Worker.all(connection=connection, queue=queue):
            raise ValueError("Scan workers are still registered")

        old_job = queue.fetch_job(str(scan_id))
        if old_job is not None:
            if (
                old_job.origin != queue.name
                or old_job.func_name != "app.jobs.tasks.run_scan"
                or old_job.args != (str(scan_id),)
                or old_job.kwargs
            ):
                raise ValueError("Existing job does not match the scan")

        repository.prepare_scan_recovery(
            session,
            scan_id,
            workers_stopped=True,
        )

        if old_job is not None:
            old_job.delete()

        job_id = enqueue_scan(scan_id)

    logger.info("recovery_queued", extra={"scan_id": str(scan_id), "job_id": job_id})
    return job_id


def main() -> None:
    parser = argparse.ArgumentParser(description="Recover a queued or interrupted scan")
    parser.add_argument("scan_id", type=UUID)
    parser.add_argument(
        "--workers-stopped",
        action="store_true",
        required=True,
        help="Confirm all scan workers and their scan subprocesses are stopped",
    )
    args = parser.parse_args()
    configure_logging()
    try:
        with Session(get_engine()) as session:
            job_id = recover_scan(
                session, args.scan_id, workers_stopped=args.workers_stopped
            )
    except ValueError as error:
        parser.exit(2, f"Recovery refused: {error}\n")
    except RedisError, SQLAlchemyError:
        parser.exit(
            1,
            "Recovery could not reach a required service. "
            "Check PostgreSQL and Redis, inspect the scan, "
            "then retry with workers stopped.\n",
        )
    print(f"Scan ID: {args.scan_id}")
    print(f"Job ID: {job_id}")
    print("Status: queued")


if __name__ == "__main__":
    main()
