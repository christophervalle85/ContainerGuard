import logging
from uuid import UUID

from redis.exceptions import RedisError
from rq import Retry
from rq.exceptions import DuplicateJobError
from sqlalchemy.orm import Session

from app.api.schemas import ScanAccepted, ScanSubmission
from app.jobs.connection import get_redis_connection, get_scan_queue
from app.jobs.tasks import run_scan
from app.persistence import repository


def enqueue_scan(scan_id: UUID) -> str:
    with get_redis_connection() as connection:
        queue = get_scan_queue(connection)
        job = queue.enqueue(
            run_scan,
            str(scan_id),
            job_id=str(scan_id),
            unique=True,
            result_ttl=3600,
            retry=Retry(max=2, interval=[5, 15]),
        )

    return job.id


logger = logging.getLogger(__name__)


class ScanQueueUnavailable(RuntimeError):
    pass


def submit_scan(session: Session, submission: ScanSubmission) -> ScanAccepted:
    scan_id = repository.create_queued_trivy_scan(session, submission)

    try:
        job_id = enqueue_scan(scan_id)
    except RedisError, DuplicateJobError, ValueError:
        repository.fail_queued_scan(session, scan_id)
        logger.warning(
            "enqueue_failed",
            extra={"scan_id": str(scan_id), "job_id": str(scan_id)},
        )
        raise ScanQueueUnavailable("Scan queue temporarily unavailable") from None

    logger.info("scan_queued", extra={"scan_id": str(scan_id), "job_id": job_id})

    return ScanAccepted(
        scan_id=scan_id,
        status="queued",
        status_url=f"/api/v1/scans/{scan_id}",
    )
