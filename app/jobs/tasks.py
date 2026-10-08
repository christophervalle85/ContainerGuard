import logging
from uuid import UUID

from rq import get_current_job
from sqlalchemy.orm import Session

from app.logging_config import bind_scan_context, configure_logging
from app.persistence.database import get_engine
from app.scanning.workflow import ScanWorkflowError, process_queued_trivy_scan

logger = logging.getLogger(__name__)


def run_scan(scan_id: str) -> str:
    parsed_id = UUID(scan_id)
    # SpawnWorker starts a fresh interpreter; configure logging in that child too.
    configure_logging()
    job = get_current_job()
    allow_retry = job is not None and (job.retries_left or 0) > 0

    with bind_scan_context(str(parsed_id), job.id if job is not None else None):
        logger.info("job_started")
        try:
            with Session(get_engine()) as session:
                result_id = process_queued_trivy_scan(
                    session,
                    parsed_id,
                    allow_retry=allow_retry,
                )
        except ScanWorkflowError:
            logger.info("job_retry_requested")
            raise
        except Exception:
            logger.error("job_interrupted")
            raise
        logger.info("job_finished")
        return str(result_id)
