from uuid import UUID

from rq import get_current_job
from sqlalchemy.orm import Session

from app.persistence.database import get_engine
from app.scanning.workflow import process_queued_trivy_scan


def run_scan(scan_id: str) -> str:
    parsed_id = UUID(scan_id)
    job = get_current_job()
    allow_retry = job is not None and (job.retries_left or 0) > 0

    with Session(get_engine()) as session:
        result_id = process_queued_trivy_scan(
            session,
            parsed_id,
            allow_retry=allow_retry,
        )

    return str(result_id)
