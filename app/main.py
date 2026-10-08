from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.schemas import (
    ErrorResponse,
    FindingPage,
    ScanAccepted,
    ScanHistory,
    ScanRecord,
    ScanSubmission,
    Severity,
)
from app.jobs import submission as job_submission
from app.logging_config import configure_logging
from app.persistence import repository
from app.persistence.database import get_session

configure_logging()

app = FastAPI(title="ContainerGuard")

DatabaseSession = Annotated[Session, Depends(get_session)]
DATABASE_ERROR_RESPONSES = {
    503: {
        "model": ErrorResponse,
        "description": "Database temporarily unavailable",
    }
}


@app.exception_handler(SQLAlchemyError)
async def handle_database_error(
    request: Request, error: SQLAlchemyError
) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"detail": "Database temporarily unavailable"},
    )


@app.exception_handler(job_submission.ScanQueueUnavailable)
async def handle_queue_error(
    request: Request, error: job_submission.ScanQueueUnavailable
) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"detail": "Scan queue temporarily unavailable"},
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/api/v1/scans",
    status_code=202,
    response_model=ScanAccepted,
    responses={
        503: {
            "model": ErrorResponse,
            "description": "Database or scan queue temporarily unavailable",
        }
    },
)
def submit_scan(
    submission: ScanSubmission,
    session: DatabaseSession,
) -> ScanAccepted:
    return job_submission.submit_scan(session, submission)


@app.get(
    "/api/v1/scans/{scan_id}",
    response_model=ScanRecord,
    responses={
        404: {"model": ErrorResponse, "description": "Scan not found"},
        **DATABASE_ERROR_RESPONSES,
    },
)
def get_scan(scan_id: UUID, session: DatabaseSession) -> ScanRecord:
    scan = repository.get_scan(session, scan_id)

    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan


@app.get(
    "/api/v1/scans",
    response_model=ScanHistory,
    responses=DATABASE_ERROR_RESPONSES,
)
def list_scans(
    session: DatabaseSession,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> ScanHistory:
    return repository.get_scan_history(session, limit=limit, offset=offset)


@app.get(
    "/api/v1/scans/{scan_id}/findings",
    response_model=FindingPage,
    responses={
        404: {"model": ErrorResponse, "description": "Scan not found"},
        **DATABASE_ERROR_RESPONSES,
    },
)
def list_findings(
    scan_id: UUID,
    session: DatabaseSession,
    severity: Severity | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> FindingPage:
    page = repository.get_scan_findings(
        session,
        scan_id,
        limit=limit,
        offset=offset,
        severity=severity,
    )

    if page is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return page
