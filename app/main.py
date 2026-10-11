from contextlib import asynccontextmanager
from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.evaluations import router as evaluation_router
from app.api.policies import router as policy_router
from app.api.sboms import router as sbom_router
from app.api.schemas import (
    ErrorResponse,
    FindingPage,
    ScanAccepted,
    ScanDetails,
    ScanHistory,
    ScanSubmission,
    Severity,
)
from app.jobs import submission as job_submission
from app.logging_config import configure_logging
from app.persistence import repository
from app.persistence.admission import (
    ScanAdmissionUnavailable,
    ScanCapacityExceeded,
    get_max_active_scans,
)
from app.persistence.database import get_session

configure_logging()


@asynccontextmanager
async def lifespan(application: FastAPI):
    get_max_active_scans()
    yield


app = FastAPI(title="ContainerGuard", lifespan=lifespan)
app.include_router(sbom_router)
app.include_router(policy_router)
app.include_router(evaluation_router)

DatabaseSession = Annotated[Session, Depends(get_session)]
DATABASE_ERROR_RESPONSES = {
    503: {
        "model": ErrorResponse,
        "description": "Database temporarily unavailable",
    }
}


@app.exception_handler(RequestValidationError)
async def handle_validation_error(
    request: Request, error: RequestValidationError
) -> JSONResponse:
    # Pydantic input/ctx may contain credentials supplied in a rejected value.
    return JSONResponse(
        status_code=422,
        content={
            "detail": [
                {"loc": item["loc"], "type": item["type"], "msg": "Invalid value"}
                for item in error.errors()
            ]
        },
    )


@app.exception_handler(SQLAlchemyError)
async def handle_database_error(
    request: Request, error: SQLAlchemyError
) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"detail": "Database temporarily unavailable"},
    )


@app.exception_handler(ScanCapacityExceeded)
async def handle_capacity_error(
    request: Request, error: ScanCapacityExceeded
) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={"detail": "Scan queue is full. Try again shortly."},
        headers={"Retry-After": "30"},
    )


@app.exception_handler(ScanAdmissionUnavailable)
async def handle_admission_error(
    request: Request, error: ScanAdmissionUnavailable
) -> JSONResponse:
    return JSONResponse(
        status_code=503, content={"detail": "Scan admission temporarily unavailable"}
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
    return {"status": "broken-for-ci-demonstration"}


@app.post(
    "/api/v1/scans",
    status_code=202,
    response_model=ScanAccepted,
    responses={
        429: {
            "model": ErrorResponse,
            "description": "Outstanding scan capacity reached",
        },
        503: {
            "model": ErrorResponse,
            "description": "Database or scan queue temporarily unavailable",
        },
    },
)
def submit_scan(
    submission: ScanSubmission,
    session: DatabaseSession,
) -> ScanAccepted:
    return job_submission.submit_scan(session, submission)


@app.get(
    "/api/v1/scans/{scan_id}",
    response_model=ScanDetails,
    responses={
        404: {"model": ErrorResponse, "description": "Scan not found"},
        **DATABASE_ERROR_RESPONSES,
    },
)
def get_scan(scan_id: UUID, session: DatabaseSession) -> ScanDetails:
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
