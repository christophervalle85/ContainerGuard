"""Evaluate explicit policy versions and retrieve saved scan decisions."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.schemas import ErrorResponse
from app.persistence import evaluations
from app.persistence.database import get_session
from app.policies.schemas import EvaluationPage, EvaluationRecord, EvaluationRequest

router = APIRouter(prefix="/api/v1/scans", tags=["Evaluations"])
DatabaseSession = Annotated[Session, Depends(get_session)]
_ERROR_RESPONSES = {
    404: {"model": ErrorResponse, "description": "Scan or policy version not found"},
    503: {"model": ErrorResponse, "description": "Database temporarily unavailable"},
}


@router.post(
    "/{scan_id}/evaluations",
    response_model=EvaluationRecord,
    responses={
        409: {
            "model": ErrorResponse,
            "description": "Scan is ineligible for evaluation",
        },
        **_ERROR_RESPONSES,
    },
)
def evaluate(
    scan_id: UUID, body: EvaluationRequest, session: DatabaseSession
) -> EvaluationRecord:
    try:
        return evaluations.evaluate_scan(session, scan_id, body.policy_version_id)
    except evaluations.ScanNotFound:
        raise HTTPException(status_code=404, detail="Scan not found") from None
    except evaluations.PolicyVersionNotFound:
        raise HTTPException(
            status_code=404, detail="Policy version not found"
        ) from None
    except evaluations.IneligibleScan:
        raise HTTPException(
            status_code=409,
            detail="Evaluation requires a completed real scan with image identity",
        ) from None


@router.get(
    "/{scan_id}/evaluations", response_model=EvaluationPage, responses=_ERROR_RESPONSES
)
def list_saved(
    scan_id: UUID,
    session: DatabaseSession,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> EvaluationPage:
    try:
        return evaluations.list_evaluations(
            session, scan_id, limit=limit, offset=offset
        )
    except evaluations.ScanNotFound:
        raise HTTPException(status_code=404, detail="Scan not found") from None
