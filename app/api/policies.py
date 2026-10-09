"""Create policies and retrieve their immutable version history."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.schemas import ErrorResponse
from app.persistence import policies
from app.persistence.database import get_session
from app.policies.schemas import (
    PolicyCreate,
    PolicyPage,
    PolicyVersionCreate,
    PolicyVersionPage,
    PolicyVersionRecord,
)

router = APIRouter(prefix="/api/v1/policies", tags=["Policies"])
DatabaseSession = Annotated[Session, Depends(get_session)]
_DATABASE_ERRORS = {
    503: {"model": ErrorResponse, "description": "Database temporarily unavailable"}
}
_PARENT_ERRORS = {
    404: {"model": ErrorResponse, "description": "Policy not found"},
    **_DATABASE_ERRORS,
}


@router.post(
    "",
    status_code=201,
    response_model=PolicyVersionRecord,
    responses={
        409: {"model": ErrorResponse, "description": "Policy name already exists"},
        **_DATABASE_ERRORS,
    },
)
def create_policy(body: PolicyCreate, session: DatabaseSession) -> PolicyVersionRecord:
    try:
        return policies.create_policy(session, body.name, body.rules)
    except policies.PolicyNameConflict:
        raise HTTPException(
            status_code=409, detail="Policy name already exists"
        ) from None


@router.get("", response_model=PolicyPage, responses=_DATABASE_ERRORS)
def list_policies(
    session: DatabaseSession,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> PolicyPage:
    return policies.list_policies(session, limit=limit, offset=offset)


@router.post(
    "/{policy_id}/versions",
    status_code=201,
    response_model=PolicyVersionRecord,
    responses=_PARENT_ERRORS,
)
def create_version(
    policy_id: UUID, body: PolicyVersionCreate, session: DatabaseSession
) -> PolicyVersionRecord:
    try:
        return policies.create_policy_version(session, policy_id, body.rules)
    except policies.PolicyNotFound:
        raise HTTPException(status_code=404, detail="Policy not found") from None


@router.get(
    "/{policy_id}/versions", response_model=PolicyVersionPage, responses=_PARENT_ERRORS
)
def list_versions(
    policy_id: UUID,
    session: DatabaseSession,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> PolicyVersionPage:
    try:
        return policies.list_policy_versions(
            session, policy_id, limit=limit, offset=offset
        )
    except policies.PolicyNotFound:
        raise HTTPException(status_code=404, detail="Policy not found") from None
