"""Metadata and verified downloads for saved image SBOMs."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.api.sbom_schemas import SbomMetadata
from app.api.schemas import ErrorResponse
from app.persistence import artifacts
from app.persistence.database import get_session

router = APIRouter(prefix="/api/v1/scans", tags=["SBOMs"])
DatabaseSession = Annotated[Session, Depends(get_session)]
_ERROR_RESPONSES = {
    404: {"model": ErrorResponse, "description": "Scan or available SBOM not found"},
    503: {"model": ErrorResponse, "description": "Database temporarily unavailable"},
}


@router.get(
    "/{scan_id}/sbom/metadata", response_model=SbomMetadata, responses=_ERROR_RESPONSES
)
def get_metadata(scan_id: UUID, session: DatabaseSession) -> SbomMetadata:
    metadata = artifacts.get_sbom_metadata(session, scan_id)
    if metadata is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return metadata


@router.get(
    "/{scan_id}/sbom",
    response_class=Response,
    responses={
        200: {
            "description": "Original CycloneDX JSON attachment",
            "content": {
                "application/json": {"schema": {"type": "string", "format": "binary"}}
            },
        },
        409: {"model": ErrorResponse, "description": "Scan has not finished"},
        500: {
            "model": ErrorResponse,
            "description": "Stored SBOM failed integrity verification",
        },
        **_ERROR_RESPONSES,
    },
)
def download(scan_id: UUID, session: DatabaseSession) -> Response:
    try:
        artifact = artifacts.load_verified_sbom(session, scan_id)
    except artifacts.ScanNotFound:
        raise HTTPException(status_code=404, detail="Scan not found") from None
    except artifacts.SbomNotReady:
        raise HTTPException(status_code=409, detail="Scan has not finished") from None
    except artifacts.SbomUnavailable:
        raise HTTPException(
            status_code=404, detail="No available SBOM for this scan"
        ) from None
    except artifacts.SbomIntegrityError:
        raise HTTPException(
            status_code=500, detail="Stored SBOM failed integrity verification"
        ) from None
    return Response(
        content=artifact.payload,
        media_type="application/json",
        headers={
            "ETag": f'"{artifact.sha256}"',
            "Content-Disposition": f'attachment; filename="{scan_id}.cdx.json"',
        },
    )
