"""Metadata for an image SBOM; payload bytes are downloaded separately."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel


class SbomMetadata(BaseModel):
    scan_id: UUID
    status: Literal["pending", "not_generated", "available", "failed"]
    format: str | None = None
    format_version: str | None = None
    scanner_version: str | None = None
    pinned_reference: str | None = None
    digest: str | None = None
    platform: str | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    created_at: datetime | None = None
    error_code: str | None = None
    error_details: str | None = None
