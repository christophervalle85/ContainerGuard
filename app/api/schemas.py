from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ScanSubmission(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    image_reference: str = Field(min_length=1, max_length=512)


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanAccepted(BaseModel):
    scan_id: UUID
    status: ScanStatus
    status_url: str


class ScanRecord(BaseModel):
    scan_id: UUID
    image_reference: str
    status: ScanStatus


class ScanDetails(ScanRecord):
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    digest: str | None
    platform: str | None
    scanner_name: str | None
    scanner_version: str | None
    scanner_database_metadata: dict | None
    error_details: str | None
    mock: bool


class ScanHistory(BaseModel):
    items: list[ScanRecord]
    total: int
    limit: int
    offset: int


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Finding(BaseModel):
    vulnerability_id: str
    package_name: str
    installed_version: str
    fixed_version: str | None
    severity: Severity
    title: str


class FindingPage(BaseModel):
    items: list[Finding]
    total: int
    limit: int
    offset: int
    mock: bool


class ErrorResponse(BaseModel):
    detail: str
