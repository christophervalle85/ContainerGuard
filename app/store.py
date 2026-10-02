from uuid import UUID

from app.schemas import Finding, ScanRecord

# M1 only: records disappear when this process stops.
scans: dict[UUID, ScanRecord] = {}

findings: dict[UUID, list[Finding]] = {}
