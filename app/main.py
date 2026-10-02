from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException, Query

from app.mock_scanner import build_mock_findings
from app.schemas import (
    FindingPage,
    ScanAccepted,
    ScanHistory,
    ScanRecord,
    ScanSubmission,
    Severity,
)
from app.store import findings, scans

app = FastAPI(title="ContainerGuard")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/scans", status_code=202, response_model=ScanAccepted)
def submit_scan(submission: ScanSubmission) -> ScanAccepted:
    scan_id = uuid4()
    scans[scan_id] = ScanRecord(
        scan_id=scan_id,
        image_reference=submission.image_reference,
        status="completed",
    )

    findings[scan_id] = build_mock_findings()
    return ScanAccepted(
        scan_id=scan_id,
        status="completed",
        status_url=f"/api/v1/scans/{scan_id}",
    )


@app.get("/api/v1/scans/{scan_id}", response_model=ScanRecord)
def get_scan(scan_id: UUID) -> ScanRecord:
    scan = scans.get(scan_id)

    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan


@app.get("/api/v1/scans", response_model=ScanHistory)
def list_scans(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> ScanHistory:
    records = list(reversed(list(scans.values())))

    return ScanHistory(
        items=records[offset : offset + limit],
        total=len(records),
        limit=limit,
        offset=offset,
    )


@app.get("/api/v1/scans/{scan_id}/findings", response_model=FindingPage)
def list_findings(
    scan_id: UUID,
    severity: Severity | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> FindingPage:
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    records = findings[scan_id]

    if severity is not None:
        records = [item for item in records if item.severity == severity]

    return FindingPage(
        items=records[offset : offset + limit],
        total=len(records),
        limit=limit,
        offset=offset,
    )
