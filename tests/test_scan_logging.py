import io
import json
import logging
from types import SimpleNamespace

import pytest
from sqlalchemy.orm import Session

from app.api.schemas import ScanSubmission
from app.jobs import tasks
from app.logging_config import JsonFormatter
from app.persistence import repository
from app.persistence.models import Scan
from app.scanning import workflow
from app.scanning.trivy.parser import ParsedScanMetadata
from tests.database_support import isolated_repository_engine

SUBMISSION = ScanSubmission(image_reference="docker.io/library/alpine:3.20")
DIGEST = "sha256:" + "a" * 64


@pytest.fixture
def recorded_job(monkeypatch):
    logger = logging.getLogger("app")
    previous = logger.handlers[:], logger.level, logger.propagate
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        with isolated_repository_engine() as engine:
            monkeypatch.setattr(tasks, "get_engine", lambda: engine)
            with Session(engine) as session:
                scan_id = repository.create_queued_trivy_scan(session, SUBMISSION)
            monkeypatch.setattr(
                tasks,
                "get_current_job",
                lambda: SimpleNamespace(id=str(scan_id), retries_left=1),
            )
            yield engine, scan_id, stream
    finally:
        for current in logger.handlers:
            if current not in previous[0]:
                current.close()
        logger.handlers, logger.level, logger.propagate = previous


@pytest.mark.parametrize(
    "outcome, event, status, error_code",
    [
        ("success", "scan_completed", "completed", None),
        ("permanent", "scan_failed", "failed", "scanner_failed"),
        ("retry", "scan_retry_queued", "queued", "scanner_timeout"),
        ("invalid", "scan_failed", "failed", "invalid_report"),
    ],
)
def test_job_logs_correlate_with_the_saved_scan_outcome(
    recorded_job, monkeypatch, outcome, event, status, error_code
):
    engine, scan_id, stream = recorded_job

    def collect(submission):
        if outcome == "permanent":
            raise workflow.ScanWorkflowError("scanner_failed")
        if outcome == "retry":
            raise workflow.ScanWorkflowError("scanner_timeout", retryable=True)
        if outcome == "invalid":
            raise ValueError("private-password and raw scanner output")
        return workflow.TrivyResult(
            pinned_reference=f"docker.io/library/alpine@{DIGEST}",
            metadata=ParsedScanMetadata(
                image_reference=SUBMISSION.image_reference,
                reported_digest=DIGEST,
                platform="linux/amd64",
                scanner_version="0.75.0",
            ),
            findings=[],
        )

    monkeypatch.setattr(workflow, "collect_trivy_result", collect)
    if outcome == "retry":
        with pytest.raises(workflow.ScanWorkflowError):
            tasks.run_scan(str(scan_id))
    else:
        tasks.run_scan(str(scan_id))
    output = stream.getvalue()
    records = [json.loads(line) for line in output.splitlines()]
    events = [record["message"] for record in records]
    assert "job_started" in events
    assert "scan_started" in events
    assert event in events
    assert all(record["scan_id"] == str(scan_id) for record in records)
    assert all(record["job_id"] == str(scan_id) for record in records)
    if error_code:
        outcome_record = next(
            record for record in records if record["message"] == event
        )
        assert outcome_record["error_code"] == error_code
    assert "private-password" not in output
    assert "raw scanner output" not in output
    assert SUBMISSION.image_reference not in output
    with Session(engine) as observer:
        assert observer.get(Scan, scan_id).status == status
