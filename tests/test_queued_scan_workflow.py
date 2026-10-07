import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas import ScanSubmission
from app.persistence import repository
from app.persistence.models import Finding, Image, Scan
from app.scanning import workflow
from app.scanning.trivy.parser import parse_trivy_findings, parse_trivy_metadata
from tests.database_support import isolated_repository_engine

SUBMISSION = ScanSubmission(image_reference="docker.io/library/alpine:3.20")
DIGEST = "sha256:" + "a" * 64
PINNED = f"docker.io/library/alpine@{DIGEST}"


def sample_result(with_findings=True):
    fixture = Path(__file__).parent / "fixtures/trivy/findings.json"
    report = json.loads(fixture.read_text())
    report["Metadata"] = {
        "RepoDigests": [PINNED],
        "ImageConfig": {"os": "linux", "architecture": "amd64"},
    }
    if not with_findings:
        report["Results"] = []
    return workflow.TrivyResult(
        PINNED, parse_trivy_metadata(report), parse_trivy_findings(report)
    )


@pytest.mark.parametrize("with_findings", [True, False])
def test_queued_scan_finishes_the_same_record_and_redelivery_preserves_results(
    monkeypatch, with_findings
):
    attempts = []
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.create_queued_trivy_scan(session, SUBMISSION)

            def collect(submission):
                assert submission == SUBMISSION
                assert not session.in_transaction()
                with Session(engine) as observer:
                    assert observer.get(Scan, scan_id).status == "running"
                attempts.append(submission)
                return sample_result(with_findings)

            monkeypatch.setattr(workflow, "collect_trivy_result", collect)
            assert workflow.process_queued_trivy_scan(session, scan_id) == scan_id
            assert workflow.process_queued_trivy_scan(session, scan_id) == scan_id
        assert len(attempts) == 1
        with Session(engine) as observer:
            stored = observer.get(Scan, scan_id)
            assert stored.status == "completed"
            assert stored.completed_at is not None
            assert stored.scanner_version == "0.75.0"
            assert observer.get(Image, stored.image_id).digest == DIGEST
            assert observer.scalar(select(func.count()).select_from(Scan)) == 1
            assert observer.scalar(select(func.count()).select_from(Finding)) == (
                3 if with_findings else 0
            )


@pytest.mark.parametrize("code", ["resolution_failed", "scanner_timeout"])
def test_queued_scan_saves_expected_failure_on_the_original_record(monkeypatch, code):
    def fail(submission):
        raise workflow.ScanWorkflowError(code)

    monkeypatch.setattr(workflow, "collect_trivy_result", fail)
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.create_queued_trivy_scan(session, SUBMISSION)
            assert workflow.process_queued_trivy_scan(session, scan_id) == scan_id
        with Session(engine) as observer:
            stored = observer.get(Scan, scan_id)
            assert stored.status == "failed"
            assert stored.completed_at is not None
            assert stored.error_details.startswith(code + ": ")
            assert observer.scalar(select(func.count()).select_from(Scan)) == 1
            assert observer.scalar(select(func.count()).select_from(Finding)) == 0


@pytest.mark.parametrize("status", ["running", "failed"])
def test_redelivered_running_or_failed_scan_does_not_call_the_scanner(
    monkeypatch, status
):
    timestamp = datetime(2026, 1, 1, tzinfo=UTC)

    def unexpected(submission):
        raise AssertionError("A redelivered job must not start another scan")

    monkeypatch.setattr(workflow, "collect_trivy_result", unexpected)
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.create_queued_trivy_scan(session, SUBMISSION)
            with session.begin():
                stored = session.get(Scan, scan_id)
                stored.status = status
                stored.started_at = timestamp
                stored.completed_at = timestamp if status == "failed" else None
            assert workflow.process_queued_trivy_scan(session, scan_id) == scan_id
        with Session(engine) as observer:
            stored = observer.get(Scan, scan_id)
            assert stored.status == status
            assert stored.started_at == timestamp


def test_unknown_queued_scan_does_not_call_the_scanner(monkeypatch):
    def unexpected(submission):
        raise AssertionError("An unknown scan must not trigger external work")

    monkeypatch.setattr(workflow, "collect_trivy_result", unexpected)
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            with pytest.raises(ValueError, match="Scan does not exist"):
                workflow.process_queued_trivy_scan(session, uuid4())


def test_queued_completion_write_failure_rolls_back_then_saves_failure(monkeypatch):
    result = sample_result()
    duplicate_result = workflow.TrivyResult(
        result.pinned_reference,
        result.metadata,
        [*result.findings, result.findings[0]],
    )
    monkeypatch.setattr(
        workflow, "collect_trivy_result", lambda submission: duplicate_result
    )
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.create_queued_trivy_scan(session, SUBMISSION)
            assert workflow.process_queued_trivy_scan(session, scan_id) == scan_id
        with Session(engine) as observer:
            stored = observer.get(Scan, scan_id)
            assert stored.status == "failed"
            assert stored.error_details.startswith("persistence_failed: ")
            assert stored.image_id is None
            assert observer.scalar(select(func.count()).select_from(Finding)) == 0
            assert observer.scalar(select(func.count()).select_from(Image)) == 0
