import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas import ScanSubmission
from app.persistence import repository
from app.persistence.models import Scan
from app.scanning import workflow
from app.scanning.trivy.parser import ParsedScanMetadata
from tests.database_support import isolated_repository_engine

SUBMISSION = ScanSubmission(image_reference="docker.io/library/alpine:3.20")
DIGEST = "sha256:" + "a" * 64
PINNED = f"docker.io/library/alpine@{DIGEST}"


def empty_result():
    return workflow.TrivyResult(
        PINNED,
        ParsedScanMetadata(PINNED, DIGEST, "linux/amd64", "0.75.0"),
        [],
    )


@pytest.mark.parametrize("code", ["resolution_failed", "scanner_timeout"])
def test_temporary_failure_requeues_before_raising_and_next_attempt_completes(
    monkeypatch, code
):
    attempts = []

    def collect(submission):
        assert submission == SUBMISSION
        attempts.append(submission)
        if len(attempts) == 1:
            raise workflow.ScanWorkflowError(code, retryable=True)
        return empty_result()

    monkeypatch.setattr(workflow, "collect_trivy_result", collect)
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.create_queued_trivy_scan(session, SUBMISSION)
            with pytest.raises(workflow.ScanWorkflowError) as error:
                workflow.process_queued_trivy_scan(session, scan_id, allow_retry=True)
            assert error.value.retryable is True
            assert not session.in_transaction()
            with Session(engine) as observer:
                stored = observer.get(Scan, scan_id)
                assert stored.status == "queued"
                assert stored.completed_at is None
                assert stored.started_at is None
                assert stored.error_details.startswith(code + ": ")
            assert (
                workflow.process_queued_trivy_scan(session, scan_id, allow_retry=True)
                == scan_id
            )
        assert len(attempts) == 2
        with Session(engine) as observer:
            stored = observer.get(Scan, scan_id)
            assert stored.status == "completed"
            assert stored.error_details is None
            assert stored.completed_at is not None
            assert observer.scalar(select(func.count()).select_from(Scan)) == 1


@pytest.mark.parametrize("code", ["resolution_failed", "invalid_report"])
def test_permanent_failure_is_final_even_when_retries_are_available(monkeypatch, code):
    def fail(submission):
        raise workflow.ScanWorkflowError(code, retryable=False)

    monkeypatch.setattr(workflow, "collect_trivy_result", fail)
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.create_queued_trivy_scan(session, SUBMISSION)
            assert (
                workflow.process_queued_trivy_scan(session, scan_id, allow_retry=True)
                == scan_id
            )
        with Session(engine) as observer:
            stored = observer.get(Scan, scan_id)
            assert stored.status == "failed"
            assert stored.completed_at is not None
            assert stored.error_details.startswith(code + ": ")


@pytest.mark.parametrize("code", ["resolution_failed", "scanner_timeout"])
def test_temporary_failure_is_final_when_retry_budget_is_exhausted(monkeypatch, code):
    def fail(submission):
        raise workflow.ScanWorkflowError(code, retryable=True)

    monkeypatch.setattr(workflow, "collect_trivy_result", fail)
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.create_queued_trivy_scan(session, SUBMISSION)
            assert (
                workflow.process_queued_trivy_scan(session, scan_id, allow_retry=False)
                == scan_id
            )
        with Session(engine) as observer:
            stored = observer.get(Scan, scan_id)
            assert stored.status == "failed"
            assert stored.completed_at is not None
            assert stored.error_details.startswith(code + ": ")
