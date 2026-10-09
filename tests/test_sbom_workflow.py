from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.jobs import tasks
from app.persistence import repository
from app.persistence.models import Finding, Image, SbomArtifact, Scan
from app.scanning import workflow
from app.scanning.trivy.parser import ParsedScanMetadata
from app.scanning.trivy.process_runner import ProcessExecutionError
from app.scanning.trivy.sbom import SbomOutcome, parse_sbom
from tests.database_support import isolated_repository_engine
from tests.test_scan_workflow import DIGEST, SUBMISSION, prepare_scanner, report_text

PINNED = (
    "docker.io/library/alpine@sha256:"
    "216266c86fc4dcef5619930bd394245824c2af52fd21ba7c6fa0e618657d4c3b"
)


def available():
    return SbomOutcome(
        parse_sbom(
            Path("tests/fixtures/trivy/cyclonedx.json").read_bytes(),
            pinned_reference=PINNED,
            platform="linux/amd64",
            scanner_version="0.75.0",
        ),
        None,
    )


def setup_collection(monkeypatch, outcome):
    prepare_scanner(monkeypatch, report_text().replace(DIGEST, PINNED.split("@")[1]))
    calls = []

    def resolve(reference):
        calls.append(("resolve", reference))
        return PINNED

    def scan(reference):
        calls.append(("scan", reference))
        return report_text().replace(DIGEST, PINNED.split("@")[1])

    def sbom(reference, *, platform, scanner_version):
        calls.append(("sbom", reference, platform, scanner_version))
        return outcome

    monkeypatch.setattr(workflow, "resolve_docker_tag", resolve)
    monkeypatch.setattr(workflow, "run_trivy_scan", scan)
    monkeypatch.setattr(workflow, "collect_sbom", sbom, raising=False)
    return calls


def test_collection_resolves_once_and_returns_sbom_for_identical_image(monkeypatch):
    outcome = available()
    calls = setup_collection(monkeypatch, outcome)
    result = workflow.collect_trivy_result(SUBMISSION)
    assert result.sbom_outcome == outcome
    assert calls == [
        ("resolve", SUBMISSION.image_reference),
        ("scan", PINNED),
        ("sbom", PINNED, "linux/amd64", "0.75.0"),
    ]


@pytest.mark.parametrize("kind", ["timeout", "invalid-report", "wrong-digest"])
def test_vulnerability_failure_never_generates_sbom(monkeypatch, kind):
    calls = setup_collection(monkeypatch, available())

    def fail(reference):
        if kind == "timeout":
            raise ProcessExecutionError("timeout")
        if kind == "wrong-digest":
            return report_text()
        return "invalid report"

    monkeypatch.setattr(workflow, "run_trivy_scan", fail)
    with pytest.raises(workflow.ScanWorkflowError):
        workflow.collect_trivy_result(SUBMISSION)
    assert not any(call[0] == "sbom" for call in calls)


@pytest.mark.parametrize(
    "code",
    [
        "sbom_timeout",
        "sbom_unavailable",
        "sbom_execution_failed",
        "sbom_output_limit",
        "sbom_invalid_report",
    ],
)
def test_sbom_failure_preserves_completed_findings_without_job_retry(monkeypatch, code):
    calls = setup_collection(monkeypatch, SbomOutcome(None, code))
    with isolated_repository_engine() as engine:
        monkeypatch.setattr(tasks, "get_engine", lambda: engine)
        monkeypatch.setattr(
            tasks, "get_current_job", lambda: SimpleNamespace(id="test", retries_left=2)
        )
        with Session(engine) as session:
            scan_id = repository.create_queued_trivy_scan(session, SUBMISSION)
        assert tasks.run_scan(str(scan_id)) == str(scan_id)
        with Session(engine) as observer:
            scan = observer.get(Scan, scan_id)
            assert scan.status == "completed" and scan.error_details is None
            assert observer.scalar(select(func.count()).select_from(Finding)) == 3
            row = observer.scalar(select(SbomArtifact))
            assert row.scan_id == scan_id and row.status == "failed"
            assert row.error_code == code and row.payload is None
        assert len([call for call in calls if call[0] == "scan"]) == 1


def test_completion_commits_image_findings_and_artifact_together(monkeypatch):
    outcome = available()
    setup_collection(monkeypatch, outcome)
    with isolated_repository_engine() as engine:
        with Session(engine) as session:

            def sbom(reference, **kwargs):
                assert not session.in_transaction()
                with Session(engine) as observer:
                    assert observer.scalar(select(Scan.status)) == "running"
                    assert (
                        observer.scalar(select(func.count()).select_from(Finding)) == 0
                    )
                    assert (
                        observer.scalar(select(func.count()).select_from(SbomArtifact))
                        == 0
                    )
                return outcome

            monkeypatch.setattr(workflow, "collect_sbom", sbom, raising=False)
            scan_id = workflow.perform_trivy_scan(session, SUBMISSION)
            assert not session.in_transaction()
        with Session(engine) as observer:
            scan = observer.get(Scan, scan_id)
            assert scan.status == "completed"
            assert observer.get(Image, scan.image_id).digest == PINNED.split("@")[1]
            assert observer.scalar(select(func.count()).select_from(Finding)) == 3
            row = observer.scalar(select(SbomArtifact))
            assert row.scan_id == scan_id and row.payload == outcome.artifact.payload
            assert row.sha256 == outcome.artifact.sha256


def test_artifact_insert_failure_rolls_back_entire_completion(monkeypatch):
    setup_collection(monkeypatch, available())
    result = workflow.collect_trivy_result(SUBMISSION)

    def reject(mapper, connection, target):
        raise SQLAlchemyError("private database details")

    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.start_trivy_scan(session, SUBMISSION)
            event.listen(SbomArtifact, "before_insert", reject)
            try:
                with pytest.raises(SQLAlchemyError):
                    repository.complete_trivy_scan(
                        session,
                        scan_id,
                        result.pinned_reference,
                        result.metadata,
                        result.findings,
                        sbom_outcome=result.sbom_outcome,
                    )
            finally:
                event.remove(SbomArtifact, "before_insert", reject)
            assert not session.in_transaction()
        with Session(engine) as observer:
            scan = observer.get(Scan, scan_id)
            assert scan.status == "running" and scan.image_id is None
            assert scan.completed_at is None and scan.scanner_version is None
            for model in (Finding, Image, SbomArtifact):
                assert observer.scalar(select(func.count()).select_from(model)) == 0


def test_terminal_redelivery_cannot_replace_artifact(monkeypatch):
    outcome = available()
    calls = setup_collection(monkeypatch, outcome)
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = repository.create_queued_trivy_scan(session, SUBMISSION)
            workflow.process_queued_trivy_scan(session, scan_id)
            workflow.process_queued_trivy_scan(session, scan_id)
            with pytest.raises(ValueError, match="running Trivy scan"):
                result = workflow.TrivyResult(
                    PINNED,
                    ParsedScanMetadata(
                        PINNED, PINNED.split("@")[1], "linux/amd64", "0.75.0"
                    ),
                    [],
                )
                repository.complete_trivy_scan(
                    session,
                    scan_id,
                    PINNED,
                    result.metadata,
                    [],
                    sbom_outcome=SbomOutcome(None, "sbom_timeout"),
                )
        with Session(engine) as observer:
            rows = observer.scalars(select(SbomArtifact)).all()
            assert len(rows) == 1
            assert (
                rows[0].status == "available"
                and rows[0].sha256 == outcome.artifact.sha256
            )
        assert len([call for call in calls if call[0] == "sbom"]) == 1
