import json
from importlib import import_module
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas import ScanSubmission
from app.persistence.models import Finding, Image, Scan
from app.registries.docker_hub import RegistryRequestError
from app.scanning.trivy.process_runner import ProcessExecutionError
from app.scanning.trivy.sbom import SbomOutcome
from tests.database_support import isolated_repository_engine

DIGEST = "sha256:" + "a" * 64
PINNED = f"docker.io/library/alpine@{DIGEST}"
SUBMISSION = ScanSubmission(image_reference="docker.io/library/alpine:3.20")


def report_text(with_findings=True):
    fixture = Path(__file__).parent / "fixtures" / "trivy" / "findings.json"
    report = json.loads(fixture.read_text())
    report["Metadata"] = {
        "RepoDigests": [PINNED],
        "ImageConfig": {"os": "linux", "architecture": "amd64"},
    }
    if not with_findings:
        report["Results"] = []
    return json.dumps(report)


def prepare_scanner(monkeypatch, raw_report):
    workflow = import_module("app.scanning.workflow")

    def resolve(reference):
        assert reference == SUBMISSION.image_reference
        return PINNED

    def scan(reference):
        assert reference == PINNED
        return raw_report

    monkeypatch.setattr(workflow, "resolve_docker_tag", resolve)
    monkeypatch.setattr(workflow, "run_trivy_scan", scan)
    monkeypatch.setattr(
        workflow, "read_trivy_database_metadata", lambda version: None, raising=False
    )
    monkeypatch.setattr(
        workflow,
        "collect_sbom",
        lambda *args, **kwargs: SbomOutcome(None, "sbom_unavailable"),
        raising=False,
    )
    return workflow


@pytest.mark.parametrize("with_findings", [True, False])
def test_collects_a_report_matching_the_resolved_image(monkeypatch, with_findings):
    workflow = prepare_scanner(monkeypatch, report_text(with_findings))
    result = workflow.collect_trivy_result(SUBMISSION)
    assert result.pinned_reference == PINNED
    assert result.metadata.reported_digest == DIGEST
    assert result.metadata.platform == "linux/amd64"
    assert result.metadata.scanner_version == "0.75.0"
    assert len(result.findings) == (3 if with_findings else 0)


@pytest.mark.parametrize(
    "process_code,scan_code",
    [
        ("timeout", "scanner_timeout"),
        ("unavailable", "scanner_unavailable"),
        ("execution_failed", "scanner_failed"),
        ("output_limit", "output_limit"),
        ("invalid_output", "invalid_report"),
    ],
)
def test_translates_process_errors_to_safe_scan_codes(
    monkeypatch, process_code, scan_code
):
    workflow = prepare_scanner(monkeypatch, report_text())

    def fail(reference):
        raise ProcessExecutionError(process_code)

    monkeypatch.setattr(workflow, "run_trivy_scan", fail)
    with pytest.raises(workflow.ScanWorkflowError) as error:
        workflow.collect_trivy_result(SUBMISSION)
    assert error.value.code == scan_code


@pytest.mark.parametrize("with_findings", [True, False])
def test_workflow_saves_real_results_visible_from_another_session(
    monkeypatch, with_findings
):
    workflow = prepare_scanner(monkeypatch, report_text(with_findings))
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = workflow.perform_trivy_scan(session, SUBMISSION)
            assert not session.in_transaction()
        with Session(engine) as session:
            stored = session.get(Scan, scan_id)
            assert stored.status == "completed"
            assert stored.scanner_version == "0.75.0"
            assert session.get(Image, stored.image_id).digest == DIGEST
            assert session.scalar(
                select(func.count())
                .select_from(Finding)
                .where(Finding.scan_id == scan_id)
            ) == (3 if with_findings else 0)


def test_running_attempt_is_committed_before_network_work(monkeypatch):
    workflow = prepare_scanner(monkeypatch, report_text(False))
    with isolated_repository_engine() as engine:
        with Session(engine) as session:

            def observe_attempt(reference):
                assert not session.in_transaction()
                with Session(engine) as observer:
                    attempt = observer.scalars(select(Scan)).one()
                    assert attempt.status == "running"
                    assert attempt.submitted_reference == reference
                return PINNED

            monkeypatch.setattr(workflow, "resolve_docker_tag", observe_attempt)
            scan_id = workflow.perform_trivy_scan(session, SUBMISSION)
        with Session(engine) as observer:
            assert observer.get(Scan, scan_id).status == "completed"


@pytest.mark.parametrize(
    "failure_kind,error_code",
    [
        ("resolution", "resolution_failed"),
        ("timeout", "scanner_timeout"),
        ("malformed", "invalid_report"),
        ("mismatch", "invalid_report"),
    ],
)
def test_expected_external_failures_are_saved_with_safe_details(
    monkeypatch, failure_kind, error_code
):
    workflow = prepare_scanner(monkeypatch, report_text())
    if failure_kind == "resolution":

        def missing(reference):
            raise RegistryRequestError("not_found")

        monkeypatch.setattr(workflow, "resolve_docker_tag", missing)
    elif failure_kind == "timeout":

        def timeout(reference):
            raise ProcessExecutionError("timeout")

        monkeypatch.setattr(workflow, "run_trivy_scan", timeout)
    else:
        raw = (
            "secret-token invalid JSON"
            if failure_kind == "malformed"
            else report_text().replace(DIGEST, "sha256:" + "b" * 64)
        )
        monkeypatch.setattr(workflow, "run_trivy_scan", lambda reference: raw)
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = workflow.perform_trivy_scan(session, SUBMISSION)
        with Session(engine) as session:
            stored = session.get(Scan, scan_id)
            assert stored.status == "failed"
            assert stored.error_details.startswith(error_code + ": ")
            assert "secret-token" not in stored.error_details
            assert stored.completed_at is not None
            assert stored.image_id is None
            assert session.scalar(select(func.count()).select_from(Finding)) == 0


def test_failed_completion_is_rolled_back_then_recorded_as_failure(monkeypatch):
    report = json.loads(report_text())
    duplicates = report["Results"][0]["Vulnerabilities"]
    duplicates.append(duplicates[0].copy())
    workflow = prepare_scanner(monkeypatch, json.dumps(report))
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = workflow.perform_trivy_scan(session, SUBMISSION)
        with Session(engine) as session:
            stored = session.get(Scan, scan_id)
            assert stored.status == "failed"
            assert stored.error_details.startswith("persistence_failed: ")
            assert stored.image_id is None
            assert stored.scanner_version is None
            assert session.scalar(select(func.count()).select_from(Finding)) == 0
            assert session.scalar(select(func.count()).select_from(Image)) == 0


def test_workflow_collects_and_persists_database_metadata(monkeypatch):
    workflow = prepare_scanner(monkeypatch, report_text(False))
    fixture = Path(__file__).parent / "fixtures" / "trivy" / "version_info.json"
    expected = json.loads(fixture.read_text())["VulnerabilityDB"]

    def version_information(expected_version):
        assert expected_version == "0.75.0"
        return expected.copy()

    monkeypatch.setattr(
        workflow, "read_trivy_database_metadata", version_information, raising=False
    )
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = workflow.perform_trivy_scan(session, SUBMISSION)
        with Session(engine) as session:
            assert session.get(Scan, scan_id).scanner_database_metadata == expected


def test_optional_metadata_unavailable_does_not_fail_a_successful_scan(monkeypatch):
    workflow = prepare_scanner(monkeypatch, report_text(False))
    attempted_versions = []

    def unavailable(expected_version):
        attempted_versions.append(expected_version)
        return None

    monkeypatch.setattr(
        workflow, "read_trivy_database_metadata", unavailable, raising=False
    )
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = workflow.perform_trivy_scan(session, SUBMISSION)
        with Session(engine) as session:
            stored = session.get(Scan, scan_id)
            assert stored.status == "completed"
            assert stored.error_details is None
            assert stored.scanner_database_metadata is None
    assert attempted_versions == ["0.75.0"]


def test_incomplete_registry_response_becomes_a_durable_failed_attempt(monkeypatch):
    import io
    from http.client import HTTPResponse

    registry = import_module("app.registries.docker_hub")
    workflow = import_module("app.scanning.workflow")

    class SampleSocket:
        def makefile(self, mode):
            return io.BytesIO(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nabc"
            )

    class TruncatedTransport:
        def open(self, request, timeout):
            response = HTTPResponse(SampleSocket())
            response.begin()
            return response

    monkeypatch.setattr(
        registry, "build_opener", lambda *handlers: TruncatedTransport()
    )
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            scan_id = workflow.perform_trivy_scan(session, SUBMISSION)
        with Session(engine) as session:
            stored = session.get(Scan, scan_id)
            assert stored.status == "failed"
            assert stored.error_details.startswith("resolution_failed: ")
            assert stored.completed_at is not None
            assert stored.image_id is None
