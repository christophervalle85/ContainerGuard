import pytest

from app.api.schemas import ScanSubmission
from app.registries.docker_hub import RegistryRequestError
from app.scanning import workflow
from app.scanning.trivy.process_runner import ProcessExecutionError

SUBMISSION = ScanSubmission(image_reference="docker.io/library/alpine:3.20")
PINNED = "docker.io/library/alpine@sha256:" + "a" * 64


@pytest.mark.parametrize(
    "code,retryable",
    [
        ("rate_limited", True),
        ("unavailable", True),
        ("not_found", False),
        ("access_denied", False),
        ("invalid_response", False),
        ("output_limit", False),
    ],
)
def test_registry_errors_keep_their_retry_classification(monkeypatch, code, retryable):
    def fail(reference):
        raise RegistryRequestError(code)

    monkeypatch.setattr(workflow, "resolve_docker_tag", fail)
    with pytest.raises(workflow.ScanWorkflowError) as error:
        workflow.collect_trivy_result(SUBMISSION)
    assert error.value.code == "resolution_failed"
    assert error.value.retryable is retryable


def test_invalid_image_reference_is_not_retryable(monkeypatch):
    def invalid(reference):
        raise ValueError("private invalid input details")

    monkeypatch.setattr(workflow, "resolve_docker_tag", invalid)
    with pytest.raises(workflow.ScanWorkflowError) as error:
        workflow.collect_trivy_result(SUBMISSION)
    assert error.value.code == "resolution_failed"
    assert error.value.retryable is False
    assert "private" not in str(error.value)


@pytest.mark.parametrize(
    "code,retryable",
    [
        ("timeout", True),
        ("unavailable", False),
        ("execution_failed", False),
        ("output_limit", False),
        ("invalid_output", False),
    ],
)
def test_process_errors_keep_their_retry_classification(monkeypatch, code, retryable):
    monkeypatch.setattr(workflow, "resolve_docker_tag", lambda reference: PINNED)

    def fail(reference):
        raise ProcessExecutionError(code)

    monkeypatch.setattr(workflow, "run_trivy_scan", fail)
    with pytest.raises(workflow.ScanWorkflowError) as error:
        workflow.collect_trivy_result(SUBMISSION)
    assert error.value.retryable is retryable


def test_malformed_report_is_not_retryable(monkeypatch):
    monkeypatch.setattr(workflow, "resolve_docker_tag", lambda reference: PINNED)
    monkeypatch.setattr(
        workflow, "run_trivy_scan", lambda reference: "private invalid JSON"
    )
    with pytest.raises(workflow.ScanWorkflowError) as error:
        workflow.collect_trivy_result(SUBMISSION)
    assert error.value.code == "invalid_report"
    assert error.value.retryable is False
    assert "private" not in str(error.value)
