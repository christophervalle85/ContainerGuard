from importlib import import_module
from pathlib import Path

import pytest

from app.scanning.trivy.process_runner import ProcessExecutionError

PINNED = (
    "docker.io/library/alpine@sha256:"
    "216266c86fc4dcef5619930bd394245824c2af52fd21ba7c6fa0e618657d4c3b"
)


def runner():
    return import_module("app.scanning.trivy.sbom_runner")


def collect(module):
    return module.collect_sbom(PINNED, platform="linux/amd64", scanner_version="0.75.0")


@pytest.mark.parametrize("reference", [PINNED, "ghcr.io/demo/image@sha256:" + "a" * 64])
def test_command_uses_only_remote_inventory_for_the_pinned_image(reference):
    assert runner().build_sbom_command(reference) == [
        "trivy",
        "image",
        "--image-src",
        "remote",
        "--platform",
        "linux/amd64",
        "--format",
        "cyclonedx",
        "--timeout",
        "60s",
        "--",
        reference,
    ]


def test_command_trims_reference():
    assert runner().build_sbom_command("  " + PINNED + "  ")[-1] == PINNED


@pytest.mark.parametrize(
    "reference",
    [
        "docker.io/library/alpine:3.20.0",
        "alpine@sha256:" + "a" * 64,
        "localhost:5000/demo@sha256:" + "a" * 64,
        "--help",
        PINNED + "; echo bad",
        "docker.io/library/alpine@sha256:short",
        None,
    ],
)
def test_command_rejects_unsupported_references(reference):
    with pytest.raises(ValueError):
        runner().build_sbom_command(reference)


def test_collect_preserves_utf8_bytes_and_enforces_process_bounds(monkeypatch):
    module = runner()
    payload = Path("tests/fixtures/trivy/cyclonedx.json").read_bytes()
    # Valid UTF-8 text round-trips without reserializing the JSON document.
    payload = b" \n" + payload.replace(b'"alpine"', '"café"'.encode(), 1)
    calls = []

    def execute(command, *, timeout_seconds, max_output_bytes, max_error_bytes):
        calls.append((command, timeout_seconds, max_output_bytes, max_error_bytes))
        return payload.decode("utf-8")

    monkeypatch.setattr(module, "run_bounded_command", execute)
    outcome = collect(module)
    assert outcome.error_code is None
    assert outcome.artifact.payload == payload
    assert outcome.artifact.pinned_reference == PINNED
    assert outcome.artifact.platform == "linux/amd64"
    assert outcome.artifact.scanner_version == "0.75.0"
    assert calls == [
        (
            [
                "trivy",
                "image",
                "--image-src",
                "remote",
                "--platform",
                "linux/amd64",
                "--format",
                "cyclonedx",
                "--timeout",
                "60s",
                "--",
                PINNED,
            ],
            60,
            10485760,
            65536,
        )
    ]


@pytest.mark.parametrize(
    "process_code, expected",
    [
        ("timeout", "sbom_timeout"),
        ("unavailable", "sbom_unavailable"),
        ("execution_failed", "sbom_execution_failed"),
        ("output_limit", "sbom_output_limit"),
        ("invalid_output", "sbom_invalid_report"),
    ],
)
def test_process_failure_becomes_classified_outcome(
    monkeypatch, process_code, expected
):
    module = runner()

    def execute(*args, **kwargs):
        raise ProcessExecutionError(process_code)

    monkeypatch.setattr(module, "run_bounded_command", execute)
    outcome = collect(module)
    assert outcome.artifact is None
    assert outcome.error_code == expected


@pytest.mark.parametrize(
    "output",
    [
        "not-json",
        "{}",
        "\ud800",
        Path("tests/fixtures/trivy/cyclonedx.json")
        .read_text()
        .replace("216266c8", "ffffffff"),
    ],
)
def test_invalid_output_never_becomes_available(monkeypatch, output):
    module = runner()
    monkeypatch.setattr(module, "run_bounded_command", lambda *a, **kw: output)
    outcome = collect(module)
    assert outcome.artifact is None
    assert outcome.error_code == "sbom_invalid_report"


@pytest.mark.parametrize(
    "error", [RuntimeError("programming bug"), TypeError("wrong type")]
)
def test_unexpected_errors_are_not_hidden(monkeypatch, error):
    module = runner()

    def execute(*args, **kwargs):
        raise error

    monkeypatch.setattr(module, "run_bounded_command", execute)
    with pytest.raises(type(error)):
        collect(module)


@pytest.mark.parametrize(
    "platform, version", [("linux/arm64", "0.75.0"), ("linux/amd64", "0.74.0")]
)
def test_unsupported_metadata_is_rejected_before_execution(
    monkeypatch, platform, version
):
    module = runner()
    calls = []
    monkeypatch.setattr(module, "run_bounded_command", lambda *a, **kw: calls.append(a))
    with pytest.raises(ValueError):
        module.collect_sbom(PINNED, platform=platform, scanner_version=version)
    assert calls == []
