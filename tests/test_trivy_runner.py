from importlib import import_module

import pytest

DIGEST = "sha256:" + "a" * 64


@pytest.mark.parametrize(
    "repository", ["docker.io/library/alpine", "ghcr.io/demo/image"]
)
def test_command_scans_a_pinned_remote_image_without_docker(
    repository: str,
) -> None:
    runner = import_module("app.scanning.trivy.runner")
    reference = f"{repository}@{DIGEST}"
    command = runner.build_trivy_command(reference, timeout_seconds=120)
    assert command == [
        "trivy",
        "image",
        "--image-src",
        "remote",
        "--platform",
        "linux/amd64",
        "--scanners",
        "vuln",
        "--format",
        "json",
        "--timeout",
        "120s",
        "--",
        reference,
    ]


def test_command_trims_reference_and_defaults_to_five_minutes() -> None:
    runner = import_module("app.scanning.trivy.runner")
    reference = f"docker.io/library/alpine@{DIGEST}"
    command = runner.build_trivy_command(f"  {reference}  ")
    assert command[command.index("--timeout") + 1] == "300s"
    assert command[-2:] == ["--", reference]


@pytest.mark.parametrize(
    "reference",
    [
        "docker.io/library/alpine:3.20",
        f"alpine@{DIGEST}",
        f"localhost:5000/demo/image@{DIGEST}",
        "docker.io/library/alpine@sha256:short",
        f"docker.io/library/alpine@{DIGEST}; echo unexpected",
        "--help",
        None,
    ],
    ids=[
        "mutable-tag",
        "unqualified-name",
        "unapproved-registry",
        "invalid-digest",
        "shell-text",
        "option",
        "wrong-type",
    ],
)
def test_command_rejects_unsupported_image_references(reference: object) -> None:
    runner = import_module("app.scanning.trivy.runner")
    with pytest.raises(ValueError):
        runner.build_trivy_command(reference)


@pytest.mark.parametrize("timeout", [0, -1, True, "300", 1.5])
def test_command_rejects_invalid_timeout(timeout: object) -> None:
    runner = import_module("app.scanning.trivy.runner")
    with pytest.raises(ValueError):
        runner.build_trivy_command(
            f"docker.io/library/alpine@{DIGEST}", timeout_seconds=timeout
        )


def install_fake_trivy(tmp_path, monkeypatch, body):
    import os
    import sys

    executable = tmp_path / "trivy"
    executable.write_text(f"#!{sys.executable}\n" + body)
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")


def test_scan_returns_json_without_mixing_in_logs(tmp_path, monkeypatch):
    from pathlib import Path

    from app.scanning.trivy.parser import load_trivy_report, parse_trivy_findings

    fixture = Path(__file__).parent / "fixtures" / "trivy" / "no_findings.json"
    reference = f"docker.io/library/alpine@{DIGEST}"
    runner = import_module("app.scanning.trivy.runner")
    arguments = runner.build_trivy_command(reference)[1:]
    install_fake_trivy(
        tmp_path,
        monkeypatch,
        "import sys\n"
        f"assert sys.argv[1:] == {arguments!r}\n"
        f"sys.stdout.write({fixture.read_text()!r})\n"
        "print('scanner warning', file=sys.stderr)\n",
    )
    report = load_trivy_report(runner.run_trivy_scan(reference))
    assert report["ArtifactType"] == "container_image"
    assert parse_trivy_findings(report) == []


def test_scan_enforces_its_output_limit(tmp_path, monkeypatch):
    from app.scanning.trivy.process_runner import ProcessExecutionError

    install_fake_trivy(tmp_path, monkeypatch, "print('x' * 4096)\n")
    runner = import_module("app.scanning.trivy.runner")
    with pytest.raises(ProcessExecutionError) as error:
        runner.run_trivy_scan(
            f"docker.io/library/alpine@{DIGEST}", max_output_bytes=128
        )
    assert error.value.code == "output_limit"


def test_reads_database_metadata_from_the_version_command(tmp_path, monkeypatch):
    import json
    from pathlib import Path

    runner = import_module("app.scanning.trivy.runner")
    fixture = Path(__file__).parent / "fixtures" / "trivy" / "version_info.json"
    install_fake_trivy(
        tmp_path,
        monkeypatch,
        "import sys\n"
        "assert sys.argv[1:] == ['--version', '--format', 'json']\n"
        f"sys.stdout.write({fixture.read_text()!r})\n",
    )
    assert (
        runner.read_trivy_database_metadata("0.75.0")
        == json.loads(fixture.read_text())["VulnerabilityDB"]
    )


def test_missing_database_information_remains_null(tmp_path, monkeypatch):
    runner = import_module("app.scanning.trivy.runner")
    install_fake_trivy(tmp_path, monkeypatch, 'print(\'{"Version": "0.75.0"}\')\n')
    assert runner.read_trivy_database_metadata("0.75.0") is None


@pytest.mark.parametrize(
    "output", ["not-json", '{"Version": "0.74.0", "VulnerabilityDB": {"Version": 2}}']
)
def test_invalid_optional_version_information_is_not_saved(
    tmp_path, monkeypatch, output
):
    runner = import_module("app.scanning.trivy.runner")
    install_fake_trivy(tmp_path, monkeypatch, f"print({output!r})\n")
    assert runner.read_trivy_database_metadata("0.75.0") is None


def test_missing_version_executable_leaves_metadata_unknown(tmp_path, monkeypatch):
    runner = import_module("app.scanning.trivy.runner")
    monkeypatch.setenv("PATH", str(tmp_path))
    assert runner.read_trivy_database_metadata("0.75.0") is None


def test_version_output_is_bounded(tmp_path, monkeypatch):
    runner = import_module("app.scanning.trivy.runner")
    install_fake_trivy(tmp_path, monkeypatch, "print('x' * (64 * 1024 + 1))\n")
    assert runner.read_trivy_database_metadata("0.75.0") is None
