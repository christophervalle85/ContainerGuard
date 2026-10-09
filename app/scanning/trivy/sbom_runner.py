"""Collect a bounded CycloneDX inventory for an already pinned image."""

from app.scanning.trivy.process_runner import ProcessExecutionError, run_bounded_command
from app.scanning.trivy.runner import build_trivy_command
from app.scanning.trivy.sbom import MAX_SBOM_BYTES, SbomOutcome, parse_sbom

_PROCESS_ERRORS = {
    "timeout": "sbom_timeout",
    "unavailable": "sbom_unavailable",
    "execution_failed": "sbom_execution_failed",
    "output_limit": "sbom_output_limit",
    "invalid_output": "sbom_invalid_report",
}


def build_sbom_command(pinned_reference: str) -> list[str]:
    # Reuse the existing registry/digest validation; building runs no command.
    reference = build_trivy_command(pinned_reference)[-1]
    return [
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


def collect_sbom(
    pinned_reference: str, *, platform: str, scanner_version: str
) -> SbomOutcome:
    if platform != "linux/amd64" or scanner_version != "0.75.0":
        raise ValueError("Unsupported SBOM platform or scanner version")
    command = build_sbom_command(pinned_reference)
    try:
        output = run_bounded_command(
            command,
            timeout_seconds=60,
            max_output_bytes=MAX_SBOM_BYTES,
            max_error_bytes=65536,
        )
    except ProcessExecutionError as error:
        return SbomOutcome(None, _PROCESS_ERRORS[error.code])

    try:
        artifact = parse_sbom(
            output.encode("utf-8"),
            pinned_reference=command[-1],
            platform=platform,
            scanner_version=scanner_version,
        )
    except ValueError:
        return SbomOutcome(None, "sbom_invalid_report")
    return SbomOutcome(artifact, None)
