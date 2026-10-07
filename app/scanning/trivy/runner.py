import re

from app.scanning.trivy.parser import parse_trivy_database_metadata
from app.scanning.trivy.process_runner import ProcessExecutionError, run_bounded_command


def build_trivy_command(image_reference: str, timeout_seconds: int = 300) -> list[str]:
    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise ValueError("Timeout must be a positive integer")

    if not isinstance(image_reference, str):
        raise ValueError("Image reference must be a string")

    reference = image_reference.strip()
    pattern = (
        r"(?:docker\.io|ghcr\.io)/"
        r"[a-z0-9]+(?:[._/-][a-z0-9]+)*"
        r"@sha256:[0-9a-f]{64}"
    )
    if re.fullmatch(pattern, reference) is None:
        raise ValueError("Expected a supported, digest-pinned image reference")

    return [
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
        f"{timeout_seconds}s",
        "--",
        reference,
    ]


def run_trivy_scan(
    image_reference: str,
    timeout_seconds: int = 300,
    max_output_bytes: int = 10 * 1024 * 1024,
) -> str:
    command = build_trivy_command(image_reference, timeout_seconds)
    return run_bounded_command(
        command,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )


def read_trivy_database_metadata(expected_scanner_version: str) -> dict | None:
    """Read optional local cache metadata after scanning, without downloading it."""
    try:
        output = run_bounded_command(
            ["trivy", "--version", "--format", "json"],
            timeout_seconds=10,
            max_output_bytes=64 * 1024,
        )
        return parse_trivy_database_metadata(output, expected_scanner_version)
    except ProcessExecutionError, ValueError:
        return None
