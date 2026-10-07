import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.api.schemas import Severity


def load_trivy_report(raw_report: str) -> dict[str, Any]:
    try:
        report = json.loads(raw_report)
    except json.JSONDecodeError:
        raise ValueError("Invalid Trivy JSON report") from None

    if not isinstance(report, dict):
        raise ValueError("Trivy report must be an object")

    if report.get("SchemaVersion") != 2:
        raise ValueError("Unsupported Trivy report schema")

    if report.get("ArtifactType") != "container_image":
        raise ValueError("Expected a container image report")

    results = report.get("Results", [])
    if not isinstance(results, list):
        raise ValueError("Trivy Results must be a list")

    if any(not isinstance(result, dict) for result in results):
        raise ValueError("Each Trivy result must be an object")

    report["Results"] = results
    return report


@dataclass(frozen=True)
class ParsedFinding:
    vulnerability_id: str
    package_name: str
    package_type: str
    target: str
    installed_version: str
    fixed_version: str | None
    severity: Severity
    title: str
    occurrence_order: int


def _optional_text(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    return value.strip() or None


def _required_text(value: object, field: str) -> str:
    text = _optional_text(value, field)
    if text is None:
        raise ValueError(f"{field} is required")
    return text


def _parse_severity(value: object) -> Severity:
    text = _optional_text(value, "Severity")
    if text is None:
        return Severity.UNKNOWN
    try:
        return Severity(text.upper())
    except ValueError:
        return Severity.UNKNOWN


def parse_trivy_findings(report: dict[str, Any]) -> list[ParsedFinding]:
    findings = []

    for result in report["Results"]:
        vulnerabilities = result.get("Vulnerabilities", [])

        if not isinstance(vulnerabilities, list):
            raise ValueError("Vulnerabilities must be a list")

        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ValueError("Each vulnerability must be an object")

            vulnerability_id = _required_text(
                vulnerability.get("VulnerabilityID"), "VulnerabilityID"
            )

            findings.append(
                ParsedFinding(
                    vulnerability_id=vulnerability_id,
                    package_name=_required_text(
                        vulnerability.get("PkgName"), "PkgName"
                    ),
                    package_type=_required_text(result.get("Type"), "Type"),
                    target=_required_text(result.get("Target"), "Target"),
                    installed_version=_required_text(
                        vulnerability.get("InstalledVersion"), "InstalledVersion"
                    ),
                    fixed_version=_optional_text(
                        vulnerability.get("FixedVersion"), "FixedVersion"
                    ),
                    severity=_parse_severity(vulnerability.get("Severity")),
                    title=(
                        _optional_text(vulnerability.get("Title"), "Title")
                        or vulnerability_id
                    ),
                    occurrence_order=len(findings),
                )
            )

    return findings


@dataclass(frozen=True)
class ParsedScanMetadata:
    image_reference: str
    reported_digest: str
    platform: str
    scanner_version: str


def _required_object(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def parse_trivy_metadata(report: dict[str, Any]) -> ParsedScanMetadata:
    metadata = _required_object(report.get("Metadata"), "Metadata")
    config = _required_object(metadata.get("ImageConfig"), "ImageConfig")
    trivy = _required_object(report.get("Trivy"), "Trivy")

    repo_digests = metadata.get("RepoDigests")
    if not isinstance(repo_digests, list) or len(repo_digests) != 1:
        raise ValueError("Expected one unambiguous registry digest")

    reference = _required_text(repo_digests[0], "RepoDigest")
    repository, separator, digest = reference.rpartition("@")

    if (
        not repository
        or separator != "@"
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
    ):
        raise ValueError("Invalid registry digest reference")

    operating_system = _required_text(config.get("os"), "os")
    architecture = _required_text(config.get("architecture"), "architecture")
    platform = f"{operating_system}/{architecture}"

    if platform != "linux/amd64" or config.get("variant") not in (None, ""):
        raise ValueError("Only linux/amd64 is supported")

    return ParsedScanMetadata(
        image_reference=reference,
        reported_digest=digest,
        platform=platform,
        scanner_version=_required_text(trivy.get("Version"), "Version"),
    )


def _load_trivy_version_info(
    raw_version_info: str, expected_scanner_version: str
) -> dict[str, Any]:
    try:
        document = json.loads(raw_version_info)
    except json.JSONDecodeError:
        raise ValueError("Invalid Trivy version JSON") from None
    document = _required_object(document, "Trivy version output")
    version = _required_text(document.get("Version"), "Trivy version")
    if version != expected_scanner_version:
        raise ValueError("Trivy version does not match the scan report")
    return document


def _validated_database_timestamp(value: object, field: str) -> str:
    text = _required_text(value, field)
    try:
        timestamp = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(f"Invalid database timestamp: {field}") from None
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError(f"Database timestamp requires a timezone: {field}")
    return text


def parse_trivy_database_metadata(
    raw_version_info: str,
    expected_scanner_version: str,
) -> dict[str, Any] | None:
    document = _load_trivy_version_info(raw_version_info, expected_scanner_version)
    database = document.get("VulnerabilityDB")

    if database is None:
        return None

    database = _required_object(database, "VulnerabilityDB")
    version = database.get("Version")

    if type(version) is not int or version <= 0:
        raise ValueError("Invalid vulnerability database format version")

    metadata = {"Version": version}

    for field in ("UpdatedAt", "NextUpdate", "DownloadedAt"):
        if field in database:
            metadata[field] = _validated_database_timestamp(database[field], field)

    return metadata
