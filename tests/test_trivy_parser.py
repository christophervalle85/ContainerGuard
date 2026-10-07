import json
from importlib import import_module
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "trivy" / "no_findings.json"


def test_load_image_report_preserves_metadata_and_zero_findings() -> None:
    parser = import_module("app.scanning.trivy.parser")
    report = parser.load_trivy_report(FIXTURE.read_text())
    assert report["ArtifactName"] == "docker.io/library/alpine:3.20"
    assert report["Trivy"]["Version"] == "0.75.0"
    assert report["Metadata"]["OS"]["EOSL"] is True
    assert report["Metadata"]["ImageConfig"] == {"architecture": "amd64", "os": "linux"}
    assert len(report["Results"]) == 1
    assert report["Results"][0]["Packages"]
    assert report["Results"][0].get("Vulnerabilities", []) == []


def test_load_report_allows_an_omitted_empty_results_list() -> None:
    parser = import_module("app.scanning.trivy.parser")
    raw = json.dumps({"SchemaVersion": 2, "ArtifactType": "container_image"})
    assert parser.load_trivy_report(raw)["Results"] == []


def test_load_report_rejects_invalid_json() -> None:
    parser = import_module("app.scanning.trivy.parser")
    with pytest.raises(ValueError):
        parser.load_trivy_report("{not valid JSON")


@pytest.mark.parametrize(
    "report",
    [
        [],
        {"SchemaVersion": 99, "ArtifactType": "container_image"},
        {"SchemaVersion": 2, "ArtifactType": "filesystem"},
        {"SchemaVersion": 2, "ArtifactType": "container_image", "Results": None},
        {"SchemaVersion": 2, "ArtifactType": "container_image", "Results": {}},
        {"SchemaVersion": 2, "ArtifactType": "container_image", "Results": "bad"},
        {"SchemaVersion": 2, "ArtifactType": "container_image", "Results": [None]},
    ],
    ids=[
        "root-array",
        "schema-version",
        "artifact-type",
        "null-results",
        "object-results",
        "string-results",
        "invalid-target",
    ],
)
def test_load_report_rejects_unsupported_structure(report: object) -> None:
    parser = import_module("app.scanning.trivy.parser")
    with pytest.raises(ValueError):
        parser.load_trivy_report(json.dumps(report))


def test_parse_findings_returns_empty_list_for_a_successful_zero_finding_report() -> (
    None
):
    parser = import_module("app.scanning.trivy.parser")
    report = parser.load_trivy_report(FIXTURE.read_text())
    assert parser.parse_trivy_findings(report) == []


def test_parse_findings_preserves_distinct_packages_and_targets() -> None:
    parser = import_module("app.scanning.trivy.parser")
    report = parser.load_trivy_report((FIXTURE.parent / "findings.json").read_text())
    findings = parser.parse_trivy_findings(report)
    assert [vars(finding) for finding in findings] == [
        {
            "vulnerability_id": "FIXTURE-001",
            "package_name": "demo-library-a",
            "package_type": "alpine",
            "target": "demo/image:fixture (alpine fixture)",
            "installed_version": "1.0",
            "fixed_version": "1.1",
            "severity": "CRITICAL",
            "title": "Fictional parser finding",
            "occurrence_order": 0,
        },
        {
            "vulnerability_id": "FIXTURE-001",
            "package_name": "demo-library-b",
            "package_type": "alpine",
            "target": "demo/image:fixture (alpine fixture)",
            "installed_version": "2.0",
            "fixed_version": None,
            "severity": "HIGH",
            "title": "Fictional finding in another package",
            "occurrence_order": 1,
        },
        {
            "vulnerability_id": "FIXTURE-001",
            "package_name": "demo-library-a",
            "package_type": "python-pkg",
            "target": "/demo/requirements.txt",
            "installed_version": "1.0",
            "fixed_version": None,
            "severity": "UNKNOWN",
            "title": "FIXTURE-001",
            "occurrence_order": 2,
        },
    ]


@pytest.mark.parametrize("fixed_version", [None, "", "   "])
def test_parse_findings_normalizes_empty_fixed_version(fixed_version: object) -> None:
    parser = import_module("app.scanning.trivy.parser")
    report = parser.load_trivy_report((FIXTURE.parent / "findings.json").read_text())
    report["Results"][0]["Vulnerabilities"][0]["FixedVersion"] = fixed_version
    assert parser.parse_trivy_findings(report)[0].fixed_version is None


def test_parse_findings_preserves_unrecognized_severity_as_unknown() -> None:
    parser = import_module("app.scanning.trivy.parser")
    report = parser.load_trivy_report((FIXTURE.parent / "findings.json").read_text())
    report["Results"][0]["Vulnerabilities"][0]["Severity"] = "UNRATED"
    assert parser.parse_trivy_findings(report)[0].severity == "UNKNOWN"


@pytest.mark.parametrize("vulnerabilities", [None, {}, "bad"])
def test_parse_findings_rejects_malformed_vulnerability_lists(
    vulnerabilities: object,
) -> None:
    parser = import_module("app.scanning.trivy.parser")
    report = parser.load_trivy_report(FIXTURE.read_text())
    report["Results"][0]["Vulnerabilities"] = vulnerabilities
    with pytest.raises(ValueError):
        parser.parse_trivy_findings(report)


def test_parse_findings_rejects_a_nonobject_vulnerability() -> None:
    parser = import_module("app.scanning.trivy.parser")
    report = parser.load_trivy_report(FIXTURE.read_text())
    report["Results"][0]["Vulnerabilities"] = [None]
    with pytest.raises(ValueError):
        parser.parse_trivy_findings(report)


@pytest.mark.parametrize(
    ("location", "field"),
    [
        ("finding", "VulnerabilityID"),
        ("finding", "PkgName"),
        ("finding", "InstalledVersion"),
        ("result", "Target"),
        ("result", "Type"),
    ],
)
def test_parse_findings_rejects_missing_occurrence_identity(
    location: str, field: str
) -> None:
    parser = import_module("app.scanning.trivy.parser")
    report = parser.load_trivy_report((FIXTURE.parent / "findings.json").read_text())
    result = report["Results"][0]
    record = result["Vulnerabilities"][0] if location == "finding" else result
    del record[field]
    with pytest.raises(ValueError):
        parser.parse_trivy_findings(report)


def test_parse_metadata_uses_registry_digest_instead_of_image_id() -> None:
    parser = import_module("app.scanning.trivy.parser")
    report = parser.load_trivy_report(FIXTURE.read_text())
    report["Metadata"]["ImageID"] = "sha256:" + "b" * 64
    metadata = parser.parse_trivy_metadata(report)
    assert metadata.image_reference == (
        "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
    )
    assert metadata.reported_digest == (
        "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
    )
    assert metadata.platform == "linux/amd64"
    assert metadata.scanner_version == "0.75.0"


@pytest.mark.parametrize("field", ["Metadata", "ImageConfig", "Trivy"])
def test_parse_metadata_rejects_missing_objects(field: str) -> None:
    parser = import_module("app.scanning.trivy.parser")
    report = parser.load_trivy_report(FIXTURE.read_text())
    if field == "ImageConfig":
        report["Metadata"][field] = None
    else:
        report[field] = None
    with pytest.raises(ValueError):
        parser.parse_trivy_metadata(report)


@pytest.mark.parametrize(
    "repo_digests",
    [
        [],
        "alpine@sha256:" + "a" * 64,
        ["alpine@sha256:short"],
        ["@sha256:" + "a" * 64],
        ["alpine@sha256:" + "a" * 64, "alpine@sha256:" + "b" * 64],
    ],
    ids=["missing", "wrong-type", "invalid-hash", "missing-repository", "ambiguous"],
)
def test_parse_metadata_rejects_missing_invalid_or_ambiguous_digest(
    repo_digests: object,
) -> None:
    parser = import_module("app.scanning.trivy.parser")
    report = parser.load_trivy_report(FIXTURE.read_text())
    report["Metadata"]["RepoDigests"] = repo_digests
    with pytest.raises(ValueError):
        parser.parse_trivy_metadata(report)


@pytest.mark.parametrize(
    "config",
    [
        {"os": "linux", "architecture": "arm64"},
        {"os": "windows", "architecture": "amd64"},
        {"os": "linux", "architecture": "amd64", "variant": "v3"},
    ],
)
def test_parse_metadata_rejects_unsupported_platform(config: dict) -> None:
    parser = import_module("app.scanning.trivy.parser")
    report = parser.load_trivy_report(FIXTURE.read_text())
    report["Metadata"]["ImageConfig"] = config
    with pytest.raises(ValueError):
        parser.parse_trivy_metadata(report)


def test_parse_metadata_rejects_missing_scanner_version() -> None:
    parser = import_module("app.scanning.trivy.parser")
    report = parser.load_trivy_report(FIXTURE.read_text())
    report["Trivy"] = {}
    with pytest.raises(ValueError):
        parser.parse_trivy_metadata(report)
