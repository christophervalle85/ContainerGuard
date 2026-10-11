import copy
import importlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

NOW = datetime(2026, 10, 11, 12, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[1]


def report(severity=None):
    result = {"Target": "uv.lock", "Class": "lang-pkgs", "Type": "uv"}
    if severity:
        result["Vulnerabilities"] = [
            {
                "VulnerabilityID": "MOCK-001",
                "PkgName": "fictional-package",
                "InstalledVersion": "1.0",
                "Severity": severity,
            }
        ]
    return {
        "SchemaVersion": 2,
        "ArtifactName": ".",
        "ArtifactType": "filesystem",
        "Results": [result],
    }


def evaluate(document, exceptions=None):
    gate = importlib.import_module("scripts.security_gate")
    return gate.evaluate_report(
        document, exceptions or [], target=".", expected_targets={"uv.lock"}, now=NOW
    )


@pytest.mark.parametrize("severity", ["HIGH", "CRITICAL"])
def test_critical_and_high_block_even_without_fix(severity):
    result = evaluate(report(severity))
    assert result["blocked"] is True
    assert len(result["findings"]) == 1
    assert result["exceptions_used"] == []


@pytest.mark.parametrize("severity", ["LOW", "MEDIUM", "UNKNOWN"])
def test_lower_and_unknown_are_reported(severity):
    result = evaluate(report(severity))
    assert result["blocked"] is False
    assert result["findings"][0]["severity"] == severity


def test_clean_expected_target_passes():
    assert evaluate(report())["blocked"] is False


@pytest.mark.parametrize(
    "change",
    [
        {"Results": []},
        {"Results": None},
        {"ArtifactName": "wrong"},
        {"ArtifactType": "sbom"},
        {"SchemaVersion": True},
        {"Results": [{"Target": "wrong", "Class": "lang-pkgs", "Type": "uv"}]},
    ],
)
def test_missing_or_wrong_target_fails(change):
    document = report()
    document.update(change)
    with pytest.raises(ValueError):
        evaluate(document)


@pytest.mark.parametrize(
    "change",
    [
        {"Severity": "unknown"},
        {"Severity": None},
        {"PkgName": ""},
        {"VulnerabilityID": 3},
        {"InstalledVersion": None},
        {"FixedVersion": []},
    ],
)
def test_malformed_vulnerability_fails(change):
    document = report("LOW")
    document["Results"][0]["Vulnerabilities"][0].update(change)
    with pytest.raises(ValueError):
        evaluate(document)


def exception():
    return {
        "vulnerability_id": "MOCK-001",
        "package": "fictional-package",
        "target": ".",
        "rationale": "Fictional exception for testing",
        "owner": "test-owner",
        "review_reference": "test-review",
        "created_at": "2026-10-10T00:00:00Z",
        "expires_at": "2026-10-12T00:00:00Z",
    }


def test_exact_exception_suppresses_only_matching_finding():
    result = evaluate(report("HIGH"), [exception()])
    assert result["blocked"] is False
    assert len(result["exceptions_used"]) == 1
    assert len(result["findings"]) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("target", "other"),
        ("package", "other"),
        ("vulnerability_id", "OTHER"),
    ],
)
def test_mismatched_exception_does_not_suppress(field, value):
    item = exception()
    item[field] = value
    assert evaluate(report("HIGH"), [item])["blocked"] is True


@pytest.mark.parametrize(
    "field,value",
    [
        ("rationale", ""),
        ("owner", ""),
        ("review_reference", None),
        ("expires_at", "2026-10-11T00:00:00Z"),
        ("expires_at", "2026-10-09T00:00:00Z"),
        ("expires_at", "2026-11-11T00:00:00Z"),
        ("expires_at", "2026-10-12T00:00:00"),
        ("created_at", "2026-10-12T00:00:00Z"),
    ],
)
def test_invalid_exception_fails_even_without_findings(field, value):
    item = exception()
    item[field] = value
    with pytest.raises(ValueError):
        evaluate(report(), [item])


def test_duplicate_exception_fails():
    item = exception()
    with pytest.raises(ValueError):
        evaluate(report(), [item, copy.deepcopy(item)])


def test_image_identity_and_os_target_are_required():
    document = report()
    document.update(
        ArtifactName="containerguard-api:security", ArtifactType="container_image"
    )
    document["Results"] = [
        {"Target": "debian 12", "Class": "os-pkgs", "Type": "debian"}
    ]
    gate = importlib.import_module("scripts.security_gate")
    assert (
        gate.evaluate_report(
            document,
            [],
            target="containerguard-api:security",
            expected_targets=set(),
            now=NOW,
        )["blocked"]
        is False
    )
    document["Results"] = []
    with pytest.raises(ValueError):
        gate.evaluate_report(
            document,
            [],
            target="containerguard-api:security",
            expected_targets=set(),
            now=NOW,
        )


@pytest.mark.parametrize(
    "kind,expected", [("clean", 0), ("blocked", 1), ("malformed", 2), ("absent", 2)]
)
def test_cli_exit_codes_and_summary(tmp_path, kind, expected):
    source = tmp_path / "report.json"
    summary = tmp_path / "summary.json"
    exceptions = tmp_path / "exceptions.json"
    exceptions.write_text("[]")
    if kind != "absent":
        source.write_text(
            "{"
            if kind == "malformed"
            else json.dumps(report("HIGH" if kind == "blocked" else None))
        )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.security_gate",
            "--report",
            str(source),
            "--exceptions",
            str(exceptions),
            "--target",
            ".",
            "--expected-target",
            "uv.lock",
            "--summary",
            str(summary),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == expected, result.stderr
    if expected < 2:
        assert json.loads(summary.read_text())["blocked"] is (expected == 1)
    else:
        assert not summary.exists()
