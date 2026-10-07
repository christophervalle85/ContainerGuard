import json
from importlib import import_module
from pathlib import Path

import pytest


@pytest.fixture
def version_document():
    fixture = Path(__file__).parent / "fixtures" / "trivy" / "version_info.json"
    return json.loads(fixture.read_text())


def parse(document, expected_version="0.75.0"):
    parser = import_module("app.scanning.trivy.parser")
    return parser.parse_trivy_database_metadata(json.dumps(document), expected_version)


def test_preserves_the_database_metadata_reported_by_trivy(version_document):
    assert parse(version_document) == version_document["VulnerabilityDB"]


def test_missing_database_metadata_remains_unknown():
    assert parse({"Version": "0.75.0"}) is None


def test_preserves_available_metadata_when_timestamps_are_absent():
    assert parse({"Version": "0.75.0", "VulnerabilityDB": {"Version": 2}}) == {
        "Version": 2
    }


def test_rejects_invalid_json():
    parser = import_module("app.scanning.trivy.parser")
    with pytest.raises(ValueError):
        parser.parse_trivy_database_metadata("not-json", "0.75.0")


def test_rejects_a_non_object_version_document():
    with pytest.raises(ValueError):
        parse([])


def test_rejects_a_scanner_version_different_from_the_scan_report(version_document):
    with pytest.raises(ValueError, match="version"):
        parse(version_document, "0.74.0")


def test_rejects_non_object_database_metadata():
    with pytest.raises(ValueError):
        parse({"Version": "0.75.0", "VulnerabilityDB": []})


def test_rejects_a_boolean_database_format_version():
    with pytest.raises(ValueError):
        parse({"Version": "0.75.0", "VulnerabilityDB": {"Version": True}})


@pytest.mark.parametrize("timestamp", ["not-a-date", "2026-10-06T13:07:05"])
def test_rejects_invalid_or_timezone_missing_timestamps(timestamp):
    with pytest.raises(ValueError):
        parse(
            {
                "Version": "0.75.0",
                "VulnerabilityDB": {"Version": 2, "UpdatedAt": timestamp},
            }
        )


def test_does_not_store_unrelated_version_output_fields(version_document):
    version_document["VulnerabilityDB"]["Unexpected"] = "unrelated data"
    parsed = parse(version_document)
    assert "Unexpected" not in parsed
    assert parsed["Version"] == 2
