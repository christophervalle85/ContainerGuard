import pytest

from scripts.releases.supply_chain import sbom


def document():
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {
            "component": {
                "type": "container",
                "name": "fixture",
                "properties": [
                    {
                        "name": "aquasecurity:trivy:ImageID",
                        "value": "sha256:" + "c" * 64,
                    }
                ],
            },
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "group": "aquasecurity",
                        "name": "trivy",
                        "version": "0.75.0+cg.1",
                    }
                ]
            },
        },
        "components": [{"type": "library", "name": "fixture", "version": "1"}],
    }


def test_full_schema_accepts_scanner_and_components():
    assert sbom.validate(document()) == document()


@pytest.mark.parametrize(
    "mutation", ["version", "unknown", "nested", "scanner", "components", "remote"]
)
def test_invalid_cyclonedx_rejected(mutation):
    doc = document()
    if mutation == "version":
        doc["specVersion"] = "1.6"
    if mutation == "unknown":
        doc["unrecognized"] = True
    if mutation == "nested":
        doc["components"][0]["licenses"] = [{"license": {"id": "NOT-AN-SPDX-LICENSE"}}]
    if mutation == "scanner":
        doc["metadata"]["tools"]["components"][0]["version"] = "0.75.0"
    if mutation == "components":
        doc.pop("components")
    if mutation == "remote":
        doc["$schema"] = "https://attacker.invalid/schema.json"
    with pytest.raises(ValueError, match="SBOM"):
        sbom.validate(doc)


def test_actual_trivy_http_schema_identity_supported():
    doc = document()
    doc["$schema"] = "http://cyclonedx.org/schema/bom-1.7.schema.json"
    assert sbom.validate(doc) == doc


def test_unknown_schema_reference_never_uses_network(tmp_path, monkeypatch):
    import hashlib
    import json
    import urllib.request

    source = json.loads((sbom.SCHEMAS / "bom-1.7.schema.json").read_text())
    source["allOf"] = [{"$ref": "https://attacker.invalid/schema.json"}]
    raw = json.dumps(source).encode()
    (tmp_path / "bom-1.7.schema.json").write_bytes(raw)
    (tmp_path / "manifest.json").write_text(
        json.dumps({"files": {"bom-1.7.schema.json": hashlib.sha256(raw).hexdigest()}})
    )
    monkeypatch.setattr(sbom, "SCHEMAS", tmp_path)
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda *a, **k: pytest.fail("network retrieval")
    )
    with pytest.raises(ValueError, match="SBOM"):
        sbom.validate(document())


def test_real_patched_scanner_output_validates():
    from pathlib import Path

    from scripts.releases.supply_chain import evidence

    path = Path(__file__).parent / "fixtures/releases/trivy-0.75.0-cg.1.cdx17.json"
    assert (
        len(sbom.validate(evidence.read_document(path, kind="sbom"))["components"])
        == 71
    )


def test_missing_format_checker_fails_closed(monkeypatch):
    from jsonschema import FormatChecker

    monkeypatch.delitem(FormatChecker.checkers, "iri-reference")
    with pytest.raises(ValueError, match="SBOM"):
        sbom.validate(document())


def test_format_constraints_are_enforced():
    doc = document()
    doc["metadata"]["timestamp"] = "not-a-timestamp"
    with pytest.raises(ValueError, match="SBOM"):
        sbom.validate(doc)


def test_generate_uses_local_only_scanner_and_bounded_stdout(tmp_path, monkeypatch):
    import json

    calls = []
    monkeypatch.setattr(sbom.shutil, "which", lambda name: "/trusted/trivy")

    def capture(args, output, **kwargs):
        calls.append((args, kwargs))
        output.write_text(
            json.dumps(
                {"Version": sbom.SCANNER_VERSION} if "--version" in args else document()
            )
        )
        return output

    monkeypatch.setattr(sbom, "command_file", capture)
    output = tmp_path / "api.sbom.json"
    assert sbom.generate("sha256:" + "a" * 64, output) == output
    scan_args, options = calls[1]
    assert scan_args[scan_args.index("--image-src") + 1] == "docker"
    assert "--offline-scan" in scan_args
    assert options["limit"] == 16 * 1024**2
    assert options["timeout"] == 600


def test_generate_rejects_unpinned_image_before_command(tmp_path, monkeypatch):
    monkeypatch.setattr(
        sbom, "command_file", lambda *a, **k: pytest.fail("scanner executed")
    )
    with pytest.raises(ValueError, match="reference"):
        sbom.generate("alpine:latest", tmp_path / "sbom.json")


@pytest.mark.parametrize("arguments", [["--help"], ["guard", "--help"]])
def test_release_cli_help_works_without_site_packages(arguments):
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-S", "-B", "-m", "scripts.releases", *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
