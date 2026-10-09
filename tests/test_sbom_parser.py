import hashlib
import json
from pathlib import Path

import pytest

from app.scanning.trivy.sbom import SbomOutcome, parse_sbom

PINNED = (
    "docker.io/library/alpine@sha256:"
    "216266c86fc4dcef5619930bd394245824c2af52fd21ba7c6fa0e618657d4c3b"
)
FIXTURE = Path(__file__).parent / "fixtures" / "trivy" / "cyclonedx.json"
LIMIT = 10 * 1024 * 1024


def parse(payload=None, **overrides):
    options = {
        "pinned_reference": PINNED,
        "platform": "linux/amd64",
        "scanner_version": "0.75.0",
    }
    options.update(overrides)
    return parse_sbom(FIXTURE.read_bytes() if payload is None else payload, **options)


def document():
    return json.loads(FIXTURE.read_bytes())


def encoded(value):
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


def test_preserves_original_bytes_and_computes_download_integrity_metadata():
    payload = b"\n " + FIXTURE.read_bytes() + b"\t"
    artifact = parse(payload)
    assert artifact.payload == payload
    assert artifact.size_bytes == len(payload)
    assert artifact.sha256 == hashlib.sha256(payload).hexdigest()
    assert artifact.format == "CycloneDX"
    assert artifact.format_version == "1.7"
    assert artifact.scanner_version == "0.75.0"
    assert artifact.pinned_reference == PINNED
    assert artifact.platform == "linux/amd64"


def test_accepts_exactly_ten_mebibytes():
    payload = FIXTURE.read_bytes()
    payload += b" " * (LIMIT - len(payload))
    assert parse(payload).size_bytes == LIMIT


def test_rejects_one_byte_over_the_limit():
    payload = FIXTURE.read_bytes()
    payload += b" " * (LIMIT + 1 - len(payload))
    with pytest.raises(ValueError):
        parse(payload)


def test_size_and_checksum_use_utf8_bytes_rather_than_character_count():
    value = document()
    value["components"][0]["name"] = "demo-caf\u00e9"
    payload = encoded(value)
    artifact = parse(payload)
    assert artifact.size_bytes == len(payload)
    assert artifact.size_bytes > len(payload.decode("utf-8"))
    assert artifact.sha256 == hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize(
    "payload", [b"", b"{", b"[]", b"null", b"\xff", "{}", bytearray(b"{}")]
)
def test_rejects_unusable_document_or_input_type(payload):
    with pytest.raises(ValueError):
        parse(payload)


def test_deep_json_is_rejected_with_value_error():
    with pytest.raises(ValueError):
        parse(b"[" * 2000 + b"0" + b"]" * 2000)


@pytest.mark.parametrize("constant", [b"NaN", b"Infinity", b"-Infinity", b"1e999"])
def test_rejects_nonfinite_json_numbers_even_in_unused_fields(constant):
    payload = FIXTURE.read_bytes().rstrip()[:-1] + b', "unused": ' + constant + b"}"
    with pytest.raises(ValueError):
        parse(payload)


def test_rejects_duplicate_json_keys_even_when_values_match():
    payload = FIXTURE.read_bytes().replace(
        b'"bomFormat": "CycloneDX"',
        b'"bomFormat": "CycloneDX", "bomFormat": "CycloneDX"',
        1,
    )
    with pytest.raises(ValueError):
        parse(payload)


@pytest.mark.parametrize(
    "path,value",
    [
        (("bomFormat",), "SPDX"),
        (("specVersion",), "1.6"),
        (("specVersion",), 1.7),
        (("metadata",), None),
        (("metadata", "component"), []),
        (("metadata", "component", "type"), "library"),
        (("metadata", "component", "purl"), ""),
        (("metadata", "tools", "components"), []),
        (("metadata", "tools", "components", 0, "name"), "different-tool"),
        (("metadata", "tools", "components", 0, "version"), "0.74.0"),
        (("components",), None),
        (("components",), ["package"]),
        (("components",), [{"name": "demo"}]),
        (("components",), [{"type": "library", "name": " "}]),
        (("components",), [{"type": "library", "name": "demo", "version": 1}]),
        (("components",), [{"type": "library", "name": "demo", "bom-ref": 1}]),
    ],
)
def test_rejects_malformed_or_unsupported_metadata_and_inventory(path, value):
    data = document()
    node = data
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value
    with pytest.raises(ValueError):
        parse(encoded(data))


@pytest.mark.parametrize(
    "field", ["metadata", "components", "specVersion", "bomFormat"]
)
def test_rejects_missing_required_sections(field):
    data = document()
    del data[field]
    with pytest.raises(ValueError):
        parse(encoded(data))


@pytest.mark.parametrize(
    "host", ["docker.io", "index.docker.io", "registry-1.docker.io"]
)
def test_accepts_equivalent_docker_hub_hosts_without_changing_download_bytes(host):
    data = document()
    component = data["metadata"]["component"]
    component["purl"] = component["purl"].replace("index.docker.io", host)
    for prop in component["properties"]:
        if prop["name"] == "aquasecurity:trivy:RepoDigest":
            prop["value"] = f"{host}/library/alpine@{PINNED.rpartition('@')[2]}"
    payload = encoded(data)
    assert parse(payload).payload == payload


def test_accepts_architecture_identity_without_an_invented_os_property():
    data = document()
    assert "os=" not in data["metadata"]["component"]["purl"]
    assert parse(encoded(data)).platform == "linux/amd64"


@pytest.mark.parametrize(
    "old,new",
    [
        ("216266c86fc4dcef5619930bd394245824c2af52fd21ba7c6fa0e618657d4c3b", "b" * 64),
        ("library%2Falpine", "library%2Fbusybox"),
        ("arch=amd64", "arch=arm64"),
        ("oci/alpine@", "oci/busybox@"),
        ("index.docker.io", "docker.io.attacker.example"),
        ("arch=amd64", "arch=amd64&arch=arm64"),
    ],
)
def test_rejects_mismatched_or_ambiguous_package_identity(old, new):
    data = document()
    component = data["metadata"]["component"]
    component["purl"] = component["purl"].replace(old, new)
    with pytest.raises(ValueError):
        parse(encoded(data))


def test_rejects_missing_registry_digest_property():
    data = document()
    component = data["metadata"]["component"]
    component["properties"] = [
        prop
        for prop in component["properties"]
        if prop["name"] != "aquasecurity:trivy:RepoDigest"
    ]
    with pytest.raises(ValueError):
        parse(encoded(data))


def test_rejects_conflicting_registry_digest_properties():
    data = document()
    data["metadata"]["component"]["properties"].append(
        {
            "name": "aquasecurity:trivy:RepoDigest",
            "value": "alpine@sha256:" + "b" * 64,
        }
    )
    with pytest.raises(ValueError):
        parse(encoded(data))


def test_rejects_conflicting_tool_versions():
    data = document()
    data["metadata"]["tools"]["components"].append(
        {"name": "trivy", "type": "application", "version": "0.74.0"}
    )
    with pytest.raises(ValueError):
        parse(encoded(data))


def test_accepts_empty_inventory():
    data = document()
    data["components"] = []
    assert parse(encoded(data)).payload == encoded(data)


@pytest.mark.parametrize(
    "override",
    [
        {"platform": "linux/arm64"},
        {"scanner_version": "0.74.0"},
        {"pinned_reference": "docker.io/library/alpine:3.20.0"},
        {
            "pinned_reference": "docker.io.attacker.example/library/alpine@sha256:"
            + "a" * 64
        },
    ],
)
def test_rejects_unsupported_or_unpinned_expected_identity(override):
    with pytest.raises(ValueError):
        parse(**override)


def test_validation_errors_do_not_echo_document_contents():
    data = document()
    data["metadata"]["component"]["purl"] = "private-untrusted-document-value"
    with pytest.raises(ValueError) as error:
        parse(encoded(data))
    assert "private-untrusted-document-value" not in str(error.value)


@pytest.mark.parametrize(
    "artifact_present,error_code",
    [(False, None), (True, "sbom_timeout"), (False, ""), (False, 1)],
)
def test_outcome_rejects_ambiguous_or_unusable_states(artifact_present, error_code):
    artifact = parse() if artifact_present else None
    with pytest.raises(ValueError):
        SbomOutcome(artifact, error_code)


def test_outcome_accepts_one_available_artifact_or_one_failure():
    artifact = parse()
    assert SbomOutcome(artifact, None).artifact is artifact
    assert SbomOutcome(None, "sbom_timeout").error_code == "sbom_timeout"
