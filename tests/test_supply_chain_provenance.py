import hashlib
import json

import pytest

from scripts.releases.supply_chain import evidence, provenance
from tests.test_supply_chain_probe import synthetic_contract_predicate
from tests.test_supply_chain_sbom import document as sbom_document


def case(tmp_path):
    context = {
        "version": "v0.2.0",
        "commit": "a" * 40,
        "repository": "christophervalle85/ContainerGuard",
        "workflow": ".github/workflows/release.yml",
        "run_id": "123",
        "run_attempt": "1",
    }
    native = synthetic_contract_predicate()
    source = "https://github.com/christophervalle85/ContainerGuard"
    definition = native["buildDefinition"]
    definition["externalParameters"]["configSource"]["uri"] = (
        source + "#" + context["commit"]
    )
    definition["externalParameters"]["configSource"]["path"] = "Dockerfile.api"
    definition["resolvedDependencies"][0]["uri"] = source + "#" + context["commit"]
    native["runDetails"]["metadata"]["buildkit_metadata"]["vcs"]["source"] = source
    files = {
        "sbom": tmp_path / "api.sbom.json",
        "provenance": tmp_path / "api.provenance.json",
    }
    files["sbom"].write_text(json.dumps(sbom_document()))
    files["provenance"].write_text(json.dumps(native))
    image = {
        "service": "api",
        "reference": "ghcr.io/christophervalle85/containerguard-api@sha256:" + "b" * 64,
        "manifest_digest": "sha256:" + "b" * 64,
        "image_id": "sha256:" + "c" * 64,
        "platform": "linux/amd64",
        "history": {
            "build_ref": "builder/node/" + "r" * 25,
            "invocation_id": "i" * 25,
            "predicate_type": "https://slsa.dev/provenance/v1",
            "predicate_digest": "sha256:"
            + hashlib.sha256(files["provenance"].read_bytes()).hexdigest(),
            "output_manifest": "sha256:" + "b" * 64,
            "output_config": "sha256:" + "c" * 64,
        },
    }
    return context, native, image, files


def test_native_and_build_record_bind_exact_raw_files(tmp_path):
    ctx, native, image, files = case(tmp_path)
    assert provenance.validate_native(native, image=image, context=ctx) == native
    record = provenance.build_record(image=image, context=ctx, files=files)
    assert set(record) == {
        "schema_version",
        "service",
        "reference",
        "manifest_digest",
        "platform",
        "context",
        "build_invocation",
        "builder",
        "sbom",
        "provenance",
    }
    assert record["builder"] == {"id": ""}
    assert record["provenance"] == evidence.describe_file(
        files["provenance"], kind="provenance"
    )
    assert record["sbom"] == evidence.describe_file(files["sbom"], kind="sbom")


def test_source_only_in_supplement_is_insufficient(tmp_path):
    ctx, native, image, _ = case(tmp_path)
    del native["buildDefinition"]["externalParameters"]["configSource"]["digest"]
    with pytest.raises(ValueError, match="native"):
        provenance.validate_native(native, image=image, context=ctx)


def test_sbom_swapped_between_services_rejected(tmp_path):
    ctx, _, image, files = case(tmp_path)
    record = provenance.build_record(image=image, context=ctx, files=files)
    files["sbom"].write_text(json.dumps({**sbom_document(), "version": 2}))
    with pytest.raises(ValueError, match="record"):
        provenance.validate_record(record, image=image, context=ctx, files=files)


@pytest.mark.parametrize(
    "mutation",
    [
        "commit",
        "dockerfile",
        "target",
        "material",
        "invocation",
        "history-manifest",
        "history-config",
        "history-type",
        "builder-version",
        "context-unknown",
    ],
)
def test_native_identity_conflicts_rejected(tmp_path, mutation):
    ctx, native, image, _ = case(tmp_path)
    if mutation == "commit":
        native["buildDefinition"]["externalParameters"]["configSource"]["digest"][
            "sha1"
        ] = "d" * 40
    if mutation == "dockerfile":
        native["buildDefinition"]["externalParameters"]["configSource"]["path"] = (
            "Dockerfile.worker"
        )
    if mutation == "target":
        native["buildDefinition"]["internalParameters"].pop("targetPlatform")
    if mutation == "material":
        native["buildDefinition"]["resolvedDependencies"].append(
            {"uri": ctx["repository"], "digest": {}}
        )
    if mutation == "invocation":
        native["runDetails"]["metadata"]["invocationId"] = "wrong"
    if mutation == "history-manifest":
        image["history"]["output_manifest"] = "sha256:" + "d" * 64
    if mutation == "history-config":
        image["history"]["output_config"] = "sha256:" + "d" * 64
    if mutation == "history-type":
        image["history"]["predicate_type"] = "https://slsa.dev/provenance/v0.2"
    if mutation == "builder-version":
        native["runDetails"]["builder"]["version"] = {"buildkit": "0.1.0"}
    if mutation == "context-unknown":
        ctx["environment"] = "private"
    with pytest.raises(ValueError):
        provenance.validate_native(native, image=image, context=ctx)


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown-external",
        "invalid-digest-type",
        "unknown-metadata",
        "incomplete",
        "timestamp",
        "unknown-resource",
    ],
)
def test_native_schema_contract_rejects_invalid_fields(tmp_path, mutation):
    ctx, native, image, _ = case(tmp_path)
    if mutation == "unknown-external":
        native["buildDefinition"]["externalParameters"]["unknown"] = True
    if mutation == "invalid-digest-type":
        native["buildDefinition"]["resolvedDependencies"].append(
            {"uri": "pkg:oci/fixture", "digest": {"sha256": 1}}
        )
    if mutation == "unknown-metadata":
        native["runDetails"]["metadata"]["unknown"] = True
    if mutation == "incomplete":
        native["runDetails"]["metadata"]["buildkit_completeness"]["request"] = False
    if mutation == "timestamp":
        native["runDetails"]["metadata"]["startedOn"] = "yesterday"
    if mutation == "unknown-resource":
        native["buildDefinition"]["resolvedDependencies"][0]["unknown"] = True
    with pytest.raises(ValueError, match="native"):
        provenance.validate_native(native, image=image, context=ctx)


def test_owned_record_schema_rejects_boolean_schema_version(tmp_path):
    ctx, _, image, files = case(tmp_path)
    record = provenance.build_record(image=image, context=ctx, files=files)
    record["schema_version"] = True
    with pytest.raises(ValueError, match="record"):
        provenance.validate_record(record, image=image, context=ctx, files=files)


@pytest.mark.parametrize(
    "mutation",
    ["missing", "duplicate", "conflicting", "wrong-config", "manifest-as-config"],
)
def test_sbom_image_identity_rejected_before_record_creation(tmp_path, mutation):
    ctx, _, image, files = case(tmp_path)
    doc = sbom_document()
    identity = {"name": "aquasecurity:trivy:ImageID", "value": image["image_id"]}
    doc["metadata"]["component"] = {
        "type": "container",
        "name": "fixture",
        "properties": [identity],
    }
    claims = doc["metadata"]["component"]["properties"]
    if mutation == "missing":
        claims.clear()
    if mutation == "duplicate":
        claims.append(dict(identity))
    if mutation == "conflicting":
        claims.append({**identity, "value": "sha256:" + "d" * 64})
    if mutation == "wrong-config":
        identity["value"] = "sha256:" + "d" * 64
    if mutation == "manifest-as-config":
        identity["value"] = image["manifest_digest"]
    files["sbom"].write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="record"):
        provenance.build_record(image=image, context=ctx, files=files)


def test_real_other_image_sbom_cannot_be_bound_to_api(tmp_path):
    from pathlib import Path

    ctx, _, image, files = case(tmp_path)
    files["sbom"].write_bytes(
        (
            Path(__file__).parent / "fixtures/releases/trivy-0.75.0-cg.1.cdx17.json"
        ).read_bytes()
    )
    with pytest.raises(ValueError, match="record"):
        provenance.build_record(image=image, context=ctx, files=files)


@pytest.mark.parametrize("store", ["classic", "containerd"])
def test_matching_config_identity_accepted_independent_of_store(
    tmp_path, monkeypatch, store
):
    import shutil

    from scripts.releases.supply_chain import oci
    from tests.test_supply_chain_oci import fixture

    path, selected, _, config = fixture(tmp_path)
    expected = oci.inspect_canonical(path)
    calls = []

    def run(args):
        calls.append(args)
        if args[1:3] == ["image", "inspect"]:
            return json.dumps(
                [
                    {
                        "Id": config if store == "classic" else selected["digest"],
                        "Os": "linux",
                        "Architecture": "amd64",
                        "RootFS": {"Layers": expected["diff_ids"]},
                    }
                ]
            )
        if args[1:3] == ["image", "save"]:
            source = calls[0][-1].removeprefix("docker-archive:")
            shutil.copyfile(source, args[args.index("--output") + 1])
        return ""

    monkeypatch.setattr(oci, "_run", run)
    monkeypatch.setattr(oci, "_skopeo", lambda: "skopeo")
    imported = oci.import_for_checks(path, "owned:test")
    assert imported["image_id"] == config != selected["digest"]
    ctx, _, image, files = case(tmp_path)
    image.update(
        {key: imported[key] for key in ("image_id", "manifest_digest", "platform")}
    )
    image["reference"] = (
        "ghcr.io/christophervalle85/containerguard-api@" + imported["manifest_digest"]
    )
    image["history"]["output_manifest"] = imported["manifest_digest"]
    image["history"]["output_config"] = imported["image_id"]
    doc = sbom_document()
    doc["metadata"]["component"]["properties"][0]["value"] = imported["image_id"]
    files["sbom"].write_text(json.dumps(doc))
    assert (
        provenance.build_record(image=image, context=ctx, files=files)[
            "manifest_digest"
        ]
        == imported["manifest_digest"]
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "integer-completeness",
        "empty-dict-builder-dependencies",
        "empty-string-byproducts",
        "bad-builder-resource",
        "bad-byproduct-resource",
    ],
)
def test_native_empty_wrong_types_rejected(tmp_path, mutation):
    ctx, native, image, _ = case(tmp_path)
    if mutation == "integer-completeness":
        native["runDetails"]["metadata"]["buildkit_completeness"] = {
            "request": 1,
            "resolvedDependencies": 1,
        }
    if mutation == "empty-dict-builder-dependencies":
        native["runDetails"]["builder"]["builderDependencies"] = {}
    if mutation == "empty-string-byproducts":
        native["runDetails"]["byproducts"] = ""
    if mutation == "bad-builder-resource":
        native["runDetails"]["builder"]["builderDependencies"] = [{}]
    if mutation == "bad-byproduct-resource":
        native["runDetails"]["byproducts"] = [{}]
    with pytest.raises(ValueError, match="native"):
        provenance.validate_native(native, image=image, context=ctx)


def test_native_legitimate_empty_lists_and_extension_preserved(tmp_path):
    ctx, native, image, _ = case(tmp_path)
    native["runDetails"]["builder"]["builderDependencies"] = []
    native["runDetails"]["byproducts"] = []
    native["buildDefinition"]["internalParameters"]["buildkit_custom_field"] = {
        "value": True
    }
    assert provenance.validate_native(native, image=image, context=ctx) == native


def test_other_image_sbom_swapped_after_record_creation_rejected(tmp_path):
    ctx, _, image, files = case(tmp_path)
    record = provenance.build_record(image=image, context=ctx, files=files)
    doc = sbom_document()
    doc["metadata"]["component"]["properties"][0]["value"] = "sha256:" + "d" * 64
    files["sbom"].write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="record"):
        provenance.validate_record(record, image=image, context=ctx, files=files)


def test_native_rejects_unknown_image_material(tmp_path):
    # Synthetic BuildKit-shaped material; a public name does not establish trust.
    ctx, native, image, _ = case(tmp_path)
    native["buildDefinition"]["resolvedDependencies"].append(
        {
            "uri": "pkg:docker/unreviewed@latest?platform=linux%2Famd64",
            "digest": {"sha256": "f" * 64},
        }
    )
    with pytest.raises(ValueError, match="native"):
        provenance.validate_native(native, image=image, context=ctx)


@pytest.mark.parametrize(
    "mutation",
    [
        "digest",
        "tag",
        "platform",
        "missing-platform",
        "service",
        "duplicate",
        "source",
        "dockerfile",
    ],
)
def test_synthetic_reviewed_materials_are_bound_to_source_and_service(
    tmp_path, mutation
):
    from scripts.releases.supply_chain.public_inputs import PYTHON

    ctx, native, image, _ = case(tmp_path)
    name, tag, digest = PYTHON
    item = {
        "uri": f"pkg:docker/{name}@{tag}?digest=sha256:{digest}&platform=linux%2Famd64",
        "digest": {"sha256": digest},
    }
    dependencies = native["buildDefinition"]["resolvedDependencies"]
    dependencies.append(item)
    assert provenance.validate_native(native, image=image, context=ctx) == native
    if mutation == "digest":
        item["digest"]["sha256"] = "f" * 64
    elif mutation == "tag":
        item["uri"] = item["uri"].replace(tag, "latest")
    elif mutation == "platform":
        item["uri"] = item["uri"].replace("amd64", "arm64")
    elif mutation == "missing-platform":
        item["uri"] = item["uri"].split("&platform=")[0]
    elif mutation == "service":
        image["service"] = "frontend"
        image["reference"] = image["reference"].replace("-api@", "-frontend@")
        native["buildDefinition"]["externalParameters"]["configSource"]["path"] = (
            "Dockerfile.frontend"
        )
    elif mutation == "duplicate":
        dependencies.append(item.copy())
    elif mutation == "source":
        native["buildDefinition"]["externalParameters"]["configSource"]["uri"] += "x"
    else:
        native["buildDefinition"]["externalParameters"]["configSource"]["path"] = (
            "Dockerfile.worker"
        )
    with pytest.raises(ValueError, match="native"):
        provenance.validate_native(native, image=image, context=ctx)


def test_synthetic_worker_http_material_is_exact(tmp_path, monkeypatch):
    from scripts.releases.supply_chain import public_inputs

    ctx, native, image, _ = case(tmp_path)
    image["service"] = "worker"
    image["reference"] = image["reference"].replace("-api@", "-worker@")
    native["buildDefinition"]["externalParameters"]["configSource"]["path"] = (
        "Dockerfile.worker"
    )
    uri, digest = public_inputs.HTTP
    material = {"uri": uri, "digest": {"sha256": digest}}
    native["buildDefinition"]["resolvedDependencies"].append(material)
    assert provenance.validate_native(native, image=image, context=ctx) == native
    material["digest"]["sha256"] = "f" * 64
    with pytest.raises(ValueError, match="native"):
        provenance.validate_native(native, image=image, context=ctx)
    material["digest"]["sha256"] = digest
    material["uri"] += "?unknown=true"
    with pytest.raises(ValueError, match="native"):
        provenance.validate_native(native, image=image, context=ctx)
    material["uri"] = uri
    monkeypatch.setitem(public_inputs.DOCKERFILES, "worker", "f" * 64)
    with pytest.raises(ValueError, match="native"):
        provenance.validate_native(native, image=image, context=ctx)
