import hashlib
import json
import tarfile

import pytest

from scripts.releases import checks
from scripts.releases.supply_chain import evidence, oci, provenance
from tests.test_release_artifacts import containerd_archive, pack, prepare_evidence
from tests.test_release_disclosure import scanner  # noqa: F401
from tests.test_supply_chain_provenance import case
from tests.test_supply_chain_sbom import document as sbom_document

pytestmark = pytest.mark.usefixtures("scanner")


def canonical_archive(path, service):
    containerd_archive(path, service)
    with tarfile.open(path) as archive:
        entries = [
            (m.name, archive.extractfile(m).read())
            for m in archive
            if m.isfile()
            and (m.name.startswith("blobs/") or m.name in ("index.json", "oci-layout"))
        ]
    path.write_bytes(pack(entries))
    return oci.inspect_canonical(path)


def native_files(directory, service, info):
    fixture = directory / (service + "-fixture")
    fixture.mkdir(exist_ok=True)
    context, native, image, _ = case(fixture)
    context["version"] = "v1.0.0"
    native["buildDefinition"]["externalParameters"]["configSource"]["path"] = (
        "Dockerfile." + service
    )
    # Synthetic producer-shaped inputs; these are not a captured native build.
    from scripts.releases.supply_chain.public_inputs import NODE, PYTHON, UV

    selected = (NODE,) if service == "frontend" else (PYTHON, UV)
    for name, tag, digest in selected:
        native["buildDefinition"]["resolvedDependencies"].append(
            {
                "uri": (
                    f"pkg:docker/{name}@{tag}?digest=sha256:{digest}"
                    "&platform=linux%2Famd64"
                ),
                "digest": {"sha256": digest},
            }
        )
    path = (
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        if service == "frontend"
        else (
            "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:"
            "/usr/sbin:/usr/bin:/sbin:/bin"
        )
    )
    native["buildDefinition"]["internalParameters"]["buildConfig"] = {
        "llbDefinition": [{"op": {"Op": {"exec": {"meta": {"env": [path]}}}}}]
    }
    sbom = sbom_document()
    sbom["metadata"]["component"]["properties"][0]["value"] = info["image_id"]
    paths = {
        kind: directory / f"{service}.{kind}.json" for kind in ("sbom", "provenance")
    }
    paths["sbom"].write_text(json.dumps(sbom))
    paths["provenance"].write_text(json.dumps(native))
    image.update(
        service=service,
        reference=f"ghcr.io/christophervalle85/containerguard-{service}@{info['manifest_digest']}",
        image_id=info["image_id"],
        manifest_digest=info["manifest_digest"],
    )
    image["history"].update(
        output_manifest=info["manifest_digest"],
        output_config=info["image_id"],
        predicate_digest="sha256:"
        + hashlib.sha256(paths["provenance"].read_bytes()).hexdigest(),
    )
    (directory / f"{service}.build-record.json").write_text(
        json.dumps(provenance.build_record(image=image, context=context, files=paths))
    )
    return context, {**info, **image}


def sealed_case(directory):
    directory.mkdir(exist_ok=True)
    images = {}
    for service in ("api", "worker", "frontend"):
        info = canonical_archive(directory / f"{service}.oci.tar", service)
        context, images[service] = native_files(directory, service, info)
    prepare_evidence(directory, images)
    checks.seal_evidence(directory, images)
    return context, images


def test_transfer_excludes_runtime_configuration(tmp_path):
    from scripts.releases.supply_chain import manifest

    source, output = tmp_path / "scratch", tmp_path / "transfer"
    context, images = sealed_case(source)
    (source / "verification").mkdir()
    (source / "verification/compose.yaml").write_text(
        "password: sentinel-password-never-transfer"
    )
    handoff = manifest.write_handoff(images, source, context=context)
    document = evidence.read_document(handoff, kind="build-record")
    staged = manifest.stage_transfer(document, source, output)
    assert {p.name for p in staged} == {"handoff.json", "checks-summary.json"} | {
        f"{s}.{suffix}"
        for s in ("api", "worker", "frontend")
        for suffix in ("oci.tar", "sbom.json", "provenance.json", "build-record.json")
    }
    assert not (output / "verification").exists()
    assert all(
        b"sentinel-password-never-transfer" not in path.read_bytes() for path in staged
    )
    assert manifest.validate_handoff(document, output, context=context) == document


@pytest.mark.parametrize(
    "name",
    [
        "api.sbom.json",
        "worker.provenance.json",
        "frontend.build-record.json",
        "api.oci.tar",
        "checks-summary.json",
    ],
)
def test_mutated_evidence_invalidates_handoff(tmp_path, name):
    from scripts.releases.supply_chain import manifest

    context, images = sealed_case(tmp_path)
    path = manifest.write_handoff(images, tmp_path, context=context)
    document = json.loads(path.read_text())
    with (tmp_path / name).open("ab") as stream:
        stream.write(b" ")
    with pytest.raises(ValueError):
        manifest.stage_transfer(document, tmp_path, tmp_path / "transfer")
    assert not (tmp_path / "transfer/handoff.json").exists()


@pytest.mark.parametrize(
    "mutation", ["schema", "unknown", "context", "path", "missing"]
)
def test_handoff_rejects_conflicting_owned_fields(tmp_path, mutation):
    from scripts.releases.supply_chain import manifest

    context, images = sealed_case(tmp_path)
    path = manifest.write_handoff(images, tmp_path, context=context)
    document = json.loads(path.read_text())
    if mutation == "schema":
        document["schema_version"] = 1
    if mutation == "unknown":
        document["unknown"] = True
    if mutation == "context":
        document["context"]["commit"] = "f" * 40
    if mutation == "path":
        document["images"]["api"]["sbom"]["path"] = "../api.sbom.json"
    if mutation == "missing":
        (tmp_path / "worker.provenance.json").unlink()
    with pytest.raises(ValueError):
        manifest.validate_handoff(document, tmp_path, context=context)


def test_evidence_disclosure_failure_removes_handoff(tmp_path, monkeypatch):
    from scripts.releases.supply_chain import manifest

    context, images = sealed_case(tmp_path)

    def blocked(*args, **kwargs):
        raise ValueError("evidence disclosure failed")

    monkeypatch.setattr(evidence, "check_disclosure", blocked)
    with pytest.raises(ValueError, match="disclosure"):
        manifest.write_handoff(images, tmp_path, context=context)
    assert not (tmp_path / "handoff.json").exists()


@pytest.mark.parametrize("mutation", ["unknown", "boolean", "blocked", "identity"])
def test_check_summary_rejects_invalid_owned_fields(tmp_path, mutation):
    from scripts.releases.supply_chain import manifest

    context, images = sealed_case(tmp_path)
    path = manifest.write_handoff(images, tmp_path, context=context)
    document = json.loads(path.read_text())
    summary_path = tmp_path / "checks-summary.json"
    summary = json.loads(summary_path.read_text())
    if mutation == "unknown":
        summary["environment"] = "secret"
    if mutation == "boolean":
        summary["schema_version"] = True
    if mutation == "blocked":
        summary["images"]["api"]["vulnerability"]["blocked"] = True
    if mutation == "identity":
        summary["images"]["worker"]["image_id"] = "sha256:" + "f" * 64
    summary_path.write_text(json.dumps(summary))
    document["checks"] = evidence.describe_file(summary_path, kind="checks")
    with pytest.raises(ValueError):
        manifest.validate_handoff(document, tmp_path, context=context)


def test_symlinked_evidence_is_not_transferred(tmp_path):
    from scripts.releases.supply_chain import manifest

    context, images = sealed_case(tmp_path)
    document = json.loads(
        manifest.write_handoff(images, tmp_path, context=context).read_text()
    )
    source = tmp_path / "api.sbom.json"
    target = tmp_path / "other.json"
    source.rename(target)
    source.symlink_to(target)
    with pytest.raises(ValueError):
        manifest.stage_transfer(document, tmp_path, tmp_path / "transfer")
    assert not (tmp_path / "transfer/handoff.json").exists()


def test_symlinked_seal_directory_does_not_remove_external_handoff(tmp_path):
    from scripts.releases.supply_chain import manifest

    real = tmp_path / "real"
    real.mkdir()
    handoff = real / "handoff.json"
    handoff.write_text("existing external handoff")
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError):
        manifest.write_handoff({}, link, context={})
    assert handoff.read_text() == "existing external handoff"


def test_evidence_changed_after_audit_cannot_be_resealed(tmp_path, monkeypatch):
    from scripts.releases.supply_chain import manifest

    context, images = sealed_case(tmp_path)
    audit = evidence.check_disclosure

    def mutate(paths, output, **kwargs):
        summary = audit(paths, output, **kwargs)
        sbom = tmp_path / "api.sbom.json"
        sbom.write_bytes(sbom.read_bytes() + b" ")
        record = provenance.build_record(
            image=images["api"],
            context=context,
            files={"sbom": sbom, "provenance": tmp_path / "api.provenance.json"},
        )
        (tmp_path / "api.build-record.json").write_text(json.dumps(record))
        return summary

    monkeypatch.setattr(evidence, "check_disclosure", mutate)
    with pytest.raises(ValueError):
        manifest.write_handoff(images, tmp_path, context=context)
    assert not (tmp_path / "handoff.json").exists()


def test_checked_findings_use_the_exact_hashed_summary_snapshot(tmp_path, monkeypatch):
    from scripts.releases.supply_chain import manifest

    context, images = sealed_case(tmp_path)
    handoff = json.loads(
        manifest.write_handoff(images, tmp_path, context=context).read_text()
    )
    path = tmp_path / "checks-summary.json"
    summary = json.loads(path.read_text())
    expected = {
        service: summary["images"][service]["vulnerability"]["counts"]
        for service in ("api", "worker", "frontend")
    }
    read = evidence._load_documents

    def replaced_after_read(*args, **kwargs):
        snapshot = read(*args, **kwargs)
        summary["images"]["api"]["vulnerability"]["counts"] = {"LOW": 999}
        path.write_text(json.dumps(summary))
        return snapshot

    monkeypatch.setattr(evidence, "_load_documents", replaced_after_read)
    assert manifest.read_checked_findings(handoff, tmp_path) == expected
