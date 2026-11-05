"""Signing policy tests; all credential/registry/signing boundaries are fake."""

import base64
import copy
import json
import sys

import pytest

from scripts.releases import commands, publish
from scripts.releases.supply_chain import signing
from tests import test_release_publish as publication_fixtures
from tests.test_release_disclosure import scanner  # noqa: F401

candidate_dir = publication_fixtures.candidate_dir
publication = publication_fixtures.publication


@pytest.fixture
def signing_case(candidate_dir, publication, monkeypatch):
    result = publish.publish_candidate(
        candidate_dir,
        version="v1.0.0",
        commit=publication[0]["context"]["commit"],
        dry_run=False,
    )
    context = result["build_context"]
    monkeypatch.setattr(signing, "recheck_source", lambda *a: None)
    monkeypatch.setattr(signing, "verify_candidate_source", lambda *a: None)
    monkeypatch.setattr(signing, "_cosign", lambda: "/qualified/cosign")
    calls, reads = [], []

    class Registry:
        def manifest(self, service, reference):
            reads.append((service, reference, len(calls)))
            return {
                k: copy.deepcopy(result["images"][service][k])
                for k in ("digest", "image_id", "diff_ids", "platform", "labels")
            }

    monkeypatch.setattr(signing, "Registry", Registry)

    def run(args, output, **kwargs):
        calls.append(args)
        bundle = kwargs["generated"][0]
        reference = args[-1]
        service = reference.split("containerguard-")[1].split("@")[0]
        kind = (
            "signature"
            if args[1] == "sign"
            else args[args.index("--predicate") + 1].split(".")[-2]
        )
        predicate = (
            {}
            if kind == "signature"
            else json.loads((candidate_dir / f"{service}.{kind}.json").read_bytes())
        )
        subject = {"digest": {"sha256": reference.split("sha256:")[1]}}
        if kind == "signature":
            subject["annotations"] = {}
        else:
            subject["name"] = reference.split("@")[0]
        statement = {
            "_type": "https://in-toto.io/Statement/v1"
            if kind == "signature"
            else "https://in-toto.io/Statement/v0.1",
            "subject": [subject],
            "predicateType": "https://sigstore.dev/cosign/sign/v1"
            if kind == "signature"
            else args[args.index("--type") + 1],
            "predicate": predicate,
        }
        bundle.write_text(
            json.dumps(
                {
                    "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                    "verificationMaterial": protocol_material(),
                    "dsseEnvelope": {
                        "payload": base64.b64encode(
                            json.dumps(statement).encode()
                        ).decode(),
                        "payloadType": "application/vnd.in-toto+json",
                        "signatures": [{"sig": "dGVzdA=="}],
                    },
                }
            )
        )
        output.write_bytes(b"")
        return output

    monkeypatch.setattr(signing, "command_file", run)
    return result, context, calls, reads, run


@pytest.mark.parametrize("mismatch", ["source", "subject", "context", "evidence"])
def test_signer_refuses_source_or_subject_mismatch_before_oidc(
    candidate_dir, signing_case, monkeypatch, tmp_path, mismatch
):
    value, context, calls, _, _ = signing_case
    if mismatch == "source":

        def fail(*a):
            raise ValueError("moved source")

        monkeypatch.setattr(signing, "recheck_source", fail)
    elif mismatch == "subject":
        value["images"]["worker"]["digest"] = "sha256:" + "f" * 64
    elif mismatch == "context":
        monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "999")
    else:
        (candidate_dir / "frontend.provenance.json").write_text("{}")
    with pytest.raises(ValueError):
        signing.sign_release(
            value, candidate_dir, context=context, output=tmp_path / "signed"
        )
    assert calls == []
    assert not (tmp_path / "signed").exists()


def test_attaching_evidence_does_not_change_manifest(
    candidate_dir, signing_case, tmp_path
):
    value, context, calls, reads, _ = signing_case
    original = copy.deepcopy(value)
    result = signing.sign_release(
        value, candidate_dir, context=context, output=tmp_path / "signed"
    )
    assert value == original
    assert result["schema_version"] == 1 and result["status"] == "complete"
    assert len(calls) == 12
    for service in ("api", "worker", "frontend"):
        assert any(s == service and n >= 4 for s, _, n in reads)
        assert all(
            op["status"] == "complete"
            for op in result["images"][service]["operations"].values()
        )
    for args in calls:
        assert "--new-bundle-format=true" in args
        assert not any(
            "insecure" in arg or arg in {"--key", "--identity-token", "--replace"}
            for arg in args
        )
        assert "@sha256:" in args[-1]
    assert (tmp_path / "signed" / "frontend.provenance.json").read_bytes() == (
        candidate_dir / "frontend.provenance.json"
    ).read_bytes()


@pytest.mark.parametrize("fail_at", [0, 1, 4, 11])
def test_signing_failure_records_partial_operations(
    candidate_dir, signing_case, monkeypatch, tmp_path, fail_at
):
    value, context, calls, _, run = signing_case

    def failed(args, output, **kwargs):
        if len(calls) == fail_at:
            calls.append(args)
            raise ValueError("SECRET PROCESS ERROR")
        return run(args, output, **kwargs)

    monkeypatch.setattr(signing, "command_file", failed)
    output = tmp_path / "signed"
    with pytest.raises(ValueError, match="Signing operation failed"):
        signing.sign_release(value, candidate_dir, context=context, output=output)
    receipt = json.loads((output / "receipt.json").read_bytes())
    statuses = [
        op["status"]
        for image in receipt["images"].values()
        for op in image["operations"].values()
    ]
    assert statuses.count("complete") == fail_at
    assert statuses.count("uncertain") == 1
    assert receipt["status"] == "partial"
    safe_record = (output / "receipt.json").read_text()
    assert "SECRET" not in safe_record
    assert "nonfunctional-test-value" not in safe_record
    assert "config.json" not in safe_record
    assert str(tmp_path) not in safe_record
    before = {p.name: p.read_bytes() for p in output.iterdir()}
    with pytest.raises(ValueError):
        signing.sign_release(value, candidate_dir, context=context, output=output)
    assert before == {p.name: p.read_bytes() for p in output.iterdir()}
    assert len(calls) == fail_at + 1


def test_command_bounds_generated_bundle_during_execution(tmp_path):
    bundle = tmp_path / "bundle.json"
    code = (
        "import pathlib,time; "
        "pathlib.Path(__import__('sys').argv[1]).write_bytes(b'x'*8192); "
        "time.sleep(10)"
    )
    with pytest.raises(ValueError, match="bounds"):
        commands.command_file(
            [sys.executable, "-c", code, str(bundle)],
            tmp_path / "stdout",
            limit=1024,
            generated=[bundle],
            timeout=2,
        )
    assert not (tmp_path / "stdout").exists()


@pytest.mark.parametrize(
    "mutation", ["subject", "type", "predicate", "wrapper", "duplicate"]
)
def test_rejects_emitted_wrapper_substitution(
    candidate_dir, signing_case, monkeypatch, tmp_path, mutation
):
    value, context, _, _, run = signing_case

    def tampered(args, output, **kwargs):
        run(args, output, **kwargs)
        bundle = kwargs["generated"][0]
        doc = json.loads(bundle.read_bytes())
        statement = json.loads(base64.b64decode(doc["dsseEnvelope"]["payload"]))
        if mutation == "subject":
            statement["subject"][0]["digest"]["sha256"] = "f" * 64
        elif mutation == "type":
            statement["predicateType"] = "https://wrong.example"
        elif mutation == "predicate":
            statement["predicate"] = {"Data": "rewritten"}
        elif mutation == "wrapper":
            statement["_type"] = "https://in-toto.io/Statement/v0.1"
        else:
            bundle.write_text('{"mediaType":"a","mediaType":"b"}')
            return
        doc["dsseEnvelope"]["payload"] = base64.b64encode(
            json.dumps(statement).encode()
        ).decode()
        bundle.write_text(json.dumps(doc))

    monkeypatch.setattr(signing, "command_file", tampered)
    with pytest.raises(ValueError, match="Signing operation failed"):
        signing.sign_release(
            value, candidate_dir, context=context, output=tmp_path / "signed"
        )
    assert not list((tmp_path / "signed").glob("*.bundle.json"))


def test_signing_environment_cannot_enable_keys_or_bypasses(
    candidate_dir, signing_case, monkeypatch, tmp_path
):
    value, context, _, _, run = signing_case
    for key in (
        "COSIGN_KEY",
        "COSIGN_ALLOW_INSECURE_REGISTRY",
        "COSIGN_REPOSITORY",
        "SIGSTORE_ID_TOKEN",
        "COSIGN_TLOG_UPLOAD",
    ):
        monkeypatch.setenv(key, "hostile")
    observed = []

    def inspect(args, output, **kwargs):
        observed.append(kwargs["env"])
        return run(args, output, **kwargs)

    monkeypatch.setattr(signing, "command_file", inspect)
    signing.sign_release(
        value, candidate_dir, context=context, output=tmp_path / "signed"
    )
    assert len(observed) == 12
    assert all(
        not any(k.startswith(("COSIGN_", "SIGSTORE_")) for k in env) for env in observed
    )


def test_registry_manifest_change_after_attachment_stops_next_service(
    candidate_dir, signing_case, monkeypatch, tmp_path
):
    value, context, calls, _, _ = signing_case

    class Changed:
        def manifest(self, service, reference):
            image = {
                k: copy.deepcopy(value["images"][service][k])
                for k in ("digest", "image_id", "diff_ids", "platform", "labels")
            }
            if len(calls) == 4:
                image["digest"] = "sha256:" + "f" * 64
            return image

    monkeypatch.setattr(signing, "Registry", Changed)
    with pytest.raises(ValueError):
        signing.sign_release(
            value, candidate_dir, context=context, output=tmp_path / "signed"
        )
    assert len(calls) == 4


def protocol_material():
    """Structurally valid protobuf-specs v0.5.1; crypto bytes are fake."""
    return {
        "certificate": {"rawBytes": "dGVzdA=="},
        "tlogEntries": [
            {
                "logIndex": "0",
                "logId": {"keyId": "dGVzdA=="},
                "kindVersion": {"kind": "dsse", "version": "0.0.1"},
                "integratedTime": "1",
                "inclusionPromise": {"signedEntryTimestamp": "dGVzdA=="},
                "inclusionProof": {
                    "logIndex": "0",
                    "rootHash": "dGVzdA==",
                    "treeSize": "1",
                    "hashes": [],
                    "checkpoint": {"envelope": "fake-checkpoint"},
                },
                "canonicalizedBody": "dGVzdA==",
            }
        ],
        "timestampVerificationData": {
            "rfc3161Timestamps": [{"signedTimestamp": "dGVzdA=="}]
        },
    }


def protocol_bundle():
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"digest": {"sha256": "a" * 64}, "annotations": {}}],
        "predicateType": signing.SIGN_TYPE,
        "predicate": {},
    }
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": protocol_material(),
        "dsseEnvelope": {
            "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"sig": "dGVzdA==", "keyid": ""}],
        },
    }


@pytest.mark.parametrize(
    "path,value",
    [
        (("verificationMaterial", "certificate", "unknownNestedField"), True),
        (("verificationMaterial", "certificate", "rawBytes"), 42),
        (("verificationMaterial", "certificate", "rawBytes"), "%%%"),
        (("verificationMaterial", "certificate"), []),
        (("verificationMaterial", "tlogEntries"), "not-an-array"),
        (("verificationMaterial", "tlogEntries", 0, "unknown"), True),
        (("verificationMaterial", "tlogEntries", 0, "logIndex"), True),
        (("verificationMaterial", "tlogEntries", 0, "logIndex"), "9223372036854775808"),
        (("verificationMaterial", "tlogEntries", 0, "logId", "unknown"), True),
        (("verificationMaterial", "tlogEntries", 0, "logId", "keyId"), []),
        (("verificationMaterial", "tlogEntries", 0, "kindVersion", "unknown"), True),
        (("verificationMaterial", "tlogEntries", 0, "kindVersion", "version"), 1),
        (("verificationMaterial", "tlogEntries", 0, "integratedTime"), -1),
        (("verificationMaterial", "tlogEntries", 0, "canonicalizedBody"), "%%%"),
        (
            ("verificationMaterial", "tlogEntries", 0, "inclusionPromise", "unknown"),
            True,
        ),
        (
            (
                "verificationMaterial",
                "tlogEntries",
                0,
                "inclusionPromise",
                "signedEntryTimestamp",
            ),
            1,
        ),
        (("verificationMaterial", "tlogEntries", 0, "inclusionProof", "unknown"), True),
        (("verificationMaterial", "tlogEntries", 0, "inclusionProof", "treeSize"), []),
        (
            ("verificationMaterial", "tlogEntries", 0, "inclusionProof", "hashes"),
            "not-an-array",
        ),
        (("verificationMaterial", "tlogEntries", 0, "inclusionProof", "hashes"), [1]),
        (
            (
                "verificationMaterial",
                "tlogEntries",
                0,
                "inclusionProof",
                "checkpoint",
                "unknown",
            ),
            True,
        ),
        (
            (
                "verificationMaterial",
                "tlogEntries",
                0,
                "inclusionProof",
                "checkpoint",
                "envelope",
            ),
            {},
        ),
        (("verificationMaterial", "timestampVerificationData", "unknown"), True),
        (
            ("verificationMaterial", "timestampVerificationData", "rfc3161Timestamps"),
            "wrong",
        ),
        (
            (
                "verificationMaterial",
                "timestampVerificationData",
                "rfc3161Timestamps",
                0,
                "unknown",
            ),
            True,
        ),
        (
            (
                "verificationMaterial",
                "timestampVerificationData",
                "rfc3161Timestamps",
                0,
                "signedTimestamp",
            ),
            42,
        ),
        (("dsseEnvelope", "signatures", 0, "sig"), 42),
        (("dsseEnvelope", "signatures", 0, "sig"), "%%%"),
        (("dsseEnvelope", "signatures", 0, "keyid"), 42),
        (("dsseEnvelope", "signatures", 0, "unknown"), True),
    ],
)
def test_bundle_rejects_malformed_nested_protocol_fields(tmp_path, path, value):
    document = protocol_bundle()
    target = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    bundle = tmp_path / "api.signature.bundle.json"
    bundle.write_text(json.dumps(document))
    with pytest.raises(ValueError):
        signing._bundle(
            bundle,
            reference="ghcr.io/christophervalle85/containerguard-api@sha256:"
            + "a" * 64,
            kind="signature",
            predicate={},
        )


@pytest.mark.parametrize(
    "path",
    [
        ("verificationMaterial", "certificate", "rawBytes"),
        ("verificationMaterial", "tlogEntries", 0, "logId"),
        ("verificationMaterial", "tlogEntries", 0, "kindVersion", "kind"),
        ("verificationMaterial", "tlogEntries", 0, "inclusionProof"),
        ("verificationMaterial", "tlogEntries", 0, "inclusionProof", "rootHash"),
        ("verificationMaterial", "tlogEntries", 0, "inclusionProof", "checkpoint"),
        (
            "verificationMaterial",
            "tlogEntries",
            0,
            "inclusionPromise",
            "signedEntryTimestamp",
        ),
        (
            "verificationMaterial",
            "timestampVerificationData",
            "rfc3161Timestamps",
            0,
            "signedTimestamp",
        ),
    ],
)
def test_bundle_rejects_missing_required_protocol_fields(tmp_path, path):
    document = protocol_bundle()
    target = document
    for key in path[:-1]:
        target = target[key]
    del target[path[-1]]
    bundle = tmp_path / "api.signature.bundle.json"
    bundle.write_text(json.dumps(document))
    with pytest.raises(ValueError):
        signing._bundle(
            bundle,
            reference="ghcr.io/christophervalle85/containerguard-api@sha256:"
            + "a" * 64,
            kind="signature",
            predicate={},
        )


@pytest.mark.parametrize(
    "profile",
    ["full", "omitted-defaults", "no-optionals", "empty-timestamps", "numeric-int64"],
)
def test_bundle_accepts_pinned_protocol_serialization_profiles(tmp_path, profile):
    document = protocol_bundle()
    material = document["verificationMaterial"]
    entry = material["tlogEntries"][0]
    if profile == "omitted-defaults":
        del entry["logIndex"]
        del entry["integratedTime"]
        del entry["inclusionProof"]["logIndex"]
        del entry["inclusionProof"]["hashes"]
    elif profile == "no-optionals":
        del material["timestampVerificationData"]
        del entry["inclusionPromise"]
        del entry["canonicalizedBody"]
        del document["dsseEnvelope"]["signatures"][0]["keyid"]
    elif profile == "empty-timestamps":
        material["timestampVerificationData"] = {}
    elif profile == "numeric-int64":
        entry["logIndex"] = 0
        entry["integratedTime"] = 1
        entry["inclusionProof"]["treeSize"] = 1
    path = tmp_path / "api.signature.bundle.json"
    path.write_text(json.dumps(document))
    descriptor = signing._bundle(
        path,
        reference="ghcr.io/christophervalle85/containerguard-api@sha256:" + "a" * 64,
        kind="signature",
        predicate={},
    )
    assert descriptor["size_bytes"] == path.stat().st_size


@pytest.mark.parametrize("variant", ["publicKey", "x509CertificateChain", "conflict"])
def test_keyless_v03_bundle_requires_single_certificate_variant(tmp_path, variant):
    document = protocol_bundle()
    material = document["verificationMaterial"]
    material["x509CertificateChain" if variant == "conflict" else variant] = (
        {"hint": "test"}
        if variant == "publicKey"
        else {"certificates": [{"rawBytes": "dGVzdA=="}]}
    )
    if variant != "conflict":
        del material["certificate"]
    path = tmp_path / "api.signature.bundle.json"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError):
        signing._bundle(
            path,
            reference="ghcr.io/christophervalle85/containerguard-api@sha256:"
            + "a" * 64,
            kind="signature",
            predicate={},
        )


def test_sign_cli_passes_guarded_context_and_exact_manifest(
    signing_case, candidate_dir, monkeypatch, tmp_path
):
    from scripts.releases import __main__

    document, context, _, _, _ = signing_case
    path = tmp_path / "release.json"
    path.write_text(json.dumps(document))
    called = []
    monkeypatch.setattr(
        signing,
        "sign_release",
        lambda manifest, directory, **kwargs: called.append(
            (manifest, directory, kwargs)
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "releases",
            "sign",
            "--manifest",
            str(path),
            "--evidence-dir",
            str(candidate_dir),
            "--output-dir",
            str(tmp_path / "signed"),
            "--version",
            context["version"],
            "--commit",
            context["commit"],
        ],
    )
    assert __main__.main() == 0
    assert called == [
        (document, candidate_dir, {"context": context, "output": tmp_path / "signed"})
    ]
