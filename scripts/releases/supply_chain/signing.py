"""Guarded keyless signing of exact published subjects; receipts are not trust."""

import base64
import copy
import json
import os
import re
import tempfile
from pathlib import Path

from scripts.releases.artifacts import read_json_file
from scripts.releases.candidate import release_context, verify_candidate_source
from scripts.releases.commands import command_file
from scripts.releases.identity import SERVICES, release_tags
from scripts.releases.publish import (
    recheck_source,
    verify_identity,
    verify_publication_context,
)
from scripts.releases.registry import Registry
from scripts.releases.supply_chain import evidence, tools
from scripts.releases.supply_chain import manifest as manifests

LIMIT = evidence.KIND_LIMITS["verification"]
SIGN_TYPE = "https://sigstore.dev/cosign/sign/v1"


def _cosign():
    tools.host_check()
    binary = (
        Path(os.environ.get("CG_RELEASE_TOOLS", tools.ROOT / ".release-tools"))
        / "cosign"
    )
    pin = tools.pins()["cosign"]
    try:
        version = tools.checked_version(binary, pin["sha256"], ["version"])
        if not tools.version_matches(version, pin["version"]):
            raise ValueError
    except Exception:
        raise ValueError("Qualified signer unavailable") from None
    return str(binary)


def _published(registry, document, service):
    image = document["images"][service]
    for reference in (
        image["digest"],
        *release_tags(document["version"], document["commit"]),
    ):
        actual = registry.manifest(service, reference)
        verify_identity(actual, {**image, "manifest_digest": image["digest"]})


def _fields(value, required, optional=frozenset()):
    if (
        not isinstance(value, dict)
        or not required <= value.keys()
        or value.keys() - required - optional
    ):
        raise ValueError("Invalid signer protocol fields")


def _protocol_bytes(value):
    # Bundle bytes are already bounded before parsing; bound encoded values again
    # before decoding. This checks transport shape, never DER or cryptography.
    if not isinstance(value, str) or not value or len(value) > LIMIT:
        raise ValueError("Invalid signer protocol bytes")
    try:
        base64.b64decode(value, validate=True)
    except ValueError:
        raise ValueError("Invalid signer protocol bytes") from None


def _protocol_int64(value):
    if isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,18}", value):
        value = int(value)
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise ValueError("Invalid signer protocol integer")
    return value


def _verification_material(material):
    """Validate the emitted keyless v0.3 profile of protobuf-specs v0.5.1.

    Source: protos/{sigstore_bundle,sigstore_rekor,sigstore_common,envelope}.proto
    at github.com/sigstore/protobuf-specs/tree/v0.5.1. Keyless v0.3 requires
    one leaf certificate, not a public-key hint or a certificate chain. Optional
    zero-valued int64/repeated fields may be omitted by Go protojson. This is
    structural validation only; Task 7 must establish all cryptographic trust.
    """
    _fields(material, {"certificate", "tlogEntries"}, {"timestampVerificationData"})
    certificate = material["certificate"]
    _fields(certificate, {"rawBytes"})
    _protocol_bytes(certificate["rawBytes"])
    entries = material["tlogEntries"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("Keyless signer log evidence missing")
    for entry in entries:
        _fields(
            entry,
            {"logId", "kindVersion", "inclusionProof"},
            {"logIndex", "integratedTime", "inclusionPromise", "canonicalizedBody"},
        )
        for key in ("logIndex", "integratedTime"):
            _protocol_int64(entry.get(key, "0"))
        _fields(entry["logId"], {"keyId"})
        _protocol_bytes(entry["logId"]["keyId"])
        _fields(entry["kindVersion"], {"kind", "version"})
        if any(not isinstance(v, str) or not v for v in entry["kindVersion"].values()):
            raise ValueError("Invalid signer log kind/version")
        proof = entry["inclusionProof"]
        _fields(proof, {"rootHash", "treeSize", "checkpoint"}, {"logIndex", "hashes"})
        _protocol_int64(proof.get("logIndex", "0"))
        if _protocol_int64(proof["treeSize"]) == 0:
            raise ValueError("Invalid signer log tree size")
        _protocol_bytes(proof["rootHash"])
        hashes = proof.get("hashes", [])
        if not isinstance(hashes, list):
            raise ValueError("Invalid signer log proof hashes")
        for value in hashes:
            _protocol_bytes(value)
        _fields(proof["checkpoint"], {"envelope"})
        checkpoint = proof["checkpoint"]["envelope"]
        if not isinstance(checkpoint, str) or not checkpoint:
            raise ValueError("Invalid signer checkpoint")
        if "inclusionPromise" in entry:
            _fields(entry["inclusionPromise"], {"signedEntryTimestamp"})
            _protocol_bytes(entry["inclusionPromise"]["signedEntryTimestamp"])
        if "canonicalizedBody" in entry:
            _protocol_bytes(entry["canonicalizedBody"])
    if "timestampVerificationData" in material:
        timestamps = material["timestampVerificationData"]
        _fields(timestamps, set(), {"rfc3161Timestamps"})
        stamps = timestamps.get("rfc3161Timestamps", [])
        if not isinstance(stamps, list):
            raise ValueError("Invalid signer timestamps")
        for stamp in stamps:
            _fields(stamp, {"signedTimestamp"})
            _protocol_bytes(stamp["signedTimestamp"])


def _bundle(path, *, reference, kind, predicate):
    """Check actual v3.1.3 bundle/statement bindings, not cryptographic trust."""
    document = evidence.read_document(path, kind="verification")
    if (
        set(document) != {"mediaType", "verificationMaterial", "dsseEnvelope"}
        or document["mediaType"] != "application/vnd.dev.sigstore.bundle.v0.3+json"
    ):
        raise ValueError("Invalid signer bundle")
    _verification_material(document["verificationMaterial"])
    envelope = document["dsseEnvelope"]
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"payload", "payloadType", "signatures"}
        or envelope["payloadType"] != "application/vnd.in-toto+json"
        or not isinstance(envelope["signatures"], list)
        or len(envelope["signatures"]) != 1
        or not isinstance(envelope["signatures"][0], dict)
        or set(envelope["signatures"][0]) - {"sig", "keyid"}
        or not envelope["signatures"][0].get("sig")
    ):
        raise ValueError("Invalid signer envelope")
    signature = envelope["signatures"][0]
    _fields(signature, {"sig"}, {"keyid"})
    _protocol_bytes(signature["sig"])
    if "keyid" in signature and not isinstance(signature["keyid"], str):
        raise ValueError("Invalid signer key identifier")
    statement = evidence.decode_document(envelope["payload"], kind="verification")
    signature = kind == "signature"
    expected_subject = {"digest": {"sha256": reference.split("sha256:")[1]}}
    if signature:
        expected_subject["annotations"] = {}
    else:
        expected_subject["name"] = reference.split("@")[0]
    if (
        set(statement) != {"_type", "subject", "predicateType", "predicate"}
        or statement["_type"]
        != (
            "https://in-toto.io/Statement/v1"
            if signature
            else "https://in-toto.io/Statement/v0.1"
        )
        or statement["subject"] != [expected_subject]
        or statement["predicateType"]
        != (SIGN_TYPE if signature else manifests.PREDICATE_TYPES[kind])
        or statement["predicate"] != predicate
    ):
        raise ValueError("Signer statement differs from validated evidence")
    return evidence.describe_file(path, kind="verification")


def sign_release(
    manifest: dict, directory: Path, *, context: dict, output: Path
) -> dict:
    """Create a new receipt directory; any attempted failure requires investigation."""
    if (
        output.exists()
        or output.is_symlink()
        or any(p.is_symlink() for p in output.parents)
        or directory.is_symlink()
        or any(p.is_symlink() for p in directory.parents)
        or not directory.is_dir()
    ):
        raise ValueError("Signing requires a fresh safe output directory")
    document = copy.deepcopy(manifest)
    version, commit = context["version"], context["commit"]
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("Signing requires guarded GitHub context")
    verify_publication_context(version, commit)
    context = release_context(version, commit, context)
    manifests.validate_release(document, version=version, commit=commit)
    if document["build_context"] != context:
        raise ValueError("Signing context mismatch")
    handoff = read_json_file(directory / "handoff.json")
    manifests.validate_handoff(handoff, directory, context=context)
    if (
        manifests.read_checked_findings(handoff, directory)
        != document["remaining_findings"]
    ):
        raise ValueError("Signing findings mismatch")
    snapshots, parsed = {}, {}
    for service in SERVICES:
        item = handoff["images"][service]
        identity = item["identity"]
        published = document["images"][service]
        if any(
            published[k] != identity[v]
            for k, v in (
                ("reference", "reference"),
                ("digest", "manifest_digest"),
                ("image_id", "image_id"),
                ("diff_ids", "diff_ids"),
                ("platform", "platform"),
            )
        ):
            raise ValueError("Signing subject differs from candidate")
        for kind in manifests.KINDS:
            descriptor = published["evidence"][kind]
            if {k: v for k, v in descriptor.items() if k != "predicate_type"} != item[
                kind
            ]:
                raise ValueError("Signing evidence differs from candidate")
            raw, actual = evidence._load_documents(
                [directory / descriptor["path"]], kinds=[kind]
            )[0]
            if any(actual[k] != descriptor[k] for k in actual):
                raise ValueError("Signing evidence changed")
            snapshots[descriptor["path"]] = raw
            parsed[(service, kind)] = evidence._parse(
                raw, limit=evidence.KIND_LIMITS[kind]
            )
    verify_candidate_source(version, commit)
    recheck_source(version, commit)
    registry = Registry()
    for service in SERVICES:
        _published(registry, document, service)
    binary = _cosign()
    receipt = {
        "schema_version": 1,
        "context": context,
        "status": "partial",
        "images": {
            service: {
                "reference": document["images"][service]["reference"],
                "operations": {
                    kind: {"status": "pending"}
                    for kind in ("signature", *manifests.KINDS)
                },
            }
            for service in SERVICES
        },
    }
    output.mkdir(mode=0o700)

    def save():
        temporary = output / ".receipt.tmp"
        temporary.write_text(json.dumps(receipt, indent=2) + "\n")
        os.replace(temporary, output / "receipt.json")

    save()
    try:
        for name, raw in snapshots.items():
            (output / name).write_bytes(raw)
        # Isolate credentials/configuration from retained release evidence. Only the
        # GitHub ambient provider is selected; no COSIGN_* environment overrides.
        with tempfile.TemporaryDirectory(prefix="cg-keyless-") as scratch:
            home = Path(scratch)
            token, actor = (
                os.environ.get("GITHUB_TOKEN"),
                os.environ.get("GITHUB_ACTOR"),
            )
            if not token or not actor:
                raise ValueError("Signer registry credentials unavailable")
            auth = home / "config.json"
            auth.write_text(
                json.dumps(
                    {
                        "auths": {
                            "ghcr.io": {
                                "auth": base64.b64encode(
                                    (actor + ":" + token).encode()
                                ).decode()
                            }
                        }
                    }
                )
            )
            auth.chmod(0o600)
            environment = {
                k: os.environ[k]
                for k in (
                    "PATH",
                    "ACTIONS_ID_TOKEN_REQUEST_URL",
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
                )
                if k in os.environ
            }
            environment.update(HOME=scratch, DOCKER_CONFIG=scratch)
            total = sum(map(len, snapshots.values()))
            for service in SERVICES:
                _published(registry, document, service)
                reference = document["images"][service]["reference"]
                for kind in ("signature", *manifests.KINDS):
                    operation = receipt["images"][service]["operations"][kind]
                    operation["status"] = "uncertain"
                    save()  # persisted before the first external side effect
                    bundle = home / f"{service}.{kind}.bundle.json"
                    args = [
                        binary,
                        "sign" if kind == "signature" else "attest",
                        "--yes",
                        "--new-bundle-format=true",
                        "--oidc-provider=github-actions",
                        "--tlog-upload=true",
                        "--bundle",
                        str(bundle),
                    ]
                    if kind != "signature":
                        predicate_path = home / f"{service}.{kind}.json"
                        predicate_path.write_bytes(snapshots[predicate_path.name])
                        args += [
                            "--type",
                            manifests.PREDICATE_TYPES[kind],
                            "--predicate",
                            str(predicate_path),
                        ]
                    args.append(reference)
                    command_file(
                        args,
                        home / "stdout",
                        limit=min(LIMIT, evidence.COMBINED_LIMIT - total),
                        generated=[bundle],
                        env=environment,
                    )
                    descriptor = _bundle(
                        bundle,
                        reference=reference,
                        kind=kind,
                        predicate={}
                        if kind == "signature"
                        else parsed[(service, kind)],
                    )
                    total += descriptor["size_bytes"]
                    if total > evidence.COMBINED_LIMIT:
                        raise ValueError("Combined signing evidence exceeded bounds")
                    # Retain exactly the bounded snapshot validated above.
                    raw, actual = evidence._load_documents(
                        [bundle], kinds=["verification"]
                    )[0]
                    if any(actual[k] != descriptor[k] for k in actual):
                        raise ValueError("Signer bundle changed")
                    (output / bundle.name).write_bytes(raw)
                    operation.update(status="complete", bundle=descriptor)
                    save()
                _published(registry, document, service)
            receipt["status"] = "complete"
            save()
    except BaseException:
        save()
        raise ValueError(
            "Signing operation failed; investigate partial receipt"
        ) from None
    return receipt
