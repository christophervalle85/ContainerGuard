"""Independently verify registry evidence before releasing a compose document."""

import copy
import hashlib
import json
import os
import tempfile
from pathlib import Path

from scripts.releases.commands import command_file
from scripts.releases.identity import SERVICES
from scripts.releases.publish import verify_identity
from scripts.releases.registry import Registry
from scripts.releases.supply_chain import evidence, provenance, signing, tools
from scripts.releases.supply_chain import manifest as manifests

_cosign = signing._cosign
ISSUER = "https://token.actions.githubusercontent.com"
WORKFLOW = "https://github.com/christophervalle85/ContainerGuard/.github/workflows/release.yml@refs/tags/"


class VerificationUnavailable(ValueError):
    """Registry or pinned verification tools could not be used."""


class VerificationIndeterminate(ValueError):
    """The verifier failed without a reliable policy or infrastructure diagnosis."""


class _Verified(dict):
    """Live in-process proof; serialized receipts are audit records only."""

    def __init__(self, value, document):
        super().__init__(value)
        self._document = copy.deepcopy(document)
        self._binding = _binding(document)


def _binding(document):
    return hashlib.sha256(
        json.dumps(
            document, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def _cosign_args(binary, bundle, digest, version, commit, predicate_type):
    return [
        binary,
        "verify-blob-attestation",
        "--bundle",
        str(bundle),
        "--digest",
        digest.split(":", 1)[1],
        "--digestAlg",
        "sha256",
        "--type",
        predicate_type,
        "--certificate-identity=" + WORKFLOW + version,
        "--certificate-oidc-issuer=" + ISSUER,
        "--certificate-github-workflow-sha=" + commit,
        "--certificate-github-workflow-repository=christophervalle85/ContainerGuard",
        "--certificate-github-workflow-trigger=push",
        "--certificate-github-workflow-ref=refs/tags/" + version,
    ]


def _verify_release(
    manifest: Path, evidence_dir: Path, *, version: str, commit: str, output: Path
) -> dict:
    if any(parent.is_symlink() for parent in manifest.parents):
        raise ValueError("unsafe manifest path")
    raw, manifest_descriptor = evidence._load_documents(
        [manifest], kinds=["provenance"]
    )[0]
    document = evidence._parse(raw)
    manifests.validate_release(document, version=version, commit=commit)
    if (
        evidence_dir.is_symlink()
        or not evidence_dir.is_dir()
        or any(p.is_symlink() for p in evidence_dir.parents)
    ):
        raise ValueError("unsafe evidence directory")
    if (
        output.exists()
        or output.is_symlink()
        or any(p.is_symlink() for p in output.parents)
    ):
        raise ValueError("verification output must be new")
    paths = [evidence_dir / f"{s}.{k}.json" for s in SERVICES for k in manifests.KINDS]
    kinds = list(manifests.KINDS) * len(SERVICES)
    snapshots = evidence._load_documents(paths, kinds=kinds)
    documents = {}
    retained = {"release.json": raw}
    for path, kind, (content, descriptor) in zip(paths, kinds, snapshots):
        service = path.name.split(".")[0]
        retained[path.name] = content
        expected = document["images"][service]["evidence"][kind]
        if any(descriptor[k] != expected[k] for k in descriptor):
            raise ValueError("release evidence changed")
        documents[(service, kind)] = evidence._parse(
            content, limit=evidence.KIND_LIMITS[kind]
        )
    try:
        binary = _cosign()
    except (ValueError, RuntimeError, OSError):
        raise VerificationUnavailable("verification tool unavailable") from None
    total = sum(len(content) for content, _ in snapshots)
    result_images = {}
    with tempfile.TemporaryDirectory(prefix="cg-consumer-") as scratch:
        private = Path(scratch)
        (private / "config.json").write_text('{"auths":{}}\n')
        environment = {
            k: os.environ[k]
            for k in ("PATH", "SSL_CERT_FILE", "SSL_CERT_DIR")
            if k in os.environ
        }
        environment.update(HOME=scratch, DOCKER_CONFIG=scratch)
        for path, (content, _) in zip(paths, snapshots):
            (private / path.name).write_bytes(content)
        registry = Registry(anonymous=True)
        for service in SERVICES:
            image = document["images"][service]
            try:
                actual = registry.manifest(service, image["digest"])
            except (ValueError, OSError):
                raise VerificationUnavailable(
                    "registry unavailable or invalid response"
                ) from None
            verify_identity(actual, {**image, "manifest_digest": image["digest"]})
            downloaded = private / (service + ".download")
            try:
                command_file(
                    [binary, "download", "attestation", image["reference"]],
                    downloaded,
                    limit=min(
                        evidence.KIND_LIMITS["verification"],
                        evidence.COMBINED_LIMIT - total,
                    ),
                    env=environment,
                )
            except (ValueError, OSError):
                raise VerificationUnavailable(
                    "registry evidence unavailable or invalid"
                ) from None
            content, _ = evidence._load_documents([downloaded], kinds=["verification"])[
                0
            ]
            total += len(content)
            found = {}
            for index, line in enumerate(content.splitlines()):
                if not line:
                    raise ValueError("empty bundle")
                bundle_document = evidence._parse(
                    line, limit=evidence.KIND_LIMITS["verification"]
                )
                envelope = bundle_document.get("dsseEnvelope", {})
                statement = evidence.decode_document(
                    envelope.get("payload"), kind="verification"
                )
                predicate_type = statement.get("predicateType")
                types = {
                    signing.SIGN_TYPE: "signature",
                    **{v: k for k, v in manifests.PREDICATE_TYPES.items()},
                }
                kind = types.get(predicate_type)
                if kind is None or kind in found:
                    raise ValueError("unexpected or duplicate registry evidence")
                bundle = private / f"{service}.{index}.bundle.json"
                bundle.write_bytes(line)
                predicate = {} if kind == "signature" else documents[(service, kind)]
                descriptor = signing._bundle(
                    bundle, reference=image["reference"], kind=kind, predicate=predicate
                )
                try:
                    command_file(
                        _cosign_args(
                            binary,
                            bundle,
                            image["digest"],
                            version,
                            commit,
                            predicate_type,
                        ),
                        private / "verification.stdout",
                        limit=evidence.KIND_LIMITS["verification"],
                        env=environment,
                    )
                except (ValueError, OSError):
                    raise VerificationIndeterminate(
                        "verification result indeterminate"
                    ) from None
                found[kind] = descriptor["sha256"]
                retained[f"{service}.{kind}.bundle.json"] = line
            if set(found) != {"signature", *manifests.KINDS}:
                raise ValueError("missing registry evidence")
            record = documents[(service, "build-record")]
            identity = {
                "service": service,
                "reference": image["reference"],
                "manifest_digest": image["digest"],
                "image_id": image["image_id"],
                "platform": image["platform"],
                "history": {
                    "build_ref": record["build_invocation"]["build_ref"],
                    "invocation_id": record["build_invocation"]["invocation_id"],
                    "predicate_type": provenance.PREDICATE_TYPE,
                    "predicate_digest": "sha256:"
                    + image["evidence"]["provenance"]["sha256"],
                    "output_manifest": image["digest"],
                    "output_config": image["image_id"],
                },
            }
            provenance.validate_record(
                record,
                image=identity,
                context=document["build_context"],
                files={
                    k: private / f"{service}.{k}.json" for k in ("sbom", "provenance")
                },
            )
            result_images[service] = {
                "reference": image["reference"],
                "bundles": found,
                "evidence": {
                    k: image["evidence"][k]["sha256"] for k in manifests.KINDS
                },
            }
    result = {
        "schema_version": 1,
        "version": version,
        "commit": commit,
        "manifest_sha256": manifest_descriptor["sha256"],
        "issuer": ISSUER,
        "identity": WORKFLOW + version,
        "images": result_images,
        "cosign_version": tools.pins()["cosign"]["version"],
        "trust_checks": [
            "registry",
            "signature",
            "certificate",
            "transparency_log",
            "attestations",
            "evidence",
        ],
    }
    output.mkdir(parents=True, mode=0o700)
    for name, content in retained.items():
        (output / name).write_bytes(content)
    (output / "verification.json").write_text(json.dumps(result, indent=2) + "\n")
    return _Verified(result, document)


def verify_release(
    manifest: Path, evidence_dir: Path, *, version: str, commit: str, output: Path
) -> dict:
    try:
        return _verify_release(
            manifest, evidence_dir, version=version, commit=commit, output=output
        )
    except (KeyError, TypeError, AttributeError, UnicodeError, RecursionError):
        raise ValueError("Invalid release evidence") from None
