"""SLSA v1 / pinned BuildKit contract and exact-byte build records."""

import copy
import json
import re
from datetime import datetime

from scripts.releases.supply_chain import evidence, public_inputs, sbom
from scripts.releases.supply_chain.tools import pins

SOURCE = "https://github.com/christophervalle85/ContainerGuard"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = (
    "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md"
)
CONTEXT_FIELDS = {
    "version",
    "commit",
    "repository",
    "workflow",
    "run_id",
    "run_attempt",
}
RECORD_FIELDS = {
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
DIGEST = re.compile(r"sha256:[a-f0-9]{64}")


def _inputs(image, context):
    if not isinstance(context, dict) or set(context) != CONTEXT_FIELDS:
        raise ValueError("invalid release context")
    if (
        context["repository"] != "christophervalle85/ContainerGuard"
        or context["workflow"] != ".github/workflows/release.yml"
        or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", context["version"])
        or not re.fullmatch(r"[a-f0-9]{40}", context["commit"])
        or any(
            not re.fullmatch(r"[1-9][0-9]*", context[key])
            for key in ("run_id", "run_attempt")
        )
    ):
        raise ValueError("invalid release context")
    if (
        image["service"] not in ("api", "worker", "frontend")
        or image["platform"] != "linux/amd64"
    ):
        raise ValueError("invalid release image")
    if not DIGEST.fullmatch(image["manifest_digest"]) or not DIGEST.fullmatch(
        image["image_id"]
    ):
        raise ValueError("invalid release image digest")
    if image["reference"] != (
        f"ghcr.io/christophervalle85/containerguard-{image['service']}@"
        f"{image['manifest_digest']}"
    ):
        raise ValueError("invalid release reference")
    history = image["history"]
    if (
        set(history)
        != {
            "build_ref",
            "invocation_id",
            "predicate_type",
            "predicate_digest",
            "output_manifest",
            "output_config",
        }
        or history["predicate_type"] != PREDICATE_TYPE
        or not DIGEST.fullmatch(history["predicate_digest"])
        or history["output_manifest"] != image["manifest_digest"]
        or history["output_config"] != image["image_id"]
        or not re.fullmatch(
            r"[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[a-z0-9]{25}", history["build_ref"]
        )
        or not re.fullmatch(r"[a-z0-9]{25}", history["invocation_id"])
    ):
        raise ValueError("invalid native history association")


def _resource(material):
    allowed = {
        "uri",
        "digest",
        "name",
        "downloadLocation",
        "mediaType",
        "content",
        "annotations",
    }
    if (
        not isinstance(material, dict)
        or set(material) - allowed
        or not isinstance(material.get("digest"), dict)
        or not material["digest"]
    ):
        raise ValueError
    if any(
        not isinstance(key, str) or not isinstance(value, str) or not value
        for key, value in material["digest"].items()
    ):
        raise ValueError
    for key in ("uri", "name", "downloadLocation", "mediaType", "content"):
        if key in material and not isinstance(material[key], str):
            raise ValueError
    if "annotations" in material and not isinstance(material["annotations"], dict):
        raise ValueError


def _metadata(metadata):
    allowed = {
        "invocationId",
        "startedOn",
        "finishedOn",
        "buildkit_metadata",
        "buildkit_hermetic",
        "buildkit_completeness",
        "buildkit_reproducible",
    }
    if not isinstance(metadata, dict) or set(metadata) - allowed:
        raise ValueError
    completeness = metadata["buildkit_completeness"]
    if (
        not isinstance(completeness, dict)
        or set(completeness) != {"request", "resolvedDependencies"}
        or any(
            type(value) is not bool or value is not True
            for value in completeness.values()
        )
    ):
        raise ValueError
    timestamps = []
    for key in ("startedOn", "finishedOn"):
        value = metadata[key]
        if not isinstance(value, str):
            raise ValueError
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError
        timestamps.append(timestamp)
    if timestamps[1] < timestamps[0]:
        raise ValueError
    for key in ("buildkit_hermetic", "buildkit_reproducible"):
        if key in metadata and type(metadata[key]) is not bool:
            raise ValueError
    buildkit = metadata["buildkit_metadata"]
    if not isinstance(buildkit, dict) or set(buildkit) - {
        "vcs",
        "source",
        "layers",
        "sysUsage",
        "network",
    }:
        raise ValueError
    if "vcs" in buildkit and (
        not isinstance(buildkit["vcs"], dict)
        or any(not isinstance(value, str) for value in buildkit["vcs"].values())
    ):
        raise ValueError


def validate_native(document: dict, *, image: dict, context: dict) -> dict:
    """Require source in native evidence, independently of the supplement."""
    try:
        _inputs(image, context)
        if set(document) != {"buildDefinition", "runDetails"}:
            raise ValueError
        definition, run = document["buildDefinition"], document["runDetails"]
        if set(definition) != {
            "buildType",
            "externalParameters",
            "internalParameters",
            "resolvedDependencies",
        }:
            raise ValueError
        if not {"builder", "metadata"} <= set(run) or set(run) - {
            "builder",
            "metadata",
            "byproducts",
        }:
            raise ValueError
        external, internal = (
            definition["externalParameters"],
            definition["internalParameters"],
        )
        if set(external) != {"configSource", "request"}:
            raise ValueError
        request = external["request"]
        if not isinstance(request, dict) or set(request) - {
            "frontend",
            "args",
            "secrets",
            "ssh",
            "locals",
            "inputs",
            "root",
            "compatibilityVersion",
        }:
            raise ValueError
        if "args" in request and (
            not isinstance(request["args"], dict)
            or any(not isinstance(value, str) for value in request["args"].values())
        ):
            raise ValueError
        if (
            not isinstance(internal["builderPlatform"], str)
            or not internal["builderPlatform"]
        ):
            raise ValueError
        commit, uri = context["commit"], SOURCE + "#" + context["commit"]
        if (
            definition["buildType"] != BUILD_TYPE
            or external["configSource"]
            != {
                "uri": uri,
                "digest": {"sha1": commit},
                "path": "Dockerfile." + image["service"],
            }
            or external["request"]["frontend"] != "dockerfile.v0"
            or internal["targetPlatform"] != "linux/amd64"
        ):
            raise ValueError
        dependencies = definition["resolvedDependencies"]
        if (
            not isinstance(dependencies, list)
            or {"uri": uri, "digest": {"sha1": commit}} not in dependencies
        ):
            raise ValueError
        public_inputs.materials(document, image["service"], commit)
        for material in dependencies:
            _resource(material)
            if not isinstance(material, dict) or not material.get("digest"):
                raise ValueError
            if material.get("uri") == SOURCE or material.get("uri", "").startswith(
                SOURCE + "#"
            ):
                if material.get("uri") != uri or material["digest"] != {"sha1": commit}:
                    raise ValueError
        builder = run["builder"]
        if set(builder) - {"id", "version", "builderDependencies"} or not isinstance(
            builder["id"], str
        ):
            raise ValueError
        # BuildKit 0.34 emits an empty id and may omit version entirely.
        if builder["id"] != "":
            raise ValueError
        if "version" in builder:
            if builder["version"] != {"buildkit": pins()["buildkit"]["version"]}:
                raise ValueError
        if "builderDependencies" in builder and not isinstance(
            builder["builderDependencies"], list
        ):
            raise ValueError
        if "byproducts" in run and not isinstance(run["byproducts"], list):
            raise ValueError
        for dependency in builder.get("builderDependencies", []):
            _resource(dependency)
        for byproduct in run.get("byproducts", []):
            _resource(byproduct)
        metadata = run["metadata"]
        _metadata(metadata)
        if metadata["invocationId"] != image["history"]["invocation_id"]:
            raise ValueError
        vcs = metadata.get("buildkit_metadata", {}).get("vcs", {})
        if vcs.get("revision", commit) != commit or vcs.get("source", SOURCE) != SOURCE:
            raise ValueError
        return document
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        raise ValueError("native provenance validation failed") from None


def build_record(*, image: dict, context: dict, files: dict) -> dict:
    """Build a supplement only after validating the raw native and SBOM files."""
    try:
        if set(files) != {"sbom", "provenance"}:
            raise ValueError
        documents = evidence._load_documents(
            [files["sbom"], files["provenance"]], kinds=["sbom", "provenance"]
        )
        native = evidence._parse(documents[1][0])
        validate_native(native, image=image, context=context)
        sbom_document = sbom.validate(
            evidence._parse(documents[0][0], limit=evidence.KIND_LIMITS["sbom"])
        )
        if sbom.image_identity(sbom_document) != image["image_id"]:
            raise ValueError("SBOM config identity mismatch")
        if (
            "sha256:" + documents[1][1]["sha256"]
            != image["history"]["predicate_digest"]
        ):
            raise ValueError
        descriptors = {
            kind: {"path": files[kind].name, "kind": kind, **documents[index][1]}
            for index, kind in enumerate(("sbom", "provenance"))
        }
        if any(
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", item["path"])
            for item in descriptors.values()
        ):
            raise ValueError
        return {
            "schema_version": 1,
            "service": image["service"],
            "reference": image["reference"],
            "manifest_digest": image["manifest_digest"],
            "platform": image["platform"],
            "context": copy.deepcopy(context),
            "build_invocation": {
                "build_ref": image["history"]["build_ref"],
                "invocation_id": image["history"]["invocation_id"],
            },
            "builder": copy.deepcopy(native["runDetails"]["builder"]),
            **descriptors,
        }
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        raise ValueError("build record validation failed") from None


def validate_record(document: dict, *, image: dict, context: dict, files: dict) -> dict:
    try:
        expected = build_record(image=image, context=context, files=files)
        if (
            not isinstance(document, dict)
            or set(document) != RECORD_FIELDS
            or json.dumps(document, sort_keys=True, allow_nan=False)
            != json.dumps(expected, sort_keys=True, allow_nan=False)
        ):
            raise ValueError
        return document
    except (ValueError, TypeError, RecursionError):
        raise ValueError("build record evidence mismatch") from None
