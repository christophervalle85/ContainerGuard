"""Strict schema-2 candidate seal and explicit transfer allowlist.

Legacy schema-1 readers remain in releases.artifacts. This seal is local evidence,
not a signature or proof that the supplied run context executed on GitHub.
"""

import copy
import json
import os
import re
from pathlib import Path

from scripts.releases import artifacts, checks
from scripts.releases.identity import SERVICES, SOURCE
from scripts.releases.supply_chain import evidence, oci, provenance

IDENTITY_FIELDS = {
    "service",
    "reference",
    "manifest_digest",
    "image_id",
    "platform",
    "history",
    "diff_ids",
}
KINDS = ("sbom", "provenance", "build-record")


def _descriptor(directory, descriptor, name, kind):
    if not isinstance(descriptor, dict) or set(descriptor) != {
        "path",
        "kind",
        "size_bytes",
        "sha256",
    }:
        raise ValueError("invalid file descriptor")
    if descriptor["path"] != name or descriptor["kind"] != kind:
        raise ValueError("invalid file association")
    if type(descriptor["size_bytes"]) is not int or descriptor["size_bytes"] < 0:
        raise ValueError("invalid file size")
    if descriptor != evidence.describe_file(directory / name, kind=kind):
        raise ValueError("altered candidate evidence")


def _summary(directory, images):
    # Original reports stay in scratch. Re-evaluate all original gates before
    # projecting only fixed safe fields and exact-byte summary hashes.
    checks.seal_evidence(directory, images)
    counts = checks.verify_evidence(directory, images)
    return {
        "schema_version": 1,
        "smoke": {
            "passed": True,
            "recreation_retained": True,
            "sha256": artifacts.sha256_file(directory / "smoke.json"),
        },
        "images": {
            service: {
                "image_id": images[service]["image_id"],
                "manifest_digest": images[service]["manifest_digest"],
                "vulnerability": {
                    "blocked": False,
                    "counts": counts[service],
                    "sha256": artifacts.sha256_file(
                        directory / f"{service}-security/summary.json"
                    ),
                },
                "disclosure": {
                    "blocked": False,
                    "sha256": artifacts.sha256_file(
                        directory / f"{service}-disclosure.json"
                    ),
                },
            }
            for service in SERVICES
        },
    }


def _validate_summary(value, images):
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "smoke", "images", "evidence_disclosure"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
    ):
        raise ValueError("invalid check summary")
    smoke = value["smoke"]
    if (
        set(smoke) != {"passed", "recreation_retained", "sha256"}
        or smoke["passed"] is not True
        or smoke["recreation_retained"] is not True
    ):
        raise ValueError("failed smoke summary")
    audit = value["evidence_disclosure"]
    if set(audit) != {"blocked", "sha256"} or audit["blocked"] is not False:
        raise ValueError("failed evidence disclosure")
    hashes = [smoke["sha256"], audit["sha256"]]
    if set(value["images"]) != set(SERVICES):
        raise ValueError("missing check summaries")
    for service in SERVICES:
        item = value["images"][service]
        identity = images[service]["identity"]
        if set(item) != {
            "image_id",
            "manifest_digest",
            "vulnerability",
            "disclosure",
        } or any(item[k] != identity[k] for k in ("image_id", "manifest_digest")):
            raise ValueError("check identity mismatch")
        for kind, fields in (
            ("vulnerability", {"blocked", "counts", "sha256"}),
            ("disclosure", {"blocked", "sha256"}),
        ):
            verdict = item[kind]
            if set(verdict) != fields or verdict["blocked"] is not False:
                raise ValueError("failed check summary")
            hashes.append(verdict["sha256"])
        counts = item["vulnerability"]["counts"]
        if (
            not isinstance(counts, dict)
            or set(counts) - {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
            or any(type(n) is not int or n < 0 for n in counts.values())
        ):
            raise ValueError("invalid vulnerability counts")
    if any(
        not isinstance(h, str) or not provenance.DIGEST.fullmatch("sha256:" + h)
        for h in hashes
    ):
        raise ValueError("invalid check hash")


def read_checked_findings(document: dict, directory: Path) -> dict:
    """Retain findings from the same bounded bytes checked against the seal."""
    try:
        raw, descriptor = evidence._load_documents(
            [directory / "checks-summary.json"], kinds=["checks"]
        )[0]
        if document["checks"] != {
            "path": "checks-summary.json",
            "kind": "checks",
            **descriptor,
        }:
            raise ValueError("altered candidate check summary")
        summary = evidence._parse(raw)
        _validate_summary(summary, document["images"])
        return {
            service: summary["images"][service]["vulnerability"]["counts"]
            for service in SERVICES
        }
    except (OSError, KeyError, TypeError, AttributeError, UnicodeError, RecursionError):
        raise ValueError("invalid candidate check summary") from None


def validate_handoff(document: dict, directory: Path, *, context: dict) -> dict:
    """Revalidate canonical archives, original evidence bytes and owned schemas."""
    try:
        if (
            directory.is_symlink()
            or not isinstance(document, dict)
            or set(document) != {"schema_version", "context", "images", "checks"}
        ):
            raise ValueError
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != 2
            or document["context"] != context
            or set(document["images"]) != set(SERVICES)
        ):
            raise ValueError
        archive_total = evidence_total = 0
        # Bound every descriptor/file before decoding any evidence JSON.
        for service in SERVICES:
            item = document["images"][service]
            if (
                set(item) != {"identity", "archive", *KINDS}
                or set(item["identity"]) != IDENTITY_FIELDS
            ):
                raise ValueError
            image = item["identity"]
            provenance._inputs(image, context)
            if image["service"] != service:
                raise ValueError
            archive = item["archive"]
            if type(archive.get("size_bytes")) is not int or archive["size_bytes"] < 0:
                raise ValueError("invalid archive size")
            if (
                set(archive) != {"path", "kind", "size_bytes", "sha256"}
                or archive["path"] != f"{service}.oci.tar"
                or archive["kind"] != "oci"
            ):
                raise ValueError
            path = directory / archive["path"]
            if (
                path.is_symlink()
                or not path.is_file()
                or path.stat().st_size > artifacts.MAX_ARCHIVE
            ):
                raise ValueError
            archive_total += path.stat().st_size
            for kind in KINDS:
                _descriptor(directory, item[kind], f"{service}.{kind}.json", kind)
                evidence_total += item[kind]["size_bytes"]
        _descriptor(directory, document["checks"], "checks-summary.json", "checks")
        evidence_total += document["checks"]["size_bytes"]
        if (
            archive_total > artifacts.MAX_TOTAL
            or evidence_total > evidence.COMBINED_LIMIT
        ):
            raise ValueError("candidate size limit")
        for service in SERVICES:
            item = document["images"][service]
            image = item["identity"]
            actual = oci.inspect_canonical(directory / item["archive"]["path"])
            if any(
                actual[k] != image[k]
                for k in ("image_id", "manifest_digest", "diff_ids", "platform")
            ) or any(actual[k] != item["archive"][k] for k in ("size_bytes", "sha256")):
                raise ValueError("canonical identity changed")
            labels = {
                "source": SOURCE,
                "revision": context["commit"],
                "version": context["version"],
                "description": "ContainerGuard " + service,
            }
            if any(
                actual["labels"].get("org.opencontainers.image." + k) != v
                for k, v in labels.items()
            ):
                raise ValueError("candidate source label mismatch")
            files = {
                kind: directory / item[kind]["path"] for kind in ("sbom", "provenance")
            }
            provenance.validate_record(
                evidence.read_document(
                    directory / item["build-record"]["path"], kind="build-record"
                ),
                image=image,
                context=context,
                files=files,
            )
        read_checked_findings(document, directory)
        return document
    except (OSError, KeyError, TypeError, AttributeError, RecursionError):
        raise ValueError("invalid schema-2 candidate handoff") from None


def write_handoff(images: dict, directory: Path, *, context: dict) -> Path:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("unsafe candidate directory")
    path = directory / "handoff.json"
    path.unlink(missing_ok=True)
    try:
        if set(images) != set(SERVICES):
            raise ValueError("missing candidate image")
        summary = _summary(directory, images)
        paths = [
            directory / f"{service}.{kind}.json"
            for service in SERVICES
            for kind in KINDS
        ]
        sealed = {
            (service, kind): evidence.describe_file(
                directory / f"{service}.{kind}.json", kind=kind
            )
            for service in SERVICES
            for kind in KINDS
        }
        audit_path = directory / "evidence-disclosure.json"
        audit = evidence.check_disclosure(
            paths,
            audit_path,
            kinds=list(KINDS) * len(SERVICES),
            contexts=[
                {"service": service, "commit": context["commit"]}
                for service in SERVICES
                for kind in KINDS
            ],
            allowed_source_urls=frozenset({SOURCE, SOURCE + "#" + context["commit"]}),
        )
        expected_audit = [
            {key: sealed[(service, kind)][key] for key in ("size_bytes", "sha256")}
            for service in SERVICES
            for kind in KINDS
        ]
        if (
            audit.get("blocked") is not False
            or audit.get("documents") != expected_audit
        ):
            raise ValueError("disclosure audit evidence mismatch")
        summary["evidence_disclosure"] = {
            "blocked": False,
            "sha256": artifacts.sha256_file(audit_path),
        }
        (directory / "checks-summary.json").write_text(
            json.dumps(summary, indent=2) + "\n"
        )
        document = {
            "schema_version": 2,
            "context": copy.deepcopy(context),
            "images": {},
            "checks": evidence.describe_file(
                directory / "checks-summary.json", kind="checks"
            ),
        }
        for service in SERVICES:
            info = images[service]
            document["images"][service] = {
                "identity": {key: copy.deepcopy(info[key]) for key in IDENTITY_FIELDS},
                "archive": {
                    "path": f"{service}.oci.tar",
                    "kind": "oci",
                    "size_bytes": info["size_bytes"],
                    "sha256": info["sha256"],
                },
                **{kind: sealed[(service, kind)] for kind in KINDS},
            }
        validate_handoff(document, directory, context=context)
        path.write_text(json.dumps(document, indent=2) + "\n")
        return path
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def stage_transfer(document: dict, directory: Path, output: Path) -> list[Path]:
    """Copy only sealed public files; validate private copy before eligibility."""
    validate_handoff(document, directory, context=document["context"])
    if (
        output.is_symlink()
        or output.resolve() == directory.resolve()
        or (output.exists() and any(output.iterdir()))
    ):
        raise ValueError("transfer output must be separate and empty")
    output.mkdir(parents=True, exist_ok=True)
    names = [document["checks"]["path"]] + [
        item[key]["path"]
        for item in document["images"].values()
        for key in ("archive", *KINDS)
    ]
    try:
        for name in names:
            # O_NOFOLLOW prevents a replaced symlink from entering the transfer.
            fd = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as source, (output / name).open("xb") as target:
                expected_size = next(
                    d["size_bytes"]
                    for d in [
                        document["checks"],
                        *[
                            item[k]
                            for item in document["images"].values()
                            for k in ("archive", *KINDS)
                        ],
                    ]
                    if d["path"] == name
                )
                remaining = expected_size
                while chunk := source.read(min(1024 * 1024, remaining + 1)):
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise ValueError("transfer size changed")
                    target.write(chunk)
                if remaining:
                    raise ValueError("transfer truncated")
        validate_handoff(document, output, context=document["context"])
        (output / "handoff.json").write_text(json.dumps(document, indent=2) + "\n")
        return [output / name for name in [*names, "handoff.json"]]
    except BaseException:
        for name in [*names, "handoff.json"]:
            (output / name).unlink(missing_ok=True)
        raise


PREDICATE_TYPES = {
    "sbom": "https://cyclonedx.org/bom",
    "provenance": "https://slsa.dev/provenance/v1",
    "build-record": "https://github.com/christophervalle85/ContainerGuard/attestations/build-record/v1",
}


def validate_release(document: dict, *, version: str, commit: str) -> dict:
    """Validate schema 2 structure/associations, never establish signature trust."""
    from scripts.releases.compose import validate_release as validate_legacy_fields
    from scripts.releases.identity import release_tags

    try:
        release_tags(version, commit)
        if (
            not isinstance(document, dict)
            or set(document)
            != {
                "schema_version",
                "version",
                "commit",
                "platform",
                "images",
                "remaining_findings",
                "checks_url",
                "build_context",
            }
            or type(document["schema_version"]) is not int
            or document["schema_version"] != 2
            or document["version"] != version
            or document["commit"] != commit
        ):
            raise ValueError("invalid schema-2 release")
        # Explicit common-field projection reuses legacy identity validation;
        # schema1 inputs never enter the signed schema2 interface.
        common = {
            k: copy.deepcopy(v) for k, v in document.items() if k != "build_context"
        }
        common["schema_version"] = 1
        total = 0
        for service in SERVICES:
            image = common["images"][service]
            descriptors = image.pop("evidence")
            if set(descriptors) != set(KINDS):
                raise ValueError("missing release evidence")
            for kind in KINDS:
                d = descriptors[kind]
                if (
                    set(d) != {"path", "kind", "size_bytes", "sha256", "predicate_type"}
                    or d["path"] != f"{service}.{kind}.json"
                    or d["kind"] != kind
                    or d["predicate_type"] != PREDICATE_TYPES[kind]
                    or type(d["size_bytes"]) is not int
                    or not 0 < d["size_bytes"] <= evidence.KIND_LIMITS[kind]
                    or not isinstance(d["sha256"], str)
                    or not provenance.DIGEST.fullmatch("sha256:" + d["sha256"])
                ):
                    raise ValueError("invalid release evidence descriptor")
                total += d["size_bytes"]
            # Reuse the strict context contract without inventing native history.
            context = document["build_context"]
            if (
                not isinstance(context, dict)
                or set(context) != provenance.CONTEXT_FIELDS
                or context["version"] != version
                or context["commit"] != commit
                or context["repository"] != "christophervalle85/ContainerGuard"
                or context["workflow"] != ".github/workflows/release.yml"
                or any(
                    not isinstance(context[k], str)
                    or not re.fullmatch(r"[1-9][0-9]*", context[k])
                    for k in ("run_id", "run_attempt")
                )
                or document["checks_url"]
                != SOURCE + "/actions/runs/" + context["run_id"]
            ):
                raise ValueError("release context mismatch")
        if total > evidence.COMBINED_LIMIT:
            raise ValueError("release evidence size limit")
        validate_legacy_fields(common)
        return document
    except (KeyError, TypeError, AttributeError, RecursionError):
        raise ValueError("invalid schema-2 release") from None
