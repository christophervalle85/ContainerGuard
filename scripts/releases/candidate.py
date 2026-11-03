"""Build, gate, inspect and exercise exact images without registry writes."""

import json
import os
import subprocess
import sys
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path

from scripts import probe_release_supply_chain as probe
from scripts.releases.commands import command
from scripts.releases.disclosure import check_disclosure
from scripts.releases.identity import (
    SERVICES,
    SOURCE,
    release_image,
    validate_commit,
    validate_source,
    validate_version,
)
from scripts.releases.smoke import exercise_stack
from scripts.releases.supply_chain import (
    evidence,
    manifest,
    oci,
    provenance,
    sbom,
    tools,
)

ROOT = Path(__file__).resolve().parents[2]


class CandidateBlocked(ValueError):
    """A completed vulnerability gate blocked this candidate."""


def verify_candidate_source(version, commit):
    validate_version(version)
    validate_commit(commit)
    if command(["git", "rev-parse", "HEAD"], capture=True).strip() != commit:
        raise ValueError("Candidate checkout source mismatch")
    # Publication candidates must originate in the same-repository tag workflow.
    if os.environ.get("GITHUB_ACTIONS") == "true":
        if (
            os.environ.get("GITHUB_REPOSITORY") != "christophervalle85/ContainerGuard"
            or os.environ.get("GITHUB_EVENT_NAME") != "push"
            or os.environ.get("GITHUB_REF") != "refs/tags/" + version
            or os.environ.get("GITHUB_SHA") != commit
        ):
            raise ValueError("Untrusted candidate event")
        validate_source(version, commit, repository=ROOT)
        if command(
            ["git", "status", "--porcelain", "--untracked-files=normal"], capture=True
        ).strip():
            raise ValueError("Release checkout is not clean")


def release_context(version, commit, context=None):
    """Local explicit inputs are qualification context, never hosted-run proof."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        # verify_candidate_source also enforces event, repository, ref and SHA.
        guarded = {
            "version": version,
            "commit": commit,
            "repository": os.environ.get("GITHUB_REPOSITORY"),
            "workflow": ".github/workflows/release.yml",
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        }
        if context is not None and context != guarded:
            raise ValueError("Candidate context differs from guarded run")
        context = guarded
        if (
            os.environ.get("GITHUB_WORKFLOW_REF")
            != SOURCE.removeprefix("https://github.com/")
            + "/.github/workflows/release.yml@refs/tags/"
            + version
        ):
            raise ValueError("Untrusted candidate workflow")
    elif context is None:
        raise ValueError("Local candidate requires explicit release context")
    if (
        not isinstance(context, dict)
        or set(context) != provenance.CONTEXT_FIELDS
        or context.get("version") != version
        or context.get("commit") != commit
    ):
        raise ValueError("Candidate context mismatch")
    # Use the same field constraints before allocating resources or building.
    import re

    validate_version(version)
    validate_commit(commit)
    if (
        context["repository"] != "christophervalle85/ContainerGuard"
        or context["workflow"] != ".github/workflows/release.yml"
        or any(
            not isinstance(context[k], str)
            or not re.fullmatch(r"[1-9][0-9]*", context[k])
            for k in ("run_id", "run_attempt")
        )
    ):
        raise ValueError("Invalid candidate context")
    return dict(context)


@contextmanager
def owned_builder():
    """Use the qualified producer pins and event-injection refusal from the probe."""
    tools.verify_tools()
    pins = tools.pins()
    buildx = str(
        Path(os.environ.get("CG_RELEASE_TOOLS", tools.ROOT / ".release-tools"))
        / "buildx"
    )
    builder = "cg-candidate-" + uuid.uuid4().hex[:16]
    created = False
    try:
        command(
            [
                buildx,
                "create",
                "--name",
                builder,
                "--driver",
                "docker-container",
                "--driver-opt",
                "network=host",
                "--driver-opt",
                "provenance-add-gha=false",
                "--driver-opt",
                "image=" + pins["buildkit"]["image"],
            ]
        )
        created = True
        command([buildx, "inspect", "--builder", builder, "--bootstrap"])
        version = command(
            [
                "docker",
                "exec",
                "buildx_buildkit_" + builder + "0",
                "buildkitd",
                "--version",
            ],
            capture=True,
        )
        if not tools.version_matches(version, pins["buildkit"]["version"]):
            raise ValueError("BuildKit version mismatch")
        yield buildx, builder
    finally:
        if created:
            command([buildx, "rm", builder])


def build_candidate(version: str, commit: str, output: Path, *, context=None) -> Path:
    context = release_context(version, commit, context)
    verify_candidate_source(version, commit)
    if output.is_symlink() or (output.exists() and any(output.iterdir())):
        raise ValueError("Candidate output must be empty")
    output.mkdir(parents=True, exist_ok=True)
    try:
        # Runtime passwords, raw reports, metadata and logs have a separate lifetime
        # from the small, explicitly enumerated transfer. Each invocation is fresh.
        with tempfile.TemporaryDirectory(prefix="cg-candidate-") as temporary:
            scratch = Path(temporary)
            images, identities, sealed = {}, {}, {}
            with owned_builder() as (buildx, builder):
                for service in SERVICES:
                    reference = release_image(service) + ":" + version
                    archive = scratch / (service + ".oci.tar")
                    metadata_path = scratch / (service + ".metadata.json")
                    args = [
                        buildx,
                        "build",
                        "--builder",
                        builder,
                        "--platform=linux/amd64",
                        "--provenance=false",
                        "--metadata-file",
                        str(metadata_path),
                        "--output",
                        "type=oci,dest=" + str(archive),
                        "-f",
                        "Dockerfile." + service,
                    ]
                    for name, value in {
                        "source": SOURCE,
                        "revision": commit,
                        "version": version,
                        "description": "ContainerGuard " + service,
                    }.items():
                        args += [
                            "--label",
                            "org.opencontainers.image." + name + "=" + value,
                        ]
                    command(
                        args + [SOURCE + "#" + commit],
                        timeout=1200,
                        env=dict(os.environ, BUILDX_METADATA_PROVENANCE="disabled"),
                    )
                    info = oci.inspect_canonical(archive)
                    metadata = evidence.read_document(metadata_path, kind="provenance")
                    if (
                        metadata.get("containerimage.digest") != info["manifest_digest"]
                        or metadata.get("containerimage.config.digest")
                        != info["image_id"]
                    ):
                        raise ValueError("Build metadata identity mismatch")
                    raw, receipt = probe.capture_history(
                        buildx,
                        builder,
                        metadata,
                        {
                            "manifest": info["manifest_digest"],
                            "config": info["image_id"],
                        },
                    )
                    native_path = scratch / (service + ".provenance.json")
                    if len(raw) > evidence.KIND_LIMITS["provenance"]:
                        raise ValueError("Native provenance size limit")
                    native_path.write_bytes(raw)
                    image = {
                        **info,
                        "service": service,
                        "reference": release_image(service)
                        + "@"
                        + info["manifest_digest"],
                        "history": receipt,
                    }
                    provenance.validate_native(
                        evidence.read_document(native_path, kind="provenance"),
                        image=image,
                        context=context,
                    )
                    imported = oci.import_for_checks(archive, reference)
                    if any(
                        imported[key] != info[key]
                        for key in (
                            "image_id",
                            "diff_ids",
                            "platform",
                            "manifest_digest",
                        )
                    ):
                        raise ValueError("Checked image differs from canonical image")
                    identities[service] = info["image_id"]
                    try:
                        command(
                            [
                                sys.executable,
                                "-m",
                                "scripts.scan_security",
                                "--kind",
                                "image",
                                "--input",
                                info["image_id"],
                                "--target",
                                info["image_id"],
                                "--output-dir",
                                str(scratch / (service + "-security")),
                            ],
                            timeout=650,
                        )
                    except subprocess.CalledProcessError as error:
                        if error.returncode == 1:
                            raise CandidateBlocked(
                                "Image vulnerability gate blocked publication"
                            ) from None
                        raise
                    sbom_path = scratch / (service + ".sbom.json")
                    # A thrown generation error always aborts. No preexisting path
                    # can stand in for this invocation's successful scan.
                    sbom.generate(info["image_id"], sbom_path)
                    files = {"sbom": sbom_path, "provenance": native_path}
                    record = provenance.build_record(
                        image=image, context=context, files=files
                    )
                    record_path = scratch / (service + ".build-record.json")
                    record_path.write_text(json.dumps(record, indent=2) + "\n")
                    check_disclosure(archive, scratch / (service + "-disclosure.json"))
                    images[service] = image
                    sealed[service] = {
                        kind: evidence.describe_file(
                            scratch / f"{service}.{kind}.json", kind=kind
                        )
                        for kind in manifest.KINDS
                    }
                smoke = exercise_stack(identities, workspace=scratch / "verification")
                (scratch / "smoke.json").write_text(json.dumps(smoke, indent=2) + "\n")
                # Full raw-byte revalidation follows smoke; neither evidence nor
                # canonical image bytes may change between checking and transfer.
                for service in SERVICES:
                    actual = oci.inspect_canonical(scratch / (service + ".oci.tar"))
                    if any(
                        actual[k] != images[service][k]
                        for k in (
                            "sha256",
                            "size_bytes",
                            "manifest_digest",
                            "image_id",
                            "diff_ids",
                            "platform",
                        )
                    ):
                        raise ValueError("Canonical archive changed after smoke")
                    for kind in manifest.KINDS:
                        if (
                            evidence.describe_file(
                                scratch / f"{service}.{kind}.json", kind=kind
                            )
                            != sealed[service][kind]
                        ):
                            raise ValueError("Evidence changed after smoke")
                handoff = manifest.write_handoff(images, scratch, context=context)
                document = evidence.read_document(handoff, kind="build-record")
                manifest.stage_transfer(document, scratch, output)
        return output / "handoff.json"
    except BaseException:
        # Only this owned output is touched. Development images/volumes/stacks
        # are never a cleanup target.
        for path in output.iterdir():
            if path.is_file() or path.is_symlink():
                path.unlink()
        raise
