#!/usr/bin/env python3
"""Qualify one native Git build and unchanged OCI transport on Linux/amd64."""

import argparse
import contextlib
import hashlib
import json
import os
import re
import selectors
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.releases.supply_chain import tools

SOURCE = "https://github.com/containerguard-probe/fixture"
LIMIT = 4 * 1024 * 1024
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"
BUILD_TYPE = (
    "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md"
)
# Select only record identity/attachment descriptors, never history logs/config.
HISTORY_FORMAT = (
    '{"Ref":"{{.Ref}}","Status":"{{.Status}}","Attachments":['
    "{{range $i,$a := .Attachments}}{{if $i}},{{end}}"
    '{"Digest":"{{$a.Digest}}","Platform":"{{$a.Platform}}",'
    '"Type":"{{$a.Type}}"}{{end}}]}'
)
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")


def command(args: list[str], **kwargs) -> str:
    return subprocess.run(
        args, check=True, capture_output=True, text=True, timeout=900, **kwargs
    ).stdout.strip()


def host_check() -> None:
    tools.host_check()
    if command(
        ["docker", "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"]
    ) not in {"linux/amd64", "linux/x86_64"}:
        raise RuntimeError("probe requires a Linux/amd64 Docker host")


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def decode(data: bytes) -> dict:
    if len(data) > LIMIT:
        raise ValueError("JSON limit exceeded")
    return json.loads(data, object_pairs_hook=pairs)


def read(path: Path) -> bytes:
    if path.is_symlink():
        raise ValueError("symlink evidence")
    with path.open("rb") as source:
        data = source.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("evidence limit exceeded")
    return data


def assessment_failures(
    native: dict,
    commit: str,
    manifest: str,
    copied: str,
    source: str = SOURCE,
    *,
    expected_invocation: str,
) -> list[str]:
    """Return fixed, bounded check codes only; never predicate values or errors."""

    def at(*keys):
        value = native
        for key in keys:
            value = value[key]
        return value

    def vcs():
        return at("runDetails", "metadata").get("buildkit_metadata", {}).get("vcs", {})

    def materials():
        return at("buildDefinition", "resolvedDependencies")

    checks = (
        ("manifest-format", lambda: DIGEST.fullmatch(manifest)),
        ("manifest-copy-digest", lambda: manifest == copied),
        ("native-build-type", lambda: at("buildDefinition", "buildType") == BUILD_TYPE),
        (
            "config-source-uri",
            lambda: (
                at("buildDefinition", "externalParameters", "configSource", "uri")
                == source + "#" + commit
            ),
        ),
        (
            "config-source-revision",
            lambda: (
                at("buildDefinition", "externalParameters", "configSource", "digest")
                == {"sha1": commit}
            ),
        ),
        (
            "dockerfile-entrypoint",
            lambda: (
                at("buildDefinition", "externalParameters", "configSource", "path")
                == "Dockerfile"
            ),
        ),
        (
            "frontend",
            lambda: (
                at("buildDefinition", "externalParameters", "request", "frontend")
                == "dockerfile.v0"
            ),
        ),
        (
            "native-target-platform",
            lambda: (
                at("buildDefinition", "internalParameters", "targetPlatform")
                == "linux/amd64"
            ),
        ),
        (
            "source-material-missing",
            lambda: (
                {"uri": source + "#" + commit, "digest": {"sha1": commit}}
                in materials()
            ),
        ),
        (
            "conflicting-source-material",
            lambda: all(
                item["uri"] == source + "#" + commit
                and item["digest"] == {"sha1": commit}
                for item in materials()
                if item.get("uri") == source
                or item.get("uri", "").startswith(source + "#")
            ),
        ),
        (
            "material-digests-missing",
            lambda: all(item.get("digest") for item in materials()),
        ),
        (
            "invocation-id",
            lambda: at("runDetails", "metadata", "invocationId") == expected_invocation,
        ),
        ("expected-invocation-empty", lambda: bool(expected_invocation)),
        ("vcs-revision", lambda: vcs().get("revision", commit) == commit),
        ("vcs-source", lambda: vcs().get("source", source) == source),
    )
    failures = []
    for code, check in checks:
        try:
            passed = bool(check())
        except (KeyError, TypeError, AttributeError):
            passed = False
        if not passed:
            failures.append(code)
    return failures


def assess(
    native: dict,
    commit: str,
    manifest: str,
    copied: str,
    source: str = SOURCE,
    *,
    expected_invocation: str,
) -> bool:
    """Require native SLSA1 source, actual target, exact invocation and output."""
    return not assessment_failures(
        native,
        commit,
        manifest,
        copied,
        source,
        expected_invocation=expected_invocation,
    )


def bounded_command(args: list[str]) -> bytes:
    """Read raw content through a bounded pipe; discard subprocess diagnostics."""
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 900
    result = bytearray()
    try:
        with process.stdout, selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise subprocess.TimeoutExpired(args, 900)
                chunk = os.read(
                    process.stdout.fileno(), min(65536, LIMIT + 1 - len(result))
                )
                if not chunk:
                    break
                result.extend(chunk)
                if len(result) > LIMIT:
                    raise ValueError("history response limit exceeded")
        code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
        if code:
            raise subprocess.CalledProcessError(code, args)
        return bytes(result)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)


def history_blob(buildx: str, builder: str, ref: str, digest: str) -> bytes:
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise ValueError("invalid history content digest")
    raw = bounded_command(
        [buildx, "history", "inspect", "attachment", "--builder", builder, ref, digest]
    )
    if len(raw) > LIMIT:
        raise ValueError("history response limit exceeded")
    if "sha256:" + hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("history content digest mismatch")
    return raw


def capture_history(
    buildx: str, builder: str, metadata: dict, identity: dict
) -> tuple[bytes, dict]:
    """Bind unchanged native bytes and output content to this owned build only."""
    build_ref = metadata["buildx.build.ref"]
    parts = build_ref.split("/")
    if (
        len(parts) != 3
        or parts[:2] != [builder, builder + "0"]
        or not re.fullmatch(r"[a-z0-9]{16,64}", parts[2])
    ):
        raise ValueError("unexpected build reference")
    ref = parts[2]
    history = decode(
        bounded_command(
            [
                buildx,
                "history",
                "inspect",
                "--builder",
                builder,
                "--format",
                HISTORY_FORMAT,
                ref,
            ]
        )
    )
    if (
        set(history) != {"Ref", "Status", "Attachments"}
        or history["Ref"] != ref
        or history["Status"] != "completed"
    ):
        raise ValueError("wrong or incomplete history record")
    attachments = history["Attachments"]
    if not isinstance(attachments, list) or any(
        not isinstance(item, dict) or set(item) != {"Digest", "Platform", "Type"}
        for item in attachments
    ):
        raise ValueError("malformed history attachments")
    predicates = [
        item
        for item in attachments
        if item["Type"].startswith("https://slsa.dev/provenance/")
    ]
    manifests = [item for item in attachments if item["Type"] == MANIFEST_TYPE]
    if (
        len(predicates) != 1
        or predicates[0]["Type"] != PREDICATE_TYPE
        or len(manifests) != 1
        or manifests[0]["Digest"] != identity["manifest"]
        or any(
            item["Platform"] not in {"", "linux/amd64"}
            for item in [predicates[0], manifests[0]]
        )
    ):
        raise ValueError("missing or ambiguous history attachments")
    digest = predicates[0]["Digest"]
    raw = history_blob(buildx, builder, ref, digest)
    native = decode(raw)
    invocation_id = native["runDetails"]["metadata"]["invocationId"]
    # BuildKit's provenance uniqueID is deliberately distinct from solve/history Ref.
    # The exact record's attachment digest binds this native identifier to its output.
    if not isinstance(invocation_id, str) or not re.fullmatch(
        r"[a-z0-9]{16,64}", invocation_id
    ):
        raise ValueError("invalid native invocation")
    output = decode(history_blob(buildx, builder, ref, manifests[0]["Digest"]))
    if (
        output["schemaVersion"] != 2
        or output["mediaType"] != MANIFEST_TYPE
        or output["config"]["digest"] != identity["config"]
    ):
        raise ValueError("history output identity mismatch")
    return raw, {
        "build_ref": build_ref,
        "invocation_id": invocation_id,
        "predicate_type": PREDICATE_TYPE,
        "predicate_digest": digest,
        "output_manifest": manifests[0]["Digest"],
        "output_config": output["config"]["digest"],
    }


def canonical(archive: Path) -> dict:
    """Inspect a tiny fixture archive without extraction or accepting attestations."""
    if archive.stat().st_size > 2 * 1024**3:
        raise ValueError("archive limit exceeded")
    with tarfile.open(archive) as bundle:
        members = {}
        total = 0
        for member in bundle:
            path = Path(member.name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or member.issym()
                or member.islnk()
                or member.name in members
            ):
                raise ValueError("unsafe archive member")
            if not (member.isfile() or member.isdir()):
                raise ValueError("unsupported archive member")
            total += member.size
            if member.size > 1024**3 or total > 8 * 1024**3 or len(members) >= 200_000:
                raise ValueError("archive member limit exceeded")
            members[member.name] = member

        def blob(name):
            member = members[name]
            if not member.isfile() or member.size > LIMIT:
                raise ValueError("fixture blob limit exceeded")
            with bundle.extractfile(member) as source:
                data = source.read(LIMIT + 1)
            if len(data) != member.size:
                raise ValueError("truncated blob")
            return data

        def descriptor(item):
            digest = item["digest"]
            if not DIGEST.fullmatch(digest):
                raise ValueError("invalid blob digest")
            data = blob("blobs/sha256/" + digest.removeprefix("sha256:"))
            if (
                len(data) != item["size"]
                or "sha256:" + hashlib.sha256(data).hexdigest() != digest
            ):
                raise ValueError("blob identity mismatch")
            return decode(data)

        if decode(blob("oci-layout")) != {"imageLayoutVersion": "1.0.0"}:
            raise ValueError("invalid OCI layout")
        index = decode(blob("index.json"))
        for _ in range(4):
            if len(index["manifests"]) != 1:
                raise ValueError("ambiguous OCI index")
            selected = index["manifests"][0]
            document = descriptor(selected)
            if selected["mediaType"] == "application/vnd.oci.image.manifest.v1+json":
                break
            if selected["mediaType"] != "application/vnd.oci.image.index.v1+json":
                raise ValueError("unexpected OCI descriptor")
            index = document
        else:
            raise ValueError("deep OCI index")
        config = descriptor(document["config"])
        if config["os"] != "linux" or config["architecture"] != "amd64":
            raise ValueError("wrong platform")
        if len(document["layers"]) != len(config["rootfs"]["diff_ids"]):
            raise ValueError("layer identity count mismatch")
        for layer in document["layers"]:
            digest = layer["digest"]
            if not DIGEST.fullmatch(digest):
                raise ValueError("invalid layer digest")
            member = members["blobs/sha256/" + digest[7:]]
            if not member.isfile() or member.size != layer["size"]:
                raise ValueError("invalid layer size")
            hasher = hashlib.sha256()
            with bundle.extractfile(member) as source:
                while chunk := source.read(1024 * 1024):
                    hasher.update(chunk)
            if "sha256:" + hasher.hexdigest() != digest:
                raise ValueError("layer digest mismatch")
        return {
            "manifest": selected["digest"],
            "config": document["config"]["digest"],
            "diff_ids": config["rootfs"]["diff_ids"],
        }


@contextlib.contextmanager
def serve_git(root: Path):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    process = subprocess.Popen(
        [
            "git",
            "daemon",
            "--reuseaddr",
            "--export-all",
            "--listen=127.0.0.1",
            f"--port={port}",
            f"--base-path={root}",
            str(root),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("fixture Git daemon failed")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("fixture Git daemon unavailable")
        yield f"git://127.0.0.1:{port}/fixture"
    finally:
        process.terminate()
        process.wait(timeout=10)


def run_probe(workspace: Path) -> dict:
    workspace.mkdir(parents=True, exist_ok=False) if not workspace.exists() else None
    if any(workspace.iterdir()):
        raise ValueError("probe workspace must be empty")
    result = {"passed": False, "build_invocations": 0}
    name = "cg-probe-" + uuid.uuid4().hex
    builder = name + "-builder"
    local_tag = name + ":fixture"
    owned_builder = owned_registry = owned_image = False
    stage = "host"
    try:
        host_check()
        stage = "tools"
        result["tools"] = tools.verify_tools()
        manifest = tools.pins()
        directory = Path(
            os.environ.get("CG_RELEASE_TOOLS", tools.ROOT / ".release-tools")
        )
        buildx = str(directory / "buildx")
        skopeo = str(directory / "skopeo")
        with tempfile.TemporaryDirectory(prefix="cg-probe-") as temporary:
            root = Path(temporary)
            stage = "fixture"
            fixture = root / "fixture"
            fixture.mkdir()
            (fixture / "Dockerfile").write_text("FROM scratch\nCOPY payload /payload\n")
            (fixture / "payload").write_text("ContainerGuard OCI transport fixture\n")
            for args in (
                ["init", "-q"],
                ["add", "Dockerfile", "payload"],
                [
                    "-c",
                    "user.name=ContainerGuard probe",
                    "-c",
                    "user.email=probe@example.invalid",
                    "commit",
                    "-qm",
                    "fixture",
                ],
            ):
                command(["git", *args], cwd=fixture)
            commit = command(["git", "rev-parse", "HEAD"], cwd=fixture)
            result["source_commit"] = commit
            stage = "registry-certificate"
            certificates = root / "certs"
            certificates.mkdir()
            command(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=127.0.0.1",
                    "-addext",
                    "subjectAltName=IP:127.0.0.1",
                    "-keyout",
                    str(certificates / "key.pem"),
                    "-out",
                    str(certificates / "ca.crt"),
                ]
            )
            stage = "registry-start"
            command(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    name,
                    "--platform=linux/amd64",
                    "-p",
                    "127.0.0.1::5000",
                    "-v",
                    f"{certificates}:/certs:ro",
                    "-e",
                    "REGISTRY_HTTP_TLS_CERTIFICATE=/certs/ca.crt",
                    "-e",
                    "REGISTRY_HTTP_TLS_KEY=/certs/key.pem",
                    manifest["registry"]["image"],
                ]
            )
            owned_registry = True
            stage = "registry-inspection"
            port = command(
                [
                    "docker",
                    "inspect",
                    "--format",
                    '{{(index (index .NetworkSettings.Ports "5000/tcp") 0).HostPort}}',
                    name,
                ]
            )
            registry = f"127.0.0.1:{port}/fixture:probe"
            version = command(["docker", "exec", name, "registry", "--version"])
            if not tools.version_matches(version, manifest["registry"]["version"]):
                raise ValueError("registry version mismatch")
            stage = "builder-start"
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
                    "image=" + manifest["buildkit"]["image"],
                ]
            )
            owned_builder = True
            stage = "builder-inspection"
            command([buildx, "inspect", "--builder", builder, "--bootstrap"])
            version = command(
                [
                    "docker",
                    "exec",
                    "buildx_buildkit_" + builder + "0",
                    "buildkitd",
                    "--version",
                ]
            )
            if not tools.version_matches(version, manifest["buildkit"]["version"]):
                raise ValueError("BuildKit version mismatch")
            stage = "git-serving"
            with serve_git(root) as source:
                stage = "fixture-build"
                result["build_invocations"] += 1
                environment = dict(os.environ, BUILDX_METADATA_PROVENANCE="disabled")
                command(
                    [
                        buildx,
                        "build",
                        "--builder",
                        builder,
                        "--platform=linux/amd64",
                        "--provenance=false",
                        "--metadata-file",
                        str(workspace / "metadata.json"),
                        "--output",
                        f"type=oci,dest={workspace / 'fixture.oci.tar'}",
                        source + "#" + commit,
                    ],
                    env=environment,
                )
                stage = "archive-validation"
                identity = canonical(workspace / "fixture.oci.tar")
                result["canonical"] = identity
                stage = "native-metadata"
                metadata = decode(read(workspace / "metadata.json"))
                stage = "metadata-identity"
                if (
                    metadata["containerimage.config.digest"] != identity["config"]
                    or metadata["containerimage.digest"] != identity["manifest"]
                ):
                    raise ValueError("build metadata identity mismatch")
                stage = "native-history"
                raw, receipt = capture_history(buildx, builder, metadata, identity)
                (workspace / "native-provenance.json").write_bytes(raw)
                result["native_provenance_sha256"] = hashlib.sha256(raw).hexdigest()
                result["history"] = receipt
                archive = "oci-archive:" + str(workspace / "fixture.oci.tar")
                # Host import comes from the archive, never a second build.
                stage = "local-import"
                owned_image = True
                command([skopeo, "copy", archive, "docker-daemon:" + local_tag])
                imported = json.loads(
                    command(["docker", "image", "inspect", local_tag])
                )[0]
                if (
                    imported["Id"] != identity["config"]
                    or imported["RootFS"]["Layers"] != identity["diff_ids"]
                ):
                    raise ValueError("local import identity mismatch")
                stage = "registry-copy"
                command(
                    [
                        skopeo,
                        "copy",
                        "--preserve-digests",
                        "--dest-cert-dir",
                        str(certificates),
                        archive,
                        "docker://" + registry,
                    ]
                )
                stage = "registry-digest"
                copied = command(
                    [
                        skopeo,
                        "inspect",
                        "--cert-dir",
                        str(certificates),
                        "--format",
                        "{{.Digest}}",
                        "docker://" + registry,
                    ]
                )
                result["copied_digest"] = copied
                stage = "native-validation"
                result["validation_failures"] = assessment_failures(
                    decode(raw),
                    commit,
                    identity["manifest"],
                    copied,
                    source,
                    expected_invocation=receipt["invocation_id"],
                )
                result["passed"] = not result["validation_failures"]
                if not result["passed"]:
                    result["failure"] = "native-source-or-manifest-check"
                    result["failure_stage"] = stage
    except (
        OSError,
        ValueError,
        RuntimeError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
        tarfile.TarError,
    ) as error:
        result["passed"] = False
        result["failure_stage"] = stage
        # Classify known failures without serializing exception text or commands.
        if isinstance(error, subprocess.TimeoutExpired):
            result["failure"] = "process-timeout"
        elif isinstance(error, subprocess.SubprocessError):
            result["failure"] = "process-failed"
        elif isinstance(error, OSError):
            result["failure"] = "io-failed"
        elif isinstance(error, (KeyError, TypeError)):
            result["failure"] = "malformed-evidence"
        elif isinstance(error, tarfile.TarError):
            result["failure"] = "invalid-archive"
        elif isinstance(error, ValueError):
            result["failure"] = "invalid-evidence"
        else:
            result["failure"] = "requirement-failed"
    finally:
        cleanup = []
        if owned_image:
            cleanup.append(["docker", "image", "rm", local_tag])
        if owned_builder:
            cleanup.append([buildx, "rm", builder])
        if owned_registry:
            cleanup.append(["docker", "rm", "-f", "-v", name])
        for args in cleanup:
            try:
                command(args)
            except (OSError, subprocess.SubprocessError):
                result["passed"] = False
                result["failure"] = "owned-resource-cleanup-failed"
                result["failure_stage"] = "cleanup"
    (workspace / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = run_probe(args.output_dir.resolve())
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
