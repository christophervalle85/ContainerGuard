import json
import subprocess
from contextlib import contextmanager
from pathlib import Path

import pytest

from scripts.releases import candidate
from scripts.releases.supply_chain import oci
from tests.test_release_artifacts import COMMIT, prepare_evidence
from tests.test_supply_chain_manifest import canonical_archive, native_files


@pytest.fixture(autouse=True)
def local_release_environment(monkeypatch):
    """Keep local fixtures independent of the surrounding GitHub Actions run."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)


def context():
    return {
        "version": "v1.0.0",
        "commit": COMMIT,
        "repository": "christophervalle85/ContainerGuard",
        "workflow": ".github/workflows/release.yml",
        "run_id": "123",
        "run_attempt": "1",
    }


@pytest.fixture
def commands(tmp_path, monkeypatch):
    calls, checked = [], {}

    @contextmanager
    def builder():
        yield "/pinned/buildx", "owned-builder"

    monkeypatch.setattr(candidate, "owned_builder", builder)
    monkeypatch.setattr(candidate, "verify_candidate_source", lambda *args: None)

    def command(args, **kwargs):
        calls.append(args)
        if "build" in args:
            service = args[args.index("-f") + 1].split(".")[-1]
            path = args[args.index("--output") + 1].split("dest=", 1)[1]
            info = canonical_archive(Path(path), service)
            Path(args[args.index("--metadata-file") + 1]).write_text(
                json.dumps(
                    {
                        "containerimage.digest": info["manifest_digest"],
                        "containerimage.config.digest": info["image_id"],
                        "service": service,
                    }
                )
            )
        return ""

    monkeypatch.setattr(candidate, "command", command)

    def capture(buildx, builder, metadata, identity):
        directory = tmp_path / "native"
        directory.mkdir(exist_ok=True)
        info = {"manifest_digest": identity["manifest"], "image_id": identity["config"]}
        _, image = native_files(directory, metadata["service"], info)
        return (
            directory / (metadata["service"] + ".provenance.json")
        ).read_bytes(), image["history"]

    monkeypatch.setattr(candidate.probe, "capture_history", capture)

    def imported(path, reference):
        info = oci.inspect_canonical(path)
        checked[reference] = (info["image_id"], info["diff_ids"])
        return info

    monkeypatch.setattr(candidate.oci, "import_for_checks", imported)

    def generate(reference, output):
        from tests.test_supply_chain_sbom import document

        value = document()
        value["metadata"]["component"]["properties"][0]["value"] = reference
        output.write_text(json.dumps(value))
        return output

    monkeypatch.setattr(candidate.sbom, "generate", generate)
    monkeypatch.setattr(candidate, "check_disclosure", lambda *args: None)

    def audit(paths, output, **kwargs):
        summary = {
            "blocked": False,
            "documents": [
                {
                    key: candidate.evidence.describe_file(path, kind=kind)[key]
                    for key in ("size_bytes", "sha256")
                }
                for path, kind in zip(paths, kwargs["kinds"], strict=True)
            ],
        }
        output.write_text(json.dumps(summary))
        return summary

    monkeypatch.setattr(candidate.evidence, "check_disclosure", audit)

    def smoke(images, *, workspace):
        directory = workspace.parent
        info = {
            s: oci.inspect_canonical(directory / (s + ".oci.tar"))
            for s in ("api", "worker", "frontend")
        }
        prepare_evidence(directory, info)
        workspace.mkdir()
        (workspace / "compose.yaml").write_text("password: candidate-runtime-sentinel")
        return {"passed": True, "recreation_retained": True}

    monkeypatch.setattr(candidate, "exercise_stack", smoke)
    return calls, checked


def test_candidate_builds_once_exports_native_evidence(tmp_path, commands):
    calls, checked = commands
    path = candidate.build_candidate(
        "v1.0.0", COMMIT, tmp_path / "candidate", context=context()
    )
    document = json.loads(path.read_text())
    assert document["schema_version"] == 2
    builds = [c for c in calls if "build" in c]
    assert len(builds) == 3
    assert all(
        "--provenance=false" in c and "--platform=linux/amd64" in c for c in builds
    )
    assert all(
        c[-1] == "https://github.com/christophervalle85/ContainerGuard#" + COMMIT
        for c in builds
    )
    assert not any(
        any(token in c for token in ("push", "login", "oidc")) for c in calls
    )
    for service, image in document["images"].items():
        assert checked[
            f"ghcr.io/christophervalle85/containerguard-{service}:v1.0.0"
        ] == (image["identity"]["image_id"], image["identity"]["diff_ids"])
    assert all(
        b"candidate-runtime-sentinel" not in p.read_bytes()
        for p in path.parent.iterdir()
    )


@pytest.mark.parametrize(
    "stage",
    ["build", "gate", "disclosure", "smoke", "sbom", "history", "identity", "mutation"],
)
def test_failed_check_produces_no_handoff(tmp_path, commands, monkeypatch, stage):
    original = candidate.command

    def fail_command(args, **kwargs):
        if (stage == "build" and "build" in args) or (
            stage == "gate" and "scripts.scan_security" in args
        ):
            raise subprocess.CalledProcessError(1, args)
        return original(args, **kwargs)

    monkeypatch.setattr(candidate, "command", fail_command)

    def fail(*args, **kwargs):
        raise ValueError("check failed")

    if stage in ("disclosure", "smoke"):
        monkeypatch.setattr(
            candidate,
            "check_disclosure" if stage == "disclosure" else "exercise_stack",
            fail,
        )
    if stage == "sbom":
        monkeypatch.setattr(candidate.sbom, "generate", fail)
    if stage == "history":
        monkeypatch.setattr(candidate.probe, "capture_history", fail)
    if stage == "identity":
        original_import = candidate.oci.import_for_checks

        def mismatch(*args):
            info = original_import(*args)
            return {**info, "image_id": "sha256:" + "f" * 64}

        monkeypatch.setattr(candidate.oci, "import_for_checks", mismatch)
    if stage == "mutation":
        original_smoke = candidate.exercise_stack

        def mutate(*args, **kwargs):
            result = original_smoke(*args, **kwargs)
            with (kwargs["workspace"].parent / "api.sbom.json").open("a") as stream:
                stream.write(" ")
            return result

        monkeypatch.setattr(candidate, "exercise_stack", mutate)
    with pytest.raises((ValueError, subprocess.SubprocessError)):
        candidate.build_candidate(
            "v1.0.0", COMMIT, tmp_path / "candidate", context=context()
        )
    assert not (tmp_path / "candidate/handoff.json").exists()
    assert not list((tmp_path / "candidate").glob("*.oci.tar"))


def test_local_candidate_requires_explicit_context(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    with pytest.raises(ValueError):
        candidate.build_candidate("v1.0.0", COMMIT, tmp_path / "candidate")


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", "v9.0.0"),
        ("commit", "f" * 40),
        ("run_id", True),
        ("run_attempt", "0"),
        ("repository", "other/repo"),
    ],
)
def test_explicit_context_rejects_conflicts_before_build(tmp_path, field, value):
    ctx = context()
    ctx[field] = value
    with pytest.raises(ValueError):
        candidate.build_candidate("v1.0.0", COMMIT, tmp_path / "candidate", context=ctx)
    assert not (tmp_path / "candidate").exists()


def test_generation_error_never_accepts_written_destination(
    tmp_path, commands, monkeypatch
):
    def stale(reference, output):
        output.write_text('{"older":"destination"}')
        raise ValueError("generation failed")

    monkeypatch.setattr(candidate.sbom, "generate", stale)
    with pytest.raises(ValueError, match="generation failed"):
        candidate.build_candidate(
            "v1.0.0", COMMIT, tmp_path / "candidate", context=context()
        )
    assert list((tmp_path / "candidate").iterdir()) == []


def test_builder_refuses_unsupported_option_without_fallback(monkeypatch):
    calls = []
    monkeypatch.setattr(candidate.tools, "verify_tools", lambda: {})

    def unsupported(args, **kwargs):
        calls.append(args)
        raise subprocess.CalledProcessError(1, args)

    monkeypatch.setattr(candidate, "command", unsupported)
    with pytest.raises(subprocess.CalledProcessError):
        with candidate.owned_builder():
            pytest.fail("unsupported producer must not build")
    assert len(calls) == 1
    assert "provenance-add-gha=false" in calls[0]


def test_hosted_context_cannot_override_guarded_run_identity(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "christophervalle85/ContainerGuard")
    monkeypatch.setenv("GITHUB_RUN_ID", "456")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv(
        "GITHUB_WORKFLOW_REF",
        "christophervalle85/ContainerGuard/.github/workflows/release.yml@refs/tags/v1.0.0",
    )
    with pytest.raises(ValueError):
        candidate.release_context("v1.0.0", COMMIT, context())
