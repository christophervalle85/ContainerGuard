"""The signed consumer must never fall back to the unsigned release path."""

import json
import subprocess
import sys

import pytest

from scripts.releases.supply_chain import signing
from tests import test_supply_chain_signing as signing_fixtures
from tests.test_release_disclosure import scanner  # noqa: F401

candidate_dir = signing_fixtures.candidate_dir
publication = signing_fixtures.publication
signing_case = signing_fixtures.signing_case


def test_signed_command_rejects_schema_one(tmp_path):
    manifest = tmp_path / "release.json"
    manifest.write_text('{"schema_version": 1}')
    output = tmp_path / "output"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.releases",
            "verify-release",
            "--manifest",
            str(manifest),
            "--version",
            "v0.1.0",
            "--commit",
            "a" * 40,
            "--evidence-dir",
            str(tmp_path),
            "--output-dir",
            str(output),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "invalid choice" not in result.stderr
    assert not output.exists() or not list(output.iterdir())


def test_forged_verification_result_cannot_render_compose():
    import pytest

    from scripts.releases.compose import render_verified_compose

    with pytest.raises(ValueError):
        render_verified_compose({"schema_version": 2}, {"success": True})


@pytest.fixture
def verified_inputs(candidate_dir, signing_case, monkeypatch, tmp_path):
    from scripts.releases.supply_chain import verification

    document, context, _, _, _ = signing_case
    signing.sign_release(
        document, candidate_dir, context=context, output=tmp_path / "signed"
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(document, indent=2))
    monkeypatch.setattr(verification, "_cosign", lambda: "/qualified/cosign")

    class Registry:
        def __init__(self, *, anonymous):
            assert anonymous

        def manifest(self, service, digest):
            image = document["images"][service]
            return {
                key: image[key]
                for key in ("digest", "image_id", "diff_ids", "platform", "labels")
            }

    monkeypatch.setattr(verification, "Registry", Registry)
    bundles = {
        service: [
            (tmp_path / "signed" / f"{service}.{kind}.bundle.json").read_bytes()
            for kind in ("signature", "sbom", "provenance", "build-record")
        ]
        for service in ("api", "worker", "frontend")
    }

    def transport(args, output, **kwargs):
        if args[1:3] == ["download", "attestation"]:
            service = args[-1].split("containerguard-")[1].split("@")[0]
            output.write_bytes(b"\n".join(bundles[service]) + b"\n")
        else:
            assert args[1] == "verify-blob-attestation"
            assert args[args.index("--digestAlg") + 1] == "sha256"
            assert args[args.index("--digest") + 1] in {
                image["digest"].split(":")[1] for image in document["images"].values()
            }
            assert args[args.index("--type") + 1] in {
                "https://sigstore.dev/cosign/sign/v1",
                "https://cyclonedx.org/bom",
                "https://slsa.dev/provenance/v1",
                "https://github.com/christophervalle85/ContainerGuard/attestations/build-record/v1",
            }
            assert "--certificate-github-workflow-trigger=push" in args
            assert "--certificate-github-workflow-sha=" + context["commit"] in args
            assert (
                "--certificate-github-workflow-repository=christophervalle85/ContainerGuard"
                in args
            )
            assert "--certificate-github-workflow-ref=refs/tags/v1.0.0" in args
            assert (
                "--certificate-oidc-issuer=https://token.actions.githubusercontent.com"
                in args
            )
            assert (
                "--certificate-identity=https://github.com/christophervalle85/ContainerGuard/.github/workflows/release.yml@refs/tags/v1.0.0"
                in args
            )
            output.write_bytes(b"")
        return output

    monkeypatch.setattr(verification, "command_file", transport)
    return manifest, candidate_dir, context, bundles, document


def test_verified_result_binds_manifest_and_all_subjects(verified_inputs, tmp_path):
    import hashlib

    from scripts.releases.compose import render_verified_compose
    from scripts.releases.supply_chain import verification

    path, directory, context, _, document = verified_inputs
    result = verification.verify_release(
        path,
        directory,
        version=context["version"],
        commit=context["commit"],
        output=tmp_path / "result",
    )
    assert result["manifest_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    rendered = render_verified_compose(document, result)
    for image in document["images"].values():
        assert image["reference"] in rendered
    document["images"]["api"]["reference"] = "attacker/image:latest"
    with pytest.raises(ValueError):
        render_verified_compose(document, result)


def test_one_unsigned_service_prevents_all_container_starts(verified_inputs, tmp_path):
    from scripts.releases.supply_chain import verification

    path, directory, context, bundles, _ = verified_inputs
    bundles["worker"] = bundles["worker"][1:]
    output = tmp_path / "result"
    with pytest.raises(ValueError):
        verification.verify_release(
            path,
            directory,
            version=context["version"],
            commit=context["commit"],
            output=output,
        )
    assert not output.exists() or not list(output.iterdir())


@pytest.mark.parametrize(
    "mutation",
    ["subject", "missing_log", "duplicate", "registry_unavailable", "verifier_failure"],
)
def test_rejected_evidence_produces_no_output(
    verified_inputs, tmp_path, monkeypatch, mutation
):
    import base64

    from scripts.releases.supply_chain import verification

    path, directory, context, bundles, _ = verified_inputs
    if mutation in {"subject", "missing_log"}:
        bundle = json.loads(bundles["worker"][0])
        if mutation == "missing_log":
            bundle["verificationMaterial"]["tlogEntries"] = []
        else:
            statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
            statement["subject"][0]["digest"]["sha256"] = "f" * 64
            bundle["dsseEnvelope"]["payload"] = base64.b64encode(
                json.dumps(statement).encode()
            ).decode()
        bundles["worker"][0] = json.dumps(bundle).encode()
    elif mutation == "duplicate":
        bundles["worker"].append(bundles["worker"][0])
    elif mutation == "registry_unavailable":

        class Unavailable:
            def __init__(self, *, anonymous):
                pass

            def manifest(self, *args):
                raise ValueError("unavailable")

        monkeypatch.setattr(verification, "Registry", Unavailable)
    else:
        original = verification.command_file

        def failed(args, output, **kwargs):
            if args[1] == "verify-blob-attestation":
                raise ValueError("verification failed")
            return original(args, output, **kwargs)

        monkeypatch.setattr(verification, "command_file", failed)
    output = tmp_path / "result"
    with pytest.raises(ValueError):
        verification.verify_release(
            path,
            directory,
            version=context["version"],
            commit=context["commit"],
            output=output,
        )
    assert not output.exists() or not list(output.iterdir())


def test_exercise_receives_anonymous_registry_environment(
    verified_inputs, tmp_path, monkeypatch
):
    from scripts.releases import __main__ as cli
    from scripts.releases import smoke
    from scripts.releases.supply_chain import verification

    path, directory, context, _, _ = verified_inputs
    output = tmp_path / "result"
    result = verification.verify_release(
        path,
        directory,
        version=context["version"],
        commit=context["commit"],
        output=output,
    )
    monkeypatch.setattr(verification, "verify_release", lambda *a, **k: result)
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    observed = {}

    def exercise(images, *, workspace, environment):
        observed.update(environment)
        assert json.loads(
            (
                __import__("pathlib").Path(environment["DOCKER_CONFIG"]) / "config.json"
            ).read_text()
        ) == {"auths": {}}

    monkeypatch.setattr(smoke, "exercise_stack", exercise)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "releases",
            "verify-release",
            "--manifest",
            str(path),
            "--version",
            context["version"],
            "--commit",
            context["commit"],
            "--evidence-dir",
            str(directory),
            "--output-dir",
            str(output),
            "--exercise",
        ],
    )
    assert cli.main() == 0
    assert "GITHUB_TOKEN" not in observed


def test_unsigned_cli_never_renders_or_exercises(
    verified_inputs, tmp_path, monkeypatch
):
    from scripts.releases import __main__ as cli
    from scripts.releases import smoke

    path, directory, context, bundles, _ = verified_inputs
    bundles["worker"] = bundles["worker"][1:]
    output = tmp_path / "result"
    started = []
    monkeypatch.setattr(smoke, "exercise_stack", lambda *a, **k: started.append(True))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "releases",
            "verify-release",
            "--manifest",
            str(path),
            "--version",
            context["version"],
            "--commit",
            context["commit"],
            "--evidence-dir",
            str(directory),
            "--output-dir",
            str(output),
            "--exercise",
        ],
    )
    assert cli.main() != 0
    assert not started
    assert not output.exists() or not list(output.iterdir())


def test_unavailable_registry_reports_infrastructure_failure(
    verified_inputs, tmp_path, monkeypatch, capsys
):
    from scripts.releases import __main__ as cli
    from scripts.releases.supply_chain import verification

    path, directory, context, _, _ = verified_inputs

    class Unavailable:
        def __init__(self, *, anonymous):
            pass

        def manifest(self, *args):
            raise ValueError("network unavailable")

    monkeypatch.setattr(verification, "Registry", Unavailable)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "releases",
            "verify-release",
            "--manifest",
            str(path),
            "--version",
            context["version"],
            "--commit",
            context["commit"],
            "--evidence-dir",
            str(directory),
            "--output-dir",
            str(tmp_path / "result"),
        ],
    )
    assert cli.main() != 0
    assert "unavailable" in capsys.readouterr().err.lower()


def test_manifest_via_symlinked_parent_is_rejected(verified_inputs, tmp_path):
    from scripts.releases.supply_chain import verification

    path, directory, context, _, _ = verified_inputs
    alias = tmp_path / "alias"
    alias.symlink_to(path.parent, target_is_directory=True)
    with pytest.raises(ValueError):
        verification.verify_release(
            alias / path.name,
            directory,
            version=context["version"],
            commit=context["commit"],
            output=tmp_path / "result",
        )


def test_cosign_failure_is_reported_indeterminate(
    verified_inputs, tmp_path, monkeypatch, capsys
):
    from scripts.releases import __main__ as cli
    from scripts.releases.supply_chain import verification

    path, directory, context, _, _ = verified_inputs
    original = verification.command_file

    def fail_verifier(args, output, **kwargs):
        if args[1] == "verify-blob-attestation":
            raise ValueError("raw sensitive diagnostic")
        return original(args, output, **kwargs)

    monkeypatch.setattr(verification, "command_file", fail_verifier)
    with pytest.raises(verification.VerificationIndeterminate):
        verification.verify_release(
            path,
            directory,
            version=context["version"],
            commit=context["commit"],
            output=tmp_path / "result",
        )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "releases",
            "verify-release",
            "--manifest",
            str(path),
            "--version",
            context["version"],
            "--commit",
            context["commit"],
            "--evidence-dir",
            str(directory),
            "--output-dir",
            str(tmp_path / "result"),
            "--exercise",
        ],
    )
    assert cli.main() == 3
    error = capsys.readouterr().err.lower()
    assert "indeterminate" in error
    assert "sensitive" not in error
    assert not (tmp_path / "result").exists()


def test_success_retains_exact_verified_evidence(verified_inputs, tmp_path):
    import hashlib

    from scripts.releases.supply_chain import verification

    path, directory, context, bundles, _ = verified_inputs
    output = tmp_path / "retained"
    result = verification.verify_release(
        path,
        directory,
        version=context["version"],
        commit=context["commit"],
        output=output,
    )
    assert (output / "release.json").read_bytes() == path.read_bytes()
    for service in ("api", "worker", "frontend"):
        for index, kind in enumerate(
            ("signature", "sbom", "provenance", "build-record")
        ):
            raw = (output / f"{service}.{kind}.bundle.json").read_bytes()
            assert raw == bundles[service][index]
            assert (
                hashlib.sha256(raw).hexdigest()
                == result["images"][service]["bundles"][kind]
            )
        for kind in ("sbom", "provenance", "build-record"):
            assert (output / f"{service}.{kind}.json").read_bytes() == (
                directory / f"{service}.{kind}.json"
            ).read_bytes()


def test_hosted_verification_rejects_prior_attempt_before_crypto(
    verified_inputs, tmp_path, monkeypatch
):
    from scripts.releases import __main__
    from scripts.releases.supply_chain import verification

    path, directory, context, _, _ = verified_inputs
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "999")
    called = []
    monkeypatch.setattr(
        verification, "verify_release", lambda *args, **kwargs: called.append(True)
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "releases",
            "verify-release",
            "--manifest",
            str(path),
            "--evidence-dir",
            str(directory),
            "--output-dir",
            str(tmp_path / "result"),
            "--version",
            context["version"],
            "--commit",
            context["commit"],
        ],
    )
    assert __main__.main() != 0
    assert not called
