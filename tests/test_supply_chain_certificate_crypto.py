"""Opt-in real Cosign certificate-policy checks; never production trust proof."""

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("CG_COSIGN_FIXTURE_BINARY"),
    reason="controlled Cosign fixture is opt-in",
)
IMAGE = (
    "golang:1.27.2-alpine@sha256:"
    "f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d"
)
SHA = "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"


@pytest.fixture(scope="module")
def fixture_dir(tmp_path_factory):
    directory = tmp_path_factory.mktemp("cert-policy")
    binary = Path(os.environ["CG_COSIGN_FIXTURE_BINARY"])
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == SHA
    shutil.copyfile(binary, directory / "cosign")
    (directory / "cosign").chmod(0o755)
    helper = Path(__file__).parent / "fixtures/releases/certificate_policy_fixture.py"
    subprocess.run(
        [os.environ.get("CG_CERT_PYTHON", "python3"), str(helper), str(directory)],
        check=True,
        timeout=30,
    )
    return directory


@pytest.mark.parametrize(
    "case",
    ["valid"]
    + [
        f"{prefix}-{field}"
        for field in ("workflow", "issuer", "sha", "repository", "event", "ref")
        for prefix in ("wrong", "missing")
    ],
)
def test_pinned_cosign_rejects_wrong_or_missing_signed_certificate_claims(
    fixture_dir, case
):
    from scripts.releases.supply_chain.verification import _cosign_args

    args = _cosign_args(
        "/fixture/cosign",
        Path("/fixture") / (case + ".json"),
        "sha256:" + "b" * 64,
        "v1.0.0",
        "a" * 40,
        "https://slsa.dev/provenance/v1",
    )
    args += [
        "--trusted-root",
        "/fixture/root.json",
        "--insecure-ignore-tlog",
        "--insecure-ignore-sct",
    ]
    container = [
        "docker",
        "run",
        "--rm",
        "--platform",
        "linux/amd64",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--mount",
        f"type=bind,src={fixture_dir},dst=/fixture,readonly",
        IMAGE,
    ]
    result = subprocess.run(container + args, capture_output=True, timeout=60)
    assert (result.returncode == 0) == (case == "valid"), result.stderr.decode(
        errors="replace"
    )

    # Positive controls establish that rejection was caused by the changed claim,
    # rather than a broken signature or unrelated fixture field.
    if case != "valid":
        variant, field = case.split("-", 1)
        options = {
            "workflow": "--certificate-identity=",
            "issuer": "--certificate-oidc-issuer=",
            "sha": "--certificate-github-workflow-sha=",
            "repository": "--certificate-github-workflow-repository=",
            "event": "--certificate-github-workflow-trigger=",
            "ref": "--certificate-github-workflow-ref=",
        }
        if variant == "wrong":
            relaxed = [
                arg + "-wrong" if arg.startswith(options[field]) else arg
                for arg in args
            ]
        elif field not in ("workflow", "issuer"):
            relaxed = [arg for arg in args if not arg.startswith(options[field])]
        else:
            # Identity and issuer are required CLI inputs; the fixture generator
            # independently verifies these signatures and CA chains.
            return
        control = subprocess.run(container + relaxed, capture_output=True, timeout=60)
        assert control.returncode == 0, control.stderr.decode(errors="replace")
