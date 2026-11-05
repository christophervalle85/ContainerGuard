import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def workflow(name):
    # BaseLoader preserves the Actions `on` key and expression strings.
    return yaml.load(
        (ROOT / ".github/workflows" / name).read_text(), Loader=yaml.BaseLoader
    )


def test_quality_remains_readonly_and_candidate_waits_for_all_checks():
    ci = workflow("ci.yml")
    assert ci["permissions"] == {"contents": "read"}
    assert set(ci["on"]) == {"push", "pull_request", "workflow_call"}
    assert (
        ci["on"]["workflow_call"]["inputs"]["release_candidate"]["default"] == "false"
    )
    assert set(ci["jobs"]["candidate"]["needs"]) == {
        "checks",
        "frontend",
        "dependencies",
    }
    assert "release_candidate" in ci["jobs"]["containers"]["if"]
    steps = ci["jobs"]["candidate"]["steps"]
    upload = next(step for step in steps if step.get("id") == "candidate_upload")
    assert upload["with"]["retention-days"] == "1"
    assert upload["with"]["if-no-files-found"] == "error"
    assert "if" not in upload
    assert steps.index(upload) > next(
        i
        for i, step in enumerate(steps)
        if "scripts.releases candidate" in step.get("run", "")
    )


def test_release_guard_precedes_local_reusable_ci():
    release = workflow("release.yml")
    assert release["on"] == {"push": {"tags": ["v*"]}}
    assert release["permissions"] == {"contents": "read"}
    assert release["concurrency"]["cancel-in-progress"] == "false"
    quality = release["jobs"]["quality"]
    assert quality["needs"] == "guard"
    assert quality["uses"] == "./.github/workflows/ci.yml"
    assert "secrets" not in quality
    assert quality["with"]["release_candidate"] == "true"
    guard = release["jobs"]["guard"]
    assert any(
        "scripts.releases guard" in step.get("run", "") for step in guard["steps"]
    )
    assert all(
        "always()" not in str(job) and "continue-on-error" not in job
        for job in release["jobs"].values()
    )


def test_actions_are_pinned_and_checkout_credentials_not_retained():
    for name in ("ci.yml", "release.yml"):
        for job in workflow(name)["jobs"].values():
            for step in job.get("steps", []):
                if "uses" in step:
                    assert re.fullmatch(r"[\w/-]+@[0-9a-f]{40}", step["uses"])
                    if step["uses"].startswith("actions/checkout@"):
                        assert step["with"]["persist-credentials"] == "false"


def test_publisher_has_exact_run_artifact_and_scoped_package_write():
    release = workflow("release.yml")
    publisher = release["jobs"]["publish"]
    assert set(publisher["needs"]) == {"guard", "quality"}
    assert publisher["permissions"] == {
        "contents": "read",
        "actions": "read",
        "packages": "write",
    }
    steps = publisher["steps"]
    download = next(
        step
        for step in steps
        if step.get("uses", "").startswith("actions/download-artifact@")
    )
    assert (
        download["with"]["artifact-ids"]
        == "${{ needs.quality.outputs.candidate_artifact_id }}"
    )
    assert "run-id" not in download["with"] and "github-token" not in download["with"]
    assert not any(
        "build" in step.get("run", "") or "uv sync" in step.get("run", "")
        for step in steps
    )
    for name, job in release["jobs"].items():
        if name not in {"publish", "sign"}:
            assert job.get("permissions", {}).get("packages") != "write"


def test_notes_job_cannot_push_packages_or_execute_image_payloads():
    release = workflow("release.yml")
    draft = release["jobs"]["draft"]
    assert set(draft["needs"]) == {"guard", "verify"}
    assert draft["permissions"] == {"contents": "write", "actions": "read"}
    assert not any("docker " in step.get("run", "") for step in draft["steps"])
    assert any(
        "scripts.releases draft" in step.get("run", "") for step in draft["steps"]
    )


def test_only_signer_has_oidc_permission():
    release = workflow("release.yml")
    assert release["jobs"]["sign"]["permissions"] == {
        "contents": "read",
        "actions": "read",
        "packages": "write",
        "id-token": "write",
    }
    assert all(
        job.get("permissions", {}).get("id-token") != "write"
        for name, job in release["jobs"].items()
        if name != "sign"
    )


def test_draft_requires_successful_verification():
    jobs = workflow("release.yml")["jobs"]
    assert "sign" in jobs["verify"]["needs"]
    assert "verify" in jobs["draft"]["needs"]


def test_all_transfers_bind_current_run_and_attempt():
    jobs = workflow("release.yml")["jobs"]
    for name in ("publish", "sign", "verify", "draft"):
        steps = jobs[name]["steps"]
        for i, step in enumerate(steps):
            if step.get("uses", "").startswith("actions/download-artifact@"):
                prior = steps[i - 1]
                assert "validate-transfer" in prior.get("run", "")
                assert prior["env"]["ARTIFACT_ID"] == step["with"]["artifact-ids"]
                assert prior["env"]["VERSION"] == "${{ needs.guard.outputs.version }}"
                assert prior["env"]["COMMIT"] == "${{ needs.guard.outputs.commit }}"


def test_candidate_upload_uses_transfer_allowlist():
    steps = workflow("ci.yml")["jobs"]["candidate"]["steps"]
    upload = next(step for step in steps if step.get("id") == "candidate_upload")
    paths = upload["with"]["path"].splitlines()
    names = {path.rsplit("/", 1)[-1] for path in paths}
    assert names == {"handoff.json", "checks-summary.json"} | {
        f"{service}.{kind}"
        for service in ("api", "worker", "frontend")
        for kind in ("oci.tar", "sbom.json", "provenance.json", "build-record.json")
    }
    assert all("*" not in path for path in paths)


def test_transfer_rejects_previous_attempt_artifact(monkeypatch):
    import pytest

    from scripts.releases import transfer

    artifact = {
        "id": 7,
        "expired": False,
        "created_at": "2026-01-01T00:01:00Z",
        "workflow_run": {"id": 10, "head_sha": "a" * 40},
    }
    jobs = {
        "total_count": 1,
        "jobs": [
            {
                "name": "publish",
                "run_id": 10,
                "head_sha": "a" * 40,
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-01-01T01:00:00Z",
                "completed_at": "2026-01-01T01:05:00Z",
            }
        ],
    }
    monkeypatch.setattr(
        transfer, "_get", lambda url: artifact if "/artifacts/" in url else jobs
    )
    with pytest.raises(ValueError):
        transfer.validate_transfer(
            "7", producer="publish", commit="a" * 40, run_id="10", attempt="2"
        )


def test_transfer_accepts_exact_current_attempt_job(monkeypatch):
    from scripts.releases import transfer

    artifact = {
        "id": 7,
        "expired": False,
        "created_at": "2026-01-01T01:01:00Z",
        "workflow_run": {"id": 10, "head_sha": "a" * 40},
    }
    jobs = {
        "total_count": 1,
        "jobs": [
            {
                "name": "publish",
                "run_id": 10,
                "head_sha": "a" * 40,
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-01-01T01:00:00Z",
                "completed_at": "2026-01-01T01:05:00Z",
            }
        ],
    }
    monkeypatch.setattr(
        transfer, "_get", lambda url: artifact if "/artifacts/" in url else jobs
    )
    transfer.validate_transfer(
        "7", producer="publish", commit="a" * 40, run_id="10", attempt="2"
    )


def test_transfer_cli_rejects_untrusted_context_before_api(monkeypatch):
    import sys

    from scripts.releases import __main__, transfer

    called = []
    monkeypatch.setattr(
        transfer, "validate_transfer", lambda *args, **kwargs: called.append(True)
    )
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "releases",
            "validate-transfer",
            "--artifact-id",
            "7",
            "--producer",
            "publish",
            "--version",
            "v1.0.0",
            "--commit",
            "a" * 40,
        ],
    )
    assert __main__.main() != 0
    assert called == []


def test_repeated_attempts_do_not_collide_and_failure_records_are_scoped():
    ci = workflow("ci.yml")
    candidate = next(
        step
        for step in ci["jobs"]["candidate"]["steps"]
        if step.get("id") == "candidate_upload"
    )
    assert "github.run_attempt" in candidate["with"]["name"]
    jobs = workflow("release.yml")["jobs"]
    for job in ("publish", "sign"):
        records = [
            step for step in jobs[job]["steps"] if step.get("if") == "${{ failure() }}"
        ]
        assert len(records) == 1
        assert records[0]["with"]["if-no-files-found"] == "ignore"
        assert "github.run_attempt" in records[0]["with"]["name"]
        assert "*" not in records[0]["with"]["path"]
