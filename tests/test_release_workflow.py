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


def test_publisher_has_exact_run_artifact_and_exclusive_package_write():
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
        if name != "publish":
            assert job.get("permissions", {}).get("packages") != "write"


def test_notes_job_cannot_push_packages_or_execute_image_payloads():
    release = workflow("release.yml")
    draft = release["jobs"]["draft"]
    assert set(draft["needs"]) == {"guard", "publish"}
    assert draft["permissions"] == {"contents": "write", "actions": "read"}
    assert not any("docker " in step.get("run", "") for step in draft["steps"])
    assert any(
        "scripts.releases draft" in step.get("run", "") for step in draft["steps"]
    )
