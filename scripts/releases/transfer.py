"""Check trusted workflow output IDs against current-run GitHub metadata."""

import datetime
import json
import os
import re
import urllib.request

from scripts.releases.registry import NoRedirect

API = "https://api.github.com/repos/christophervalle85/ContainerGuard/actions"
JOBS = {
    "candidate": "quality / candidate",
    "publish": "publish",
    "sign": "sign",
    "verify": "verify",
}


def _get(url):
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("Artifact metadata credentials unavailable")
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(
            request, timeout=30
        ) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError("Artifact metadata exceeded bounds")
            return json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ValueError("Artifact metadata unavailable") from None


def _time(value):
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def validate_transfer(artifact_id, *, producer, commit, run_id, attempt):
    """Reject mismatched or earlier-attempt output; never resolve by name."""
    if (
        producer not in JOBS
        or not re.fullmatch(r"[0-9a-f]{40}", commit)
        or any(
            not isinstance(v, str) or not re.fullmatch(r"[1-9][0-9]*", v)
            for v in (artifact_id, run_id, attempt)
        )
    ):
        raise ValueError("Invalid artifact context")
    try:
        artifact = _get(f"{API}/artifacts/{artifact_id}")
        jobs = _get(f"{API}/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
        run = artifact["workflow_run"]
        if (
            artifact["id"] != int(artifact_id)
            or artifact["expired"] is not False
            or run["id"] != int(run_id)
            or run["head_sha"] != commit
            or jobs["total_count"] != len(jobs["jobs"])
            or len(jobs["jobs"]) > 100
        ):
            raise ValueError("Artifact run mismatch")
        matches = [job for job in jobs["jobs"] if job["name"] == JOBS[producer]]
        if len(matches) != 1:
            raise ValueError("Artifact producer missing or ambiguous")
        job = matches[0]
        if (
            job["run_id"] != int(run_id)
            or job["head_sha"] != commit
            or job["status"] != "completed"
            or job["conclusion"] != "success"
            or not _time(job["started_at"])
            <= _time(artifact["created_at"])
            <= _time(job["completed_at"])
        ):
            raise ValueError("Artifact producer mismatch")
    except (KeyError, TypeError, AttributeError, OverflowError):
        raise ValueError("Invalid artifact metadata") from None
