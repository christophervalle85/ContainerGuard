import subprocess
from pathlib import Path

import pytest

from scripts.releases.identity import (
    release_image,
    release_tags,
    validate_source,
    validate_version,
)


@pytest.mark.parametrize("version", ["v0.1.0", "v1.0.0", "v23.10.100"])
def test_accept_stable_version(version):
    assert validate_version(version) == version


@pytest.mark.parametrize(
    "version",
    [
        "1.0.0",
        "v01.0.0",
        "v1.00.0",
        "v1.0.0-rc1",
        " v1.0.0",
        "v1.0.0\n",
        "v1.0.0;id",
        "",
        None,
    ],
)
def test_reject_unsafe_version_without_echo(version):
    with pytest.raises(ValueError, match="Invalid release version"):
        validate_version(version)


def test_fixed_packages_and_full_commit_tags():
    assert release_image("worker") == "ghcr.io/christophervalle85/containerguard-worker"
    assert release_tags("v1.0.0", "a" * 40) == ("v1.0.0", "sha-" + "a" * 40)
    with pytest.raises(ValueError):
        release_image("api;id")
    with pytest.raises(ValueError):
        release_tags("v1.0.0", "abc")


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


@pytest.fixture
def repository(tmp_path):
    git(tmp_path, "init", "-b", "main")
    git(tmp_path, "config", "user.name", "Release Test")
    git(tmp_path, "config", "user.email", "test@example.invalid")
    git(tmp_path, "commit", "--allow-empty", "-m", "first")
    commit = git(tmp_path, "rev-parse", "HEAD")
    git(tmp_path, "update-ref", "refs/remotes/origin/main", commit)
    return tmp_path, commit


@pytest.mark.parametrize("annotated", [False, True])
def test_peels_main_tag(repository, annotated):
    repo, commit = repository
    git(repo, "tag", *(["-a", "-m", "release"] if annotated else []), "v1.0.0")
    assert validate_source("v1.0.0", commit, repository=repo) == commit


def test_rejects_wrong_event_and_moved_tag(repository):
    repo, commit = repository
    git(repo, "tag", "v1.0.0")
    with pytest.raises(ValueError):
        validate_source("v1.0.0", "b" * 40, repository=repo)
    git(repo, "commit", "--allow-empty", "-m", "second")
    git(repo, "tag", "-f", "v1.0.0")
    with pytest.raises(ValueError):
        validate_source("v1.0.0", commit, repository=repo)


def test_rejects_non_main_commit(repository):
    repo, _ = repository
    git(repo, "checkout", "-b", "feature")
    git(repo, "commit", "--allow-empty", "-m", "unreviewed")
    git(repo, "tag", "v1.0.0")
    with pytest.raises(ValueError):
        validate_source("v1.0.0", git(repo, "rev-parse", "HEAD"), repository=repo)
