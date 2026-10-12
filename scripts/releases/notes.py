"""Create a new draft only; never overwrite an existing release or assets."""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from scripts.releases.compose import release_notes, render_compose, validate_release
from scripts.releases.publish import recheck_source, verify_publication_context
from scripts.releases.registry import NoRedirect

API = "https://api.github.com/repos/christophervalle85/ContainerGuard/releases"


def request(url, *, method="GET", body=None, content_type="application/json"):
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in ("api.github.com", "uploads.github.com")
        or parsed.username
        or parsed.port not in (None, 443)
    ):
        raise ValueError("Untrusted release endpoint")
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("Draft release credentials unavailable")
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": content_type,
    }
    try:
        try:
            response = urllib.request.build_opener(NoRedirect()).open(
                urllib.request.Request(url, data=body, method=method, headers=headers),
                timeout=30,
            )
        except urllib.error.HTTPError as error:
            if method == "GET" and error.code == 404:
                return 404, {}
            raise ValueError("Draft release request refused") from None
        with response:
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError("Draft response exceeded bounds")
            return response.code, json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ValueError("Draft release request failed") from None


def create_draft(manifest: dict, directory: Path) -> str:
    validate_release(manifest)
    version, commit = manifest["version"], manifest["commit"]
    verify_publication_context(version, commit)
    recheck_source(version, commit)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "release.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (directory / "compose.release.yaml").write_text(render_compose(manifest))
    notes = release_notes(manifest)
    status, _ = request(API + "/tags/" + version)
    if status != 404:
        raise ValueError("Refusing to replace an existing GitHub Release")
    payload = {
        "tag_name": version,
        "target_commitish": commit,
        "name": "ContainerGuard " + version,
        "body": notes,
        "draft": True,
        "prerelease": False,
    }
    status, response = request(API, method="POST", body=json.dumps(payload).encode())
    release_id = response.get("id")
    if (
        status != 201
        or type(release_id) is not int
        or release_id < 1
        or response.get("draft") is not True
    ):
        raise ValueError("Draft creation not verified")
    for name in ("release.json", "compose.release.yaml"):
        url = (
            "https://uploads.github.com/repos/christophervalle85/ContainerGuard/releases/"
            + str(release_id)
            + "/assets?name="
            + name
        )
        status, asset = request(
            url,
            method="POST",
            body=(directory / name).read_bytes(),
            content_type="application/octet-stream",
        )
        if (
            status != 201
            or asset.get("name") != name
            or asset.get("state") != "uploaded"
        ):
            raise ValueError("Draft release asset upload not verified")
    return (
        "https://github.com/christophervalle85/ContainerGuard/releases/tag/" + version
    )
