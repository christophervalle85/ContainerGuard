"""Create a new draft only; never overwrite an existing release or assets."""

import copy
import json
import os
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from scripts.releases.candidate import release_context
from scripts.releases.compose import release_notes, render_compose
from scripts.releases.disclosure import disclosure_scanner
from scripts.releases.identity import SERVICES, SOURCE
from scripts.releases.publish import recheck_source, verify_publication_context
from scripts.releases.registry import NoRedirect
from scripts.releases.supply_chain import (
    evidence,
    tools,
    verification,
)
from scripts.releases.supply_chain import (
    manifest as manifests,
)

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


def validate_assets(manifest: dict, directory: Path, *, version, commit):
    """Validate and snapshot all assets before transfer or publication."""
    if not isinstance(version, str) or not isinstance(commit, str):
        raise ValueError("Guarded release identity required")
    manifests.validate_release(manifest, version=version, commit=commit)
    verify_publication_context(version, commit)
    context = release_context(version, commit)
    if manifest["build_context"] != context:
        raise ValueError("Verification run context mismatch")
    recheck_source(version, commit)
    if (
        directory.is_symlink()
        or not directory.is_dir()
        or any(p.is_symlink() for p in directory.parents)
    ):
        raise ValueError("Unsafe verified asset directory")
    names = ["release.json", "compose.release.yaml", "verification.json"]
    kinds = ["provenance", "verification", "verification"]
    for service in SERVICES:
        for kind in manifests.KINDS:
            names.append(f"{service}.{kind}.json")
            kinds.append(kind)
        for kind in ("signature", *manifests.KINDS):
            names.append(f"{service}.{kind}.bundle.json")
            kinds.append("verification")
    if {p.name for p in directory.iterdir()} != set(names):
        raise ValueError("Unexpected verified asset inventory")
    snapshots = evidence._load_documents(
        [directory / name for name in names], kinds=kinds
    )
    assets = {name: raw for name, (raw, _) in zip(names, snapshots)}
    descriptors = {name: descriptor for name, (_, descriptor) in zip(names, snapshots)}
    if evidence._parse(assets["release.json"]) != manifest:
        raise ValueError("Verified manifest mismatch")
    receipt = evidence._parse(assets["verification.json"])
    expected = {
        "schema_version": 1,
        "version": version,
        "commit": commit,
        "manifest_sha256": descriptors["release.json"]["sha256"],
        "issuer": verification.ISSUER,
        "identity": verification.WORKFLOW + version,
        "cosign_version": tools.pins()["cosign"]["version"],
        "trust_checks": [
            "registry",
            "signature",
            "certificate",
            "transparency_log",
            "attestations",
            "evidence",
        ],
        "images": {},
    }
    for service in SERVICES:
        image = manifest["images"][service]
        for kind in manifests.KINDS:
            descriptor = descriptors[f"{service}.{kind}.json"]
            if any(
                descriptor[key] != image["evidence"][kind][key] for key in descriptor
            ):
                raise ValueError("Evidence changed after verification")
        expected["images"][service] = {
            "reference": image["reference"],
            "evidence": {
                kind: image["evidence"][kind]["sha256"] for kind in manifests.KINDS
            },
            "bundles": {
                kind: descriptors[f"{service}.{kind}.bundle.json"]["sha256"]
                for kind in ("signature", *manifests.KINDS)
            },
        }
    if type(receipt.get("schema_version")) is not int or receipt != expected:
        raise ValueError("Verification receipt mismatch")
    common = copy.deepcopy(manifest)
    common.pop("build_context")
    common["schema_version"] = 1
    for service in SERVICES:
        common["images"][service].pop("evidence")
    if assets["compose.release.yaml"] != render_compose(common).encode():
        raise ValueError("Verified compose mismatch")
    with tempfile.TemporaryDirectory(prefix="cg-assets-audit-") as scratch:
        # Compose is a fixed template with variable placeholders, so its
        # expected environment keys are not captured runtime configuration.
        with disclosure_scanner() as scan:
            if scan(assets["compose.release.yaml"]):
                raise ValueError("Compose disclosure check failed")
        evidence._audit(
            [item for index, item in enumerate(snapshots) if index != 1],
            Path(scratch) / "audit.json",
            allowed_source_urls=frozenset({SOURCE, SOURCE + "#" + commit}),
            roles=tuple(
                "native" if name.endswith(".provenance.json") else "other"
                for name in names
                if name != "compose.release.yaml"
            ),
            contexts=tuple(
                {"service": name.split(".")[0], "commit": commit}
                if name.endswith(".provenance.json")
                else {}
                for name in names
                if name != "compose.release.yaml"
            ),
        )
    notes = release_notes(common).replace(
        "Signing, provenance, cloud hosting and independent second-developer "
        "setup verification are not claimed.",
        "Consumers must independently verify signatures and attestations "
        "before installation.",
    )
    return names, assets, notes


def create_draft(manifest: dict, directory: Path, *, version=None, commit=None) -> str:
    """Consume only exact current-run snapshots from a successful verifier job."""
    names, assets, notes = validate_assets(
        manifest, directory, version=version, commit=commit
    )
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
    for name in names:
        url = (
            "https://uploads.github.com/repos/christophervalle85/ContainerGuard/releases/"
            + str(release_id)
            + "/assets?name="
            + name
        )
        status, asset = request(
            url,
            method="POST",
            body=assets[name],
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
