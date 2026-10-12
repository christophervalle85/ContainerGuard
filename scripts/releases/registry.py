"""Bounded GHCR reads with explicit authentication and content identity checks."""

import base64
import hashlib
import os
import re
import urllib.error
import urllib.parse
import urllib.request

from scripts.releases.artifacts import MAX_JSON, read_json
from scripts.releases.identity import DIGEST, release_image, validate_version

SUPPORTED = (
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)
ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    )
)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _trusted_endpoint(url, host):
    try:
        parsed = urllib.parse.urlsplit(url)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname == host
            and parsed.port in (None, 443)
            and not parsed.username
            and not parsed.password
            and not parsed.fragment
        )
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("Untrusted registry endpoint")


def _fetch(url, headers):
    _trusted_endpoint(url, "ghcr.io")
    blob = (
        re.fullmatch(
            r"/v2/[a-z0-9/_-]+/blobs/sha256:[0-9a-f]{64}",
            urllib.parse.urlsplit(url).path,
        )
        is not None
    )
    headers = dict(headers)
    try:
        for redirects in range(4):
            request = urllib.request.Request(url, headers=headers)
            try:
                response = urllib.request.build_opener(NoRedirect()).open(
                    request, timeout=20
                )
            except urllib.error.HTTPError as error:
                if error.code in (302, 307) and blob and redirects < 3:
                    destination = error.headers.get("Location", "")
                    error.close()
                    _trusted_endpoint(
                        destination, "pkg-containers.githubusercontent.com"
                    )
                    # The signed CDN URL authorizes this download; registry tokens
                    # must never leave ghcr.io, including on subsequent redirects.
                    headers = {
                        k: v for k, v in headers.items() if k.lower() != "authorization"
                    }
                    url = destination
                    continue
                if error.code not in (401, 404):
                    error.close()
                    raise ValueError("Registry request refused") from None
                response = error
            with response:
                raw = response.read(MAX_JSON + 1)
                if len(raw) > MAX_JSON:
                    raise ValueError("Registry response exceeded bounds")
                return response.code, response.headers, raw
        raise ValueError("Registry redirect limit exceeded")
    except (OSError, urllib.error.URLError):
        raise ValueError("Registry request unavailable") from None


class Registry:
    def __init__(self, *, anonymous=False):
        self.credential = "" if anonymous else os.environ.get("GITHUB_TOKEN", "")
        self.actor = "" if anonymous else os.environ.get("GITHUB_ACTOR", "")
        self.tokens = {}

    def _get(self, repository, suffix):
        url = "https://ghcr.io/v2/" + repository + "/" + suffix
        headers = {"Accept": ACCEPT}
        if repository in self.tokens:
            headers["Authorization"] = "Bearer " + self.tokens[repository]
        status, response_headers, raw = _fetch(url, headers)
        if status == 401:
            challenge = response_headers.get("WWW-Authenticate", "")
            fields = dict(re.findall(r'([a-z]+)="([^"\r\n]*)"', challenge))
            if (
                not challenge.startswith("Bearer ")
                or fields.get("realm") != "https://ghcr.io/token"
                or fields.get("service") != "ghcr.io"
                or fields.get("scope")
                not in (
                    "repository:" + repository + ":pull",
                    "repository:" + repository + ":pull,push",
                )
            ):
                raise ValueError("Untrusted registry authentication challenge")
            token_headers = {}
            if self.credential and self.actor:
                basic = base64.b64encode(
                    (self.actor + ":" + self.credential).encode()
                ).decode()
                token_headers["Authorization"] = "Basic " + basic
            query = urllib.parse.urlencode(
                {"service": "ghcr.io", "scope": "repository:" + repository + ":pull"}
            )
            code, _, token_raw = _fetch("https://ghcr.io/token?" + query, token_headers)
            if code != 200:
                raise ValueError("Registry authentication failed")
            token = read_json(token_raw).get("token")
            if (
                not isinstance(token, str)
                or not token
                or len(token) > 16384
                or "\n" in token
                or "\r" in token
            ):
                raise ValueError("Registry authentication failed")
            self.tokens[repository] = token
            headers["Authorization"] = "Bearer " + token
            status, response_headers, raw = _fetch(url, headers)
        return status, response_headers, raw

    def manifest(self, service, reference, *, allow_missing=False):
        if not isinstance(reference, str):
            raise ValueError("Invalid registry reference")
        if not DIGEST.fullmatch(reference) and not re.fullmatch(
            r"sha-[0-9a-f]{40}", reference
        ):
            validate_version(reference)
        repository = release_image(service).partition("/")[2]
        status, headers, raw = self._get(repository, "manifests/" + reference)
        if (
            status == 404
            and allow_missing
            and self.credential
            and self.actor
            and repository in self.tokens
        ):
            error = read_json(raw)
            errors = error.get("errors")
            if (
                isinstance(errors, list)
                and len(errors) == 1
                and errors[0].get("code") in ("MANIFEST_UNKNOWN", "NAME_UNKNOWN")
            ):
                return None
        if status != 200:
            raise ValueError("Registry tag absence or identity not verified")
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if headers.get("Docker-Content-Digest") != digest or (
            DIGEST.fullmatch(reference) and reference != digest
        ):
            raise ValueError("Registry manifest digest mismatch")
        document = read_json(raw)
        try:
            if document["schemaVersion"] != 2 or document["mediaType"] not in SUPPORTED:
                raise ValueError("Unsupported registry manifest")
            config_id = document["config"]["digest"]
            if not DIGEST.fullmatch(config_id):
                raise ValueError("Invalid registry configuration")
            status, _, config_raw = self._get(repository, "blobs/" + config_id)
            if (
                status != 200
                or len(config_raw) != document["config"]["size"]
                or "sha256:" + hashlib.sha256(config_raw).hexdigest() != config_id
            ):
                raise ValueError("Registry configuration digest mismatch")
            config = read_json(config_raw)
            if config["os"] != "linux" or config["architecture"] != "amd64":
                raise ValueError("Registry platform mismatch")
            diff_ids = config["rootfs"]["diff_ids"]
            layers = document["layers"]
            if (
                not isinstance(diff_ids, list)
                or not all(DIGEST.fullmatch(d) for d in diff_ids)
                or len(diff_ids) != len(layers)
                or not all(DIGEST.fullmatch(layer["digest"]) for layer in layers)
            ):
                raise ValueError("Registry layer identity invalid")
            return {
                "digest": digest,
                "image_id": config_id,
                "diff_ids": diff_ids,
                "platform": "linux/amd64",
                "labels": config.get("config", {}).get("Labels") or {},
            }
        except (KeyError, TypeError, AttributeError):
            raise ValueError("Registry manifest invalid") from None
