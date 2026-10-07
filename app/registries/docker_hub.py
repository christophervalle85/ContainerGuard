"""Fetch public Docker Hub image indexes without operator credentials."""

import json
import math
import re
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

INDEX_ACCEPT = (
    "application/vnd.oci.image.index.v1+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json"
)


class RegistryRequestError(RuntimeError):
    _messages = {
        "access_denied": "Registry denied anonymous access",
        "not_found": "Registry image or tag was not found",
        "rate_limited": "Registry request rate limit was reached",
        "unavailable": "Registry request could not be completed",
        "output_limit": "Registry response exceeded its size limit",
        "invalid_response": "Registry returned an invalid response",
    }

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(self._messages[code])


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _validate_repository_and_tag(repository: str, tag: str) -> None:
    if (
        not isinstance(repository, str)
        or re.fullmatch(
            r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+",
            repository,
        )
        is None
    ):
        raise ValueError("Expected a Docker Hub namespace and repository")
    if (
        not isinstance(tag, str)
        or re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag) is None
    ):
        raise ValueError("Expected a valid image tag")


def parse_docker_tag(image_reference: str) -> tuple[str, str]:
    if not isinstance(image_reference, str):
        raise ValueError("Image reference must be a string")
    reference = image_reference.strip()
    if not reference.startswith("docker.io/") or "@" in reference:
        raise ValueError("Expected an explicit Docker Hub tag reference")
    repository, separator, tag = reference[len("docker.io/") :].rpartition(":")
    if not separator:
        raise ValueError("An explicit image tag is required")
    if "/" not in repository:
        repository = f"library/{repository}"
    _validate_repository_and_tag(repository, tag)
    return repository, tag


def _get_bytes(opener, request: Request, timeout: float, limit: int) -> bytes:
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(limit + 1)
    except HTTPError as error:
        code = {
            401: "access_denied",
            403: "access_denied",
            404: "not_found",
            429: "rate_limited",
        }.get(
            error.code,
            "unavailable"
            if error.code == 408 or 500 <= error.code < 600
            else "invalid_response",
        )
        error.close()
        raise RegistryRequestError(code) from None
    except URLError, OSError, HTTPException:
        raise RegistryRequestError("unavailable") from None
    if len(body) > limit:
        raise RegistryRequestError("output_limit")
    return body


def fetch_docker_index(
    repository: str,
    tag: str,
    timeout_seconds: float = 10,
    max_response_bytes: int = 2 * 1024 * 1024,
) -> str:
    """Use fixed HTTPS endpoints and a timeout for each network operation."""
    _validate_repository_and_tag(repository, tag)
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ValueError("Timeout must be finite and positive")
    if type(max_response_bytes) is not int or max_response_bytes <= 0:
        raise ValueError("Response size limit must be a positive integer")
    opener = build_opener(NoRedirect())
    query = urlencode(
        {"service": "registry.docker.io", "scope": f"repository:{repository}:pull"}
    )
    token_body = _get_bytes(
        opener,
        Request(f"https://auth.docker.io/token?{query}"),
        timeout_seconds,
        64 * 1024,
    )
    try:
        token_document = json.loads(token_body)
    except ValueError, UnicodeDecodeError:
        raise RegistryRequestError("invalid_response") from None
    token = (
        token_document.get("token") or token_document.get("access_token")
        if isinstance(token_document, dict)
        else None
    )
    if (
        not isinstance(token, str)
        or re.fullmatch(r"[A-Za-z0-9._~+/=-]+", token) is None
    ):
        raise RegistryRequestError("invalid_response")
    request = Request(
        f"https://registry-1.docker.io/v2/{repository}/manifests/{tag}",
        headers={"Authorization": f"Bearer {token}", "Accept": INDEX_ACCEPT},
    )
    body = _get_bytes(opener, request, timeout_seconds, max_response_bytes)
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        raise RegistryRequestError("invalid_response") from None
