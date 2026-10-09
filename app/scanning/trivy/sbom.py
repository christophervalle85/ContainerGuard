"""Validate bounded CycloneDX output from the pinned Trivy runtime."""

import hashlib
import json
import math
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlsplit

MAX_SBOM_BYTES = 10 * 1024 * 1024
_HUB_HOSTS = {"docker.io", "index.docker.io", "registry-1.docker.io"}


@dataclass(frozen=True)
class ParsedSbom:
    payload: bytes
    format: str
    format_version: str
    scanner_version: str
    pinned_reference: str
    platform: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class SbomOutcome:
    artifact: ParsedSbom | None
    error_code: str | None

    def __post_init__(self) -> None:
        if self.artifact is not None:
            if not isinstance(self.artifact, ParsedSbom) or self.error_code is not None:
                raise ValueError("Expected exactly one SBOM outcome")
        elif not isinstance(self.error_code, str) or not self.error_code.strip():
            raise ValueError("Expected exactly one SBOM outcome")


def _object(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError
    return value


def _list(value: object) -> list:
    if not isinstance(value, list):
        raise ValueError
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError
    return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError
    return number


def _reference_identity(value: object, *, allow_short: bool) -> tuple[str, str]:
    reference = _text(value)
    repository, separator, digest = reference.rpartition("@")
    if separator != "@" or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise ValueError

    first, slash, rest = repository.partition("/")
    if first in _HUB_HOSTS and slash:
        repository = rest
    elif not allow_short or "." in first or ":" in first:
        raise ValueError

    if re.fullmatch(r"[a-z0-9]+(?:[._/-][a-z0-9]+)*", repository) is None:
        raise ValueError
    if "/" not in repository:
        repository = "library/" + repository
    return repository, digest


def _validate_package_url(value: object, expected: tuple[str, str]) -> None:
    url = urlsplit(_text(value))
    if url.scheme != "pkg" or url.netloc or url.fragment:
        raise ValueError
    name, separator, digest = unquote(url.path, errors="strict").rpartition("@")
    if separator != "@" or name != "oci/" + expected[0].rsplit("/", 1)[-1]:
        raise ValueError
    qualifiers = parse_qsl(url.query, keep_blank_values=True, strict_parsing=True)
    if len({key for key, _ in qualifiers}) != len(qualifiers):
        raise ValueError
    qualifiers = dict(qualifiers)
    if qualifiers.get("arch") != "amd64":
        raise ValueError
    if "os" in qualifiers and qualifiers["os"] != "linux":
        raise ValueError
    repository = _text(qualifiers.get("repository_url"))
    if _reference_identity(repository + "@" + digest, allow_short=False) != expected:
        raise ValueError


def _validate_identity(metadata: dict, expected: tuple[str, str]) -> None:
    component = _object(metadata.get("component"))
    if component.get("type") != "container":
        raise ValueError
    _text(component.get("name"))
    _validate_package_url(component.get("purl"), expected)

    digests = []
    for item in _list(component.get("properties")):
        prop = _object(item)
        if prop.get("name") == "aquasecurity:trivy:RepoDigest":
            digests.append(_reference_identity(prop.get("value"), allow_short=True))
    if not digests or any(identity != expected for identity in digests):
        raise ValueError

    tools = _list(_object(metadata.get("tools")).get("components"))
    versions = [
        tool.get("version")
        for item in tools
        if (tool := _object(item)).get("name") == "trivy"
    ]
    if not versions or any(version != "0.75.0" for version in versions):
        raise ValueError


def _validate_inventory(value: object) -> None:
    for item in _list(value):
        component = _object(item)
        _text(component.get("type"))
        _text(component.get("name"))
        for field in ("version", "bom-ref", "purl"):
            if field in component and not isinstance(component[field], str):
                raise ValueError


def parse_sbom(
    payload: bytes,
    *,
    pinned_reference: str,
    platform: str,
    scanner_version: str,
) -> ParsedSbom:
    """Check Trivy's scoped output contract; this is not full schema validation."""
    try:
        if not isinstance(payload, bytes) or len(payload) > MAX_SBOM_BYTES:
            raise ValueError
        if platform != "linux/amd64" or scanner_version != "0.75.0":
            raise ValueError
        expected = _reference_identity(pinned_reference, allow_short=False)
        document = _object(
            json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
                parse_float=_finite_float,
            )
        )
        if document.get("bomFormat") != "CycloneDX":
            raise ValueError
        if document.get("specVersion") != "1.7":
            raise ValueError
        _validate_identity(_object(document.get("metadata")), expected)
        _validate_inventory(document.get("components"))
    except ValueError, RecursionError, OverflowError:
        raise ValueError("Invalid CycloneDX SBOM") from None

    return ParsedSbom(
        payload=payload,
        format="CycloneDX",
        format_version="1.7",
        scanner_version=scanner_version,
        pinned_reference=pinned_reference,
        platform=platform,
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
    )
