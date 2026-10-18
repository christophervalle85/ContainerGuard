"""Bounded exact-byte disclosure audit shared with future release evidence work."""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

from scripts.releases.artifacts import unique
from scripts.releases.disclosure import DisclosureBlocked, disclosure_scanner

DOCUMENT_LIMIT = 4 * 1024 * 1024
COMBINED_LIMIT = 256 * 1024 * 1024
MAX_DOCUMENTS = COMBINED_LIMIT // DOCUMENT_LIMIT
URL = re.compile(r"(?:https?|git|ssh)://[^\s\"'<>`]+", re.IGNORECASE)
HOME = re.compile(
    r"(?<![A-Za-z0-9])(?:(?:/Users/|/home/|[A-Za-z]:\\Users\\)[^/\\\s]+|/root(?:/|$))",
    re.IGNORECASE,
)
ENVIRONMENT_KEYS = frozenset({"env", "environment", "environ", "runtime_environment"})


class EvidenceDisclosureBlocked(DisclosureBlocked):
    """Carry only the safe audit summary through the local command boundary."""

    def __init__(self, summary: dict):
        super().__init__("Evidence disclosure blocked")
        self.summary = summary


def _prepare_output(output: Path, paths: list[Path]) -> None:
    if output.is_symlink():
        raise ValueError("unsafe audit output")
    for path in paths:
        if os.path.abspath(output) == os.path.abspath(path) or (
            output.exists() and path.exists() and output.samefile(path)
        ):
            raise ValueError("audit output aliases evidence")
    output.unlink(missing_ok=True)


def _load_documents(paths: list[Path]) -> list[tuple[bytes, dict]]:
    if not paths or len(paths) > MAX_DOCUMENTS:
        raise ValueError("evidence count limit")
    documents, seen, total = [], set(), 0
    for path in paths:
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            raise ValueError("unsafe evidence input") from None
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            identity = (info.st_dev, info.st_ino)
            if not stat.S_ISREG(info.st_mode) or identity in seen:
                raise ValueError("unsafe evidence input")
            if info.st_size > DOCUMENT_LIMIT or total + info.st_size > COMBINED_LIMIT:
                raise ValueError("evidence size limit")
            seen.add(identity)
            raw, digest = bytearray(), hashlib.sha256()
            while chunk := stream.read(min(65536, DOCUMENT_LIMIT + 1 - len(raw))):
                raw.extend(chunk)
                digest.update(chunk)
                if len(raw) > DOCUMENT_LIMIT or total + len(raw) > COMBINED_LIMIT:
                    raise ValueError("evidence size limit")
            total += len(raw)
            documents.append(
                (bytes(raw), {"size_bytes": len(raw), "sha256": digest.hexdigest()})
            )
    return documents


def _parse(raw: bytes):
    def invalid_constant(value):
        raise ValueError("invalid JSON constant")

    if len(raw) > DOCUMENT_LIMIT:
        raise ValueError("evidence size limit")
    document = json.loads(
        raw, object_pairs_hook=unique, parse_constant=invalid_constant
    )
    if not isinstance(document, dict):
        raise ValueError("evidence JSON object required")
    return document


def _private_host(host: str) -> bool:
    # DNS root dots do not change host identity; URL allowances remain exact.
    host = host.rstrip(".").casefold()
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        return (
            "." not in host
            or bool(re.fullmatch(r"[0-9.]+", host))
            or host.casefold().endswith(
                (".localhost", ".local", ".internal", ".lan", ".invalid", ".test")
            )
        )


def privacy_categories(
    document, *, allowed_source_urls: frozenset[str], diagnostics=None, role="other"
) -> set[str]:
    categories = set()

    def at(*keys):
        value = document
        for key in keys:
            if not isinstance(value, dict):
                return None
            value = value.get(key)
        return value

    # Source identities need trusted exact approval; public DNS cannot prove ACLs.
    # Documentation, builder, buildType and tool download URLs are not source fields.
    locators = [
        at("buildDefinition", "externalParameters", "configSource", "uri"),
        at("runDetails", "metadata", "buildkit_metadata", "vcs", "source"),
    ]
    dependencies = at("buildDefinition", "resolvedDependencies")
    if isinstance(dependencies, list):
        locators.extend(
            item.get("uri") for item in dependencies if isinstance(item, dict)
        )
    if any(
        value is not None
        and (not isinstance(value, str) or value not in allowed_source_urls)
        for value in locators
    ):
        categories.add("unapproved-source-url")

    def record(location, matcher, candidate):
        if diagnostics is None:
            return
        relation = "other"
        if candidate in allowed_source_urls:
            relation = "exact-allowed"
        elif any(candidate.startswith(url) for url in allowed_source_urls):
            relation = "allowed-prefix"
        key = (location, matcher, relation)
        diagnostics[key] = min(diagnostics.get(key, 0) + 1, 65535)

    def location_for(location, key):
        if role == "native" and location == "native-other":
            return {
                "invocation": "native-request",
                "buildDefinition": "native-build-config",
                "runDetails": "native-run-details",
            }.get(key, location)
        if role == "native" and location == "native-run-details" and key == "source":
            return "native-source-map"
        if role == "native" and key == "request":
            return "native-request"
        if role == "native" and key in {"configSource", "resolvedDependencies", "vcs"}:
            return "native-source"
        if role == "result" and location == "result-other" and key == "tools":
            return "result-tools"
        return location

    initial_location = {
        "native": "native-other",
        "metadata": "metadata",
        "result": "result-other",
    }.get(role, "other")
    pending = [(document, initial_location)]
    while pending:
        value, location = pending.pop()
        if isinstance(value, dict):
            for key, item in value.items():
                if (
                    key.casefold() in ENVIRONMENT_KEYS
                    and isinstance(item, (dict, list, str))
                    and item
                ):
                    categories.add("runtime-environment")
                child_location = location_for(location, key)
                pending.extend(((key, child_location), (item, child_location)))
        elif isinstance(value, list):
            pending.extend((item, location) for item in value)
        elif isinstance(value, str):
            if HOME.search(value):
                categories.add("user-home-path")
            for candidate in URL.findall(value):
                try:
                    parsed = urlsplit(candidate)
                    host = parsed.hostname or ""
                    if parsed.username is not None or parsed.password is not None:
                        categories.add("credential-url")
                    if _private_host(host) and candidate not in allowed_source_urls:
                        categories.add("private-source-url")
                        record(location, "url-private-host", candidate)
                except ValueError:
                    categories.add("private-source-url")
                    record(location, "url-malformed", candidate)
            if re.search(r"(?:^|\s)[^\s/@]+@[^\s/:]+:[^\s]+", value):
                categories.add("private-source-url")
                record(location, "scp", value)
    return categories


def _audit(
    documents, output: Path, *, allowed_source_urls: frozenset[str], roles=()
) -> dict:
    categories, findings, diagnostics = set(), 0, {}
    with disclosure_scanner() as scan:
        for index, (raw, _) in enumerate(documents):
            # Hashing/bounds happened before parsing; scan original bytes unchanged.
            parsed = _parse(raw)
            rules = scan(raw)
            findings += sum(rules.values())
            if rules:
                categories.add("credential")
            categories.update(
                privacy_categories(
                    parsed,
                    allowed_source_urls=allowed_source_urls,
                    diagnostics=diagnostics,
                    role=roles[index] if roles else "other",
                )
            )
    summary = {
        "schema_version": 1,
        "blocked": bool(categories),
        "categories": sorted(categories),
        "private_source_diagnostics": [
            {
                "location": location,
                "matcher": matcher,
                "relation": relation,
                "count": count,
            }
            for (location, matcher, relation), count in sorted(diagnostics.items())
        ],
        "documents": [descriptor for _, descriptor in documents],
        "detector": {"version": "8.30.1", "finding_count": findings},
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2) + "\n")
    if categories:
        raise EvidenceDisclosureBlocked(summary)
    return summary


def check_disclosure(
    paths: list[Path],
    output: Path,
    *,
    allowed_source_urls: frozenset[str] = frozenset(),
) -> dict:
    """Audit bounded original JSON bytes; allowance is trusted caller context only."""
    _prepare_output(output, paths)
    if not isinstance(allowed_source_urls, frozenset):
        raise ValueError("immutable trusted source allowance required")
    return _audit(
        _load_documents(paths), output, allowed_source_urls=allowed_source_urls
    )


def audit_probe(directory: Path) -> dict:
    """Bind successful fixture evidence before deriving its exact URL allowance."""
    from scripts import probe_release_supply_chain as probe

    output = directory / "evidence-audit.json"
    paths = [
        directory / name
        for name in ("native-provenance.json", "metadata.json", "result.json")
    ]
    _prepare_output(output, paths)
    documents = _load_documents(paths)
    native, metadata, result = [_parse(raw) for raw, _ in documents]
    if (
        set(result)
        != {
            "passed",
            "build_invocations",
            "tools",
            "source_commit",
            "canonical",
            "native_provenance_sha256",
            "history",
            "copied_digest",
            "validation_failures",
        }
        or result["passed"] is not True
        or result["build_invocations"] != 1
        or result["validation_failures"] != []
    ):
        raise ValueError("probe not qualified")
    native_hash = documents[0][1]["sha256"]
    receipt = result["history"]
    canonical = result["canonical"]
    if (
        native_hash != result["native_provenance_sha256"]
        or "sha256:" + native_hash != receipt["predicate_digest"]
        or receipt["predicate_type"] != probe.PREDICATE_TYPE
        or receipt["build_ref"] != metadata["buildx.build.ref"]
        or receipt["output_manifest"] != canonical["manifest"]
        or receipt["output_config"] != canonical["config"]
        or metadata["containerimage.digest"] != canonical["manifest"]
        or metadata["containerimage.config.digest"] != canonical["config"]
    ):
        raise ValueError("probe evidence identity mismatch")
    commit = result["source_commit"]
    uri = native["buildDefinition"]["externalParameters"]["configSource"]["uri"]
    parsed = urlsplit(uri)
    if (
        not re.fullmatch(r"[a-f0-9]{40}", commit)
        or parsed.scheme != "git"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/fixture"
        or parsed.query
        or parsed.fragment != commit
        or parsed.port is None
        or not 1 <= parsed.port <= 65535
    ):
        raise ValueError("unexpected fixture source")
    source = f"git://127.0.0.1:{parsed.port}/fixture"
    if uri != source + "#" + commit or not probe.assess(
        native,
        commit,
        canonical["manifest"],
        result["copied_digest"],
        source,
        expected_invocation=receipt["invocation_id"],
    ):
        raise ValueError("probe source identity mismatch")
    # Only these exact already-validated fixture URLs may be network-private.
    return _audit(
        documents,
        output,
        allowed_source_urls=frozenset({source, uri}),
        roles=("native", "metadata", "result"),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        summary = audit_probe(args.probe_dir)
    except EvidenceDisclosureBlocked as error:
        summary = {
            "passed": False,
            "failure": "evidence-disclosure-blocked",
            **error.summary,
        }
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        RecursionError,
        subprocess.SubprocessError,
    ):
        summary = {"passed": False, "failure": "evidence-audit-failed"}
    else:
        summary = {"passed": True, **summary}
    print(json.dumps(summary, indent=2))
    return 0 if summary.get("passed") else 1


if __name__ == "__main__":
    sys.exit(main())
