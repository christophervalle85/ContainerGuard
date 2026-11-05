"""Offline full CycloneDX 1.7 validation and bounded patched Trivy capture."""

import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

from scripts.releases.commands import command_file
from scripts.releases.supply_chain.evidence import KIND_LIMITS, read_document

ROOT = Path(__file__).resolve().parents[3]
SCHEMAS = ROOT / "security/schemas/cyclonedx-1.7"
SCANNER_VERSION = "0.75.0+cg.2"


def _validator():
    try:
        if any(
            importlib.metadata.version(name) != version
            for name, version in [("jsonschema", "4.26.0"), ("referencing", "0.37.0")]
        ):
            raise ValueError
        from jsonschema import Draft7Validator, FormatChecker
        from referencing import Registry, Resource
        from referencing.exceptions import NoSuchResource

        def unavailable(uri):
            raise NoSuchResource(ref=uri)

        registry = Registry(retrieve=unavailable)
        manifest = json.loads((SCHEMAS / "manifest.json").read_text())
        documents = {}
        for name, digest in manifest["files"].items():
            data = (SCHEMAS / name).read_bytes()
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError
            if name.endswith(".schema.json"):
                schema = json.loads(data)
                documents[name] = schema
                registry = registry.with_resource(
                    schema["$id"], Resource.from_contents(schema)
                )
        checker = FormatChecker()

        def required_formats(value):
            if isinstance(value, dict):
                if (
                    isinstance(value.get("format"), str)
                    and value["format"] not in checker.checkers
                ):
                    raise ValueError("missing schema format checker")
                for child in value.values():
                    required_formats(child)
            elif isinstance(value, list):
                for child in value:
                    required_formats(child)

        for document in documents.values():
            required_formats(document)
        schema = documents["bom-1.7.schema.json"]
        Draft7Validator.check_schema(schema)
        return Draft7Validator(
            schema, registry=registry, format_checker=FormatChecker()
        )
    except (
        ImportError,
        KeyError,
        ValueError,
        OSError,
        importlib.metadata.PackageNotFoundError,
    ):
        raise ValueError("SBOM validator unavailable") from None


def image_identity(document: dict) -> str:
    """Read the single producer ImageID claim from the root container metadata."""
    try:
        component = document["metadata"]["component"]
        if component["type"] != "container":
            raise ValueError
        claims = [
            item
            for item in component["properties"]
            if item.get("name") == "aquasecurity:trivy:ImageID"
        ]
        if len(claims) != 1:
            raise ValueError
        identity = claims[0]["value"]
        if not isinstance(identity, str) or not re.fullmatch(
            r"sha256:[a-f0-9]{64}", identity
        ):
            raise ValueError
        # Reject additional identity claims anywhere, including misplaced claims.
        pending, count = [document], 0
        while pending:
            value = pending.pop()
            if isinstance(value, dict):
                if value.get("name") == "aquasecurity:trivy:ImageID":
                    count += 1
                pending.extend(value.values())
            elif isinstance(value, list):
                pending.extend(value)
        if count != 1:
            raise ValueError
        return identity
    except (KeyError, TypeError, AttributeError, ValueError):
        raise ValueError("SBOM image identity invalid") from None


def validate(document: dict) -> dict:
    """Validate every declared schema rule, then require this release scanner."""
    try:
        if not isinstance(document, dict) or document.get("$schema") not in {
            "https://cyclonedx.org/schema/bom-1.7.schema.json",
            "http://cyclonedx.org/schema/bom-1.7.schema.json",
        }:
            raise ValueError
        if (
            document.get("bomFormat") != "CycloneDX"
            or document.get("specVersion") != "1.7"
        ):
            raise ValueError
        validator = _validator()
        from referencing.exceptions import Unresolvable

        try:
            if next(validator.iter_errors(document), None) is not None:
                raise ValueError
        except Unresolvable:
            raise ValueError from None
        tools = document["metadata"]["tools"]["components"]
        if not any(
            tool.get("name") == "trivy"
            and tool.get("group") == "aquasecurity"
            and tool.get("version") == SCANNER_VERSION
            and tool.get("type") == "application"
            for tool in tools
        ):
            raise ValueError
        if (
            not isinstance(document.get("components"), list)
            or not document["components"]
        ):
            raise ValueError
        image_identity(document)
        return document
    except (
        KeyError,
        TypeError,
        AttributeError,
        ValueError,
        RecursionError,
    ):
        raise ValueError("SBOM validation failed") from None


def generate(reference: str, output: Path) -> Path:
    """Scan an imported canonical local image ID or digest without registry fallback."""
    if not isinstance(reference, str) or not re.fullmatch(
        r"(?:sha256:[a-f0-9]{64}|ghcr\.io/christophervalle85/containerguard-(?:api|worker|frontend)@sha256:[a-f0-9]{64})",
        reference,
    ):
        raise ValueError("SBOM image reference invalid")
    scanner = shutil.which("trivy")
    if scanner is None:
        raise ValueError("SBOM scanner unavailable")
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("TRIVY_")
    }
    with tempfile.TemporaryDirectory(prefix="cg-release-sbom-") as directory:
        temporary = Path(directory)
        version = temporary / "version.json"
        command_file(
            [scanner, "--version", "--format", "json"],
            version,
            limit=1024 * 1024,
            timeout=30,
            env=environment,
            cwd=temporary,
        )
        if read_document(version, kind="provenance").get("Version") != SCANNER_VERSION:
            raise ValueError("SBOM scanner version mismatch")
        captured = temporary / "sbom.json"
        command_file(
            [
                scanner,
                "image",
                "--image-src",
                "docker",
                "--platform",
                "linux/amd64",
                "--scanners",
                "license",
                "--format",
                "cyclonedx",
                "--skip-db-update",
                "--skip-java-db-update",
                "--offline-scan",
                "--timeout",
                "600s",
                "--config",
                "",
                "--ignorefile",
                "",
                "--",
                reference,
            ],
            captured,
            limit=KIND_LIMITS["sbom"],
            timeout=600,
            env=environment,
            cwd=temporary,
        )
        validate(read_document(captured, kind="sbom"))
        # Copy only after validation; no partial output is eligible as evidence.
        command_file(
            ["cat", str(captured)], output, limit=KIND_LIMITS["sbom"], timeout=30
        )
    return output
