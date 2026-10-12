"""Bind security and smoke evidence to the exact transferred image archives."""

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from scripts.releases.artifacts import MAX_JSON, read_json, sha256_file
from scripts.releases.identity import SERVICES
from scripts.security_gate import evaluate_report
from scripts.security_gate import read_json as read_report

ROOT = Path(__file__).resolve().parents[2]


def evidence_paths():
    return ["smoke.json"] + [
        name
        for service in SERVICES
        for name in (
            f"{service}-disclosure.json",
            f"{service}-security/report.json",
            f"{service}-security/summary.json",
            f"{service}-security/scanner.json",
        )
    ]


def verify_evidence(directory: Path, images: dict) -> dict:
    path = directory / "checks.json"
    if path.is_symlink() or path.stat().st_size > MAX_JSON:
        raise ValueError("Invalid candidate evidence")
    sealed = read_json(path.read_bytes())
    if not isinstance(sealed, dict) or set(sealed) != set(evidence_paths()):
        raise ValueError("Missing candidate evidence")
    counts = {}
    total = sum(record["size_bytes"] for record in images.values())
    for name in evidence_paths():
        entry = directory / name
        limit = 50 * 1024**2 if name.endswith("report.json") else MAX_JSON
        if (
            entry.is_symlink()
            or entry.parent.is_symlink()
            or not entry.is_file()
            or entry.stat().st_size > limit
            or sha256_file(entry) != sealed[name]
        ):
            raise ValueError("Altered or oversized candidate evidence")
        total += entry.stat().st_size
    if total > 4 * 1024**3:
        raise ValueError("Candidate transfer exceeded bounds")
    smoke = read_json((directory / "smoke.json").read_bytes())
    if smoke.get("passed") is not True or smoke.get("recreation_retained") is not True:
        raise ValueError("Candidate smoke evidence did not pass")
    for service in SERVICES:
        record = images[service]
        disclosure = read_json((directory / f"{service}-disclosure.json").read_bytes())
        if (
            disclosure.get("schema_version") != 1
            or disclosure.get("blocked") is not False
            or disclosure.get("rules") != {}
            or disclosure.get("archive_sha256") != record["sha256"]
            or disclosure.get("layers") != len(record["diff_ids"])
            or type(disclosure.get("files")) is not int
            or disclosure["files"] < 1
        ):
            raise ValueError("Candidate disclosure evidence did not pass")
        report = read_report(directory / f"{service}-security/report.json")
        target = report.get("ArtifactName")
        if not isinstance(target, str) or target not in (
            record["image_id"],
            record["manifest_digest"],
        ):
            raise ValueError("Candidate scan target differs from checked archive")
        summary = evaluate_report(
            report,
            read_report(ROOT / "security/exceptions.json"),
            target=target,
            expected_targets=set(),
            now=datetime.now(UTC),
        )
        saved = read_report(directory / f"{service}-security/summary.json")
        scanner = read_json(
            (directory / f"{service}-security/scanner.json").read_bytes()
        )
        if (
            summary != saved
            or summary["blocked"] is not False
            or scanner.get("Version") not in ("0.75.0", "0.75.0+cg.1")
        ):
            raise ValueError("Candidate vulnerability evidence did not pass")
        counts[service] = dict(
            Counter(item["severity"] for item in summary["findings"])
        )
    return counts


def seal_evidence(directory: Path, images: dict) -> str:
    document = {name: sha256_file(directory / name) for name in evidence_paths()}
    path = directory / "checks.json"
    path.write_text(json.dumps(document, indent=2) + "\n")
    verify_evidence(directory, images)
    return sha256_file(path)
