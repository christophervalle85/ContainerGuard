"""Redacted Gitleaks inspection of bounded layer bytes and image metadata."""

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections import Counter
from pathlib import Path

from scripts.releases.artifacts import inspect_image_archive, read_json

ROOT = Path(__file__).resolve().parents[2]
PROCESS_TIMEOUT = 60
IMAGE_TIMEOUT = 600
MAX_REPORT = 1024 * 1024
BATCH = 4 * 1024 * 1024
OVERLAP = 8192


class DisclosureBlocked(ValueError):
    """A validated secret detector result blocks publication."""


def check_disclosure(archive: Path, output: Path) -> dict:
    output.unlink(missing_ok=True)
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GITLEAKS_")
    }
    executable = shutil.which("gitleaks")
    if not executable:
        raise ValueError("Disclosure scanner unavailable")
    try:
        version = subprocess.run(
            [executable, "version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        if version.stdout.strip() != "8.30.1":
            raise ValueError("Disclosure scanner version mismatch")
    except (OSError, subprocess.SubprocessError):
        raise ValueError("Disclosure scanner unavailable") from None
    started = time.monotonic()
    rules, files, pending = Counter(), 0, bytearray()
    with tempfile.TemporaryDirectory(prefix="containerguard-disclosure-") as directory:
        scratch = Path(directory)
        ignore = scratch / ".gitleaksignore"
        ignore.write_text("")
        report, data = scratch / "report.json", scratch / "input"

        def scan(raw):
            if time.monotonic() - started > IMAGE_TIMEOUT:
                raise ValueError("Disclosure inspection deadline exceeded")
            data.write_bytes(raw)
            report.unlink(missing_ok=True)
            command = [
                executable,
                "stdin",
                "--config",
                str(ROOT / "security/gitleaks.toml"),
                "--redact=100",
                "--ignore-gitleaks-allow",
                "--gitleaks-ignore-path",
                str(ignore),
                "--max-decode-depth=1",
                "--max-archive-depth=0",
                "--timeout=60",
                "--no-banner",
                "--no-color",
                "--report-format",
                "json",
                "--report-path",
                str(report),
            ]
            with data.open("rb") as source:
                process = subprocess.Popen(
                    command,
                    stdin=source,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    cwd=scratch,
                    env=environment,
                )
                try:
                    deadline = min(
                        started + IMAGE_TIMEOUT, time.monotonic() + PROCESS_TIMEOUT
                    )
                    while process.poll() is None:
                        if time.monotonic() > deadline or (
                            report.exists() and report.stat().st_size > MAX_REPORT
                        ):
                            raise ValueError("Disclosure scanner exceeded bounds")
                        time.sleep(0.02)
                    if (
                        process.returncode not in (0, 1)
                        or not report.is_file()
                        or report.stat().st_size > MAX_REPORT
                    ):
                        raise ValueError("Disclosure scanner failed")
                    findings = read_json(report.read_bytes())
                    if not isinstance(findings, list) or bool(findings) != (
                        process.returncode == 1
                    ):
                        raise ValueError("Disclosure scanner report invalid")
                    for finding in findings:
                        rule = (
                            finding.get("RuleID") if isinstance(finding, dict) else None
                        )
                        if not isinstance(rule, str) or not re.fullmatch(
                            r"[a-z0-9-]{1,100}", rule
                        ):
                            raise ValueError("Disclosure scanner report invalid")
                        rules[rule] += 1
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=5)

        def visit(kind, stream, size):
            nonlocal files
            if kind == "file":
                files += 1
            pending.extend(b"\n")
            while chunk := stream.read(256 * 1024):
                pending.extend(chunk)
                if len(pending) >= BATCH:
                    scan(pending)
                    tail = pending[-OVERLAP:]
                    pending.clear()
                    pending.extend(tail)
            pending.extend(b"\n")
            if time.monotonic() - started > IMAGE_TIMEOUT:
                raise ValueError("Disclosure inspection deadline exceeded")

        try:
            info = inspect_image_archive(archive, visitor=visit)
            if pending:
                scan(pending)
        except (OSError, subprocess.SubprocessError):
            raise ValueError("Disclosure inspection failed") from None
    summary = {
        "schema_version": 1,
        "archive_sha256": info["sha256"],
        "layers": len(info["diff_ids"]),
        "files": files,
        "rules": dict(rules),
        "blocked": bool(rules),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2) + "\n")
    if rules:
        raise DisclosureBlocked("Image disclosure check blocked publication")
    return summary
