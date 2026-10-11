"""Run Trivy, validate its completed report, then apply the release gate."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from scripts.security_gate import evaluate_report, read_json

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=["filesystem", "image"], required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--expected-target", action="append", default=[])
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    report_path, summary_path = output / "report.json", output / "summary.json"
    try:
        if not 1 <= args.timeout <= 900:
            raise ValueError("Invalid timeout")
        output.mkdir(parents=True, exist_ok=True)
        for filename in ("report.json", "summary.json", "scanner.json"):
            (output / filename).unlink(missing_ok=True)
        scanner = shutil.which("trivy")
        if scanner is None:
            raise ValueError("Scanner missing")
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("TRIVY_")
        }
        with tempfile.TemporaryDirectory(
            prefix="containerguard-security-"
        ) as directory:
            staging = Path(directory)
            if args.kind == "filesystem":
                source = Path(args.input).resolve()
                (staging / "frontend").mkdir()
                for lock in ("uv.lock", "frontend/package-lock.json"):
                    shutil.copyfile(source / lock, staging / lock)
                command = [scanner, "fs", "--include-dev-deps"]
                reference = "."
            else:
                command = [
                    scanner,
                    "image",
                    "--image-src",
                    "docker",
                    "--platform",
                    "linux/amd64",
                ]
                reference = args.input
                if reference != args.target:
                    raise ValueError("Image target mismatch")
            command += [
                "--scanners",
                "vuln",
                "--format",
                "json",
                "--output",
                str(report_path),
                "--timeout",
                f"{args.timeout}s",
                "--config",
                "",
                "--ignorefile",
                "",
                "--exit-code",
                "0",
                "--",
                reference,
            ]
            subprocess.run(
                command,
                cwd=staging,
                env=environment,
                timeout=args.timeout,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            version = subprocess.run(
                [scanner, "--version", "--format", "json"],
                cwd=staging,
                env=environment,
                timeout=10,
                check=True,
                capture_output=True,
            )
            metadata = json.loads(version.stdout)
        if metadata.get("Version") not in {"0.75.0", "0.75.0+cg.1"}:
            raise ValueError("Unexpected scanner version")
        report = read_json(report_path)
        summary = evaluate_report(
            report,
            read_json(ROOT / "security/exceptions.json"),
            target=args.target,
            expected_targets=set(args.expected_target),
            now=datetime.now(UTC),
        )
        (output / "scanner.json").write_text(json.dumps(metadata, indent=2) + "\n")
        summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    except (
        OSError,
        ValueError,
        TypeError,
        AttributeError,
        RecursionError,
        subprocess.SubprocessError,
    ):
        # No stale or unvalidated report is eligible for artifact upload.
        for filename in ("report.json", "summary.json", "scanner.json"):
            (output / filename).unlink(missing_ok=True)
        print(
            "Security scan failed: execution or report validation was unsuccessful.",
            file=sys.stderr,
        )
        return 2
    print(
        f"Security scan {args.target}: {'BLOCKED' if summary['blocked'] else 'PASS'}; "
        f"{len(summary['findings'])} findings"
    )
    return 1 if summary["blocked"] else 0


if __name__ == "__main__":
    sys.exit(main())
