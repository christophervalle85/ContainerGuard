"""Evaluate validated Trivy reports without application or database dependencies."""

import argparse
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
EXCEPTION_FIELDS = {
    "vulnerability_id",
    "package",
    "target",
    "rationale",
    "owner",
    "review_reference",
    "created_at",
    "expires_at",
}


def _text(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Invalid security report or exception")
    return value


def _utc(value: object) -> datetime:
    try:
        stamp = datetime.fromisoformat(_text(value))
    except (TypeError, ValueError):
        raise ValueError("Invalid security exception timestamp") from None
    if stamp.utcoffset() != timedelta(0):
        raise ValueError("Security exception timestamps must use UTC")
    return stamp


def _exceptions(items: list[dict], now: datetime) -> dict[tuple, dict]:
    if not isinstance(items, list) or now.utcoffset() != timedelta(0):
        raise ValueError("Invalid security exceptions or evaluation time")
    validated = {}
    for item in items:
        if not isinstance(item, dict) or set(item) != EXCEPTION_FIELDS:
            raise ValueError("Invalid security exception fields")
        for value in item.values():
            _text(value)
        created, expires = _utc(item["created_at"]), _utc(item["expires_at"])
        if not created <= now < expires <= created + timedelta(days=30):
            raise ValueError(
                "Security exception is expired or outside its review window"
            )
        key = (item["vulnerability_id"], item["package"], item["target"])
        if key in validated:
            raise ValueError("Duplicate security exception")
        validated[key] = item
    return validated


def evaluate_report(
    report: dict,
    exceptions: list[dict],
    *,
    target: str,
    expected_targets: set[str],
    now: datetime,
) -> dict:
    """Fail closed on invalid reports; preserve all findings in the summary."""
    approved = _exceptions(exceptions, now)
    if (
        not isinstance(report, dict)
        or type(report.get("SchemaVersion")) is not int
        or report["SchemaVersion"] != 2
        or report.get("ArtifactName") != _text(target)
        or report.get("ArtifactType") not in {"filesystem", "container_image"}
        or not isinstance(report.get("Results"), list)
    ):
        raise ValueError("Invalid security report envelope")
    if not isinstance(expected_targets, set) or any(
        not isinstance(value, str) or not value for value in expected_targets
    ):
        raise ValueError("Invalid expected security targets")
    is_image = report["ArtifactType"] == "container_image"
    if not is_image and not expected_targets:
        raise ValueError("Filesystem scans require expected dependency targets")
    findings, used, targets = [], {}, set()
    os_target = False
    for result in report["Results"]:
        if not isinstance(result, dict):
            raise ValueError("Invalid security result")
        result_target = _text(result.get("Target"))
        result_class = result.get("Class")
        if result_class not in {"lang-pkgs", "os-pkgs"}:
            raise ValueError("Unexpected security result class")
        _text(result.get("Type"))
        targets.add(result_target)
        os_target |= result_class == "os-pkgs"
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            vulnerabilities = []
        if not isinstance(vulnerabilities, list):
            raise ValueError("Invalid vulnerability list")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ValueError("Invalid vulnerability record")
            identifier = _text(vulnerability.get("VulnerabilityID"))
            package = _text(vulnerability.get("PkgName"))
            installed = _text(vulnerability.get("InstalledVersion"))
            severity = vulnerability.get("Severity")
            if not isinstance(severity, str) or severity not in SEVERITIES:
                raise ValueError("Invalid vulnerability severity")
            fixed = vulnerability.get("FixedVersion")
            if fixed is not None and not isinstance(fixed, str):
                raise ValueError("Invalid fixed version")
            key = (identifier, package, target)
            excepted = key in approved
            blocked = severity in {"HIGH", "CRITICAL"} and not excepted
            findings.append(
                {
                    "vulnerability_id": identifier,
                    "package": package,
                    "installed_version": installed,
                    "fixed_version": fixed,
                    "severity": severity,
                    "result_target": result_target,
                    "excepted": excepted,
                    "blocked": blocked,
                }
            )
            if excepted:
                used[key] = approved[key]
    if not expected_targets <= targets or (is_image and not os_target):
        raise ValueError("Security report is missing expected scan targets")
    return {
        "target": target,
        "blocked": any(item["blocked"] for item in findings),
        "findings": findings,
        "exceptions_used": list(used.values()),
    }


def _unique_object(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def read_json(path: Path) -> object:
    # A missing, oversized, malformed, or ambiguous report must never mean clean.
    with path.open("rb") as handle:
        raw = handle.read(50 * 1024 * 1024 + 1)
    if len(raw) > 50 * 1024 * 1024:
        raise ValueError("Security input exceeds its size limit")
    return json.loads(raw, object_pairs_hook=_unique_object)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--exceptions", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--expected-target", action="append", default=[])
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    try:
        # Do not leave a previous passing summary behind after a failed evaluation.
        args.summary.unlink(missing_ok=True)
        summary = evaluate_report(
            read_json(args.report),
            read_json(args.exceptions),
            target=args.target,
            expected_targets=set(args.expected_target),
            now=datetime.now(UTC),
        )
        args.summary.write_text(json.dumps(summary, indent=2) + "\n")
    except (OSError, ValueError, TypeError, RecursionError):
        print(
            "Security gate could not validate its inputs or write its summary.",
            file=sys.stderr,
        )
        return 2
    print(f"Security gate: {'BLOCKED' if summary['blocked'] else 'PASS'}")
    return 1 if summary["blocked"] else 0


if __name__ == "__main__":
    sys.exit(main())
