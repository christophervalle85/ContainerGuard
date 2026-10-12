"""Owned, disposable, no-build integration verification."""

import hashlib
import json
import re
import secrets
import time
import urllib.request
from pathlib import Path
from uuid import UUID, uuid4

from scripts.releases.commands import command
from scripts.releases.identity import DIGEST, SERVICES

PROJECT = re.compile(r"containerguard-release-verify-[0-9a-f]{12}")
POSTGRES = (
    "docker.io/library/postgres@sha256:"
    "d74eeac9a635390a49bc21bd49fccd973de707e2a53a76ac49b552b8712ec46f"
)
REDIS = (
    "docker.io/library/redis@sha256:"
    "b51665e66f00759be7c3152ad5ac3c66fb2f619c13ef62dea7cc1f9914524635"
)


def stack_document(images: dict[str, str], project: str, password: str) -> dict:
    if not PROJECT.fullmatch(project) or set(images) != set(SERVICES):
        raise ValueError("Invalid verification ownership or images")
    for reference in images.values():
        if not isinstance(reference, str) or not (
            DIGEST.fullmatch(reference)
            or re.fullmatch(
                r"ghcr\.io/christophervalle85/containerguard-(?:api|worker|frontend)@sha256:[0-9a-f]{64}",
                reference,
            )
        ):
            raise ValueError("Invalid verification image")
    environment = {
        "DATABASE_URL": f"postgresql+psycopg://containerguard:{password}@db:5432/containerguard",
        "REDIS_URL": "redis://redis:6379/0",
        "MAX_ACTIVE_SCANS": "20",
    }
    dependencies = {
        "db": {"condition": "service_healthy"},
        "redis": {"condition": "service_healthy"},
        "migrate": {"condition": "service_completed_successfully"},
    }
    api = {
        "image": images["api"],
        "init": True,
        "environment": environment,
        "depends_on": dependencies,
        "cpus": "1.0",
        "mem_limit": "512m",
        "pids_limit": 128,
        "ports": [{"target": 8000, "published": "0", "host_ip": "127.0.0.1"}],
        "healthcheck": {
            "test": [
                "CMD",
                "python",
                "-c",
                "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=3).close()",
            ],
            "interval": "5s",
            "timeout": "5s",
            "retries": 10,
            "start_period": "10s",
        },
    }
    services = {
        "api": api,
        "worker": {
            "image": images["worker"],
            "init": True,
            "environment": {**environment, "RQ_WORKER_NAME": "containerguard-worker"},
            "depends_on": dependencies,
            "stop_grace_period": "650s",
            "cpus": "2.0",
            "mem_limit": "2g",
            "pids_limit": 256,
            "volumes": ["trivy_cache:/var/cache/trivy"],
            "healthcheck": {
                "test": ["CMD", "python", "-m", "app.jobs.health"],
                "interval": "15s",
                "timeout": "8s",
                "retries": 5,
                "start_period": "10s",
            },
        },
        "frontend": {
            "image": images["frontend"],
            "init": True,
            "depends_on": {"api": {"condition": "service_healthy"}},
            "cpus": "0.5",
            "mem_limit": "128m",
            "pids_limit": 64,
            "ports": [{"target": 8080, "published": "0", "host_ip": "127.0.0.1"}],
            "healthcheck": {
                "test": [
                    "CMD",
                    "wget",
                    "-q",
                    "-O",
                    "/dev/null",
                    "http://127.0.0.1:8080/healthz",
                ],
                "interval": "5s",
                "timeout": "3s",
                "retries": 5,
            },
        },
        "migrate": {
            "image": images["api"],
            "command": ["alembic", "upgrade", "head"],
            "environment": {"DATABASE_URL": environment["DATABASE_URL"]},
            "depends_on": {"db": {"condition": "service_healthy"}},
            "cpus": "1.0",
            "mem_limit": "512m",
            "pids_limit": 128,
        },
        "db": {
            "image": POSTGRES,
            "environment": {
                "POSTGRES_USER": "containerguard",
                "POSTGRES_DB": "containerguard",
                "POSTGRES_PASSWORD": password,
            },
            "volumes": ["postgres_data:/var/lib/postgresql/data"],
            "healthcheck": {
                "test": [
                    "CMD",
                    "pg_isready",
                    "-U",
                    "containerguard",
                    "-d",
                    "containerguard",
                ],
                "interval": "5s",
                "timeout": "5s",
                "retries": 20,
            },
        },
        "redis": {
            "image": REDIS,
            "command": [
                "redis-server",
                "--appendonly",
                "yes",
                "--appendfsync",
                "everysec",
                "--save",
                "",
                "--maxmemory",
                "128mb",
                "--maxmemory-policy",
                "noeviction",
            ],
            "volumes": ["redis_data:/data"],
            "cpus": "0.5",
            "mem_limit": "256m",
            "pids_limit": 64,
            "healthcheck": {
                "test": ["CMD", "redis-cli", "ping"],
                "interval": "5s",
                "timeout": "3s",
                "retries": 20,
            },
        },
    }
    for service in services.values():
        service["platform"] = "linux/amd64"
    return {
        "name": project,
        "services": services,
        "volumes": {"postgres_data": {}, "redis_data": {}, "trivy_cache": {}},
    }


def cleanup_stack(project: str, config: Path):
    if not PROJECT.fullmatch(project) or config.is_symlink():
        raise ValueError("Refusing cleanup of an unowned stack")
    document = json.loads(config.read_text())
    try:
        images = {
            service: document["services"][service]["image"] for service in SERVICES
        }
        password = document["services"]["db"]["environment"]["POSTGRES_PASSWORD"]
        if document != stack_document(images, project, password):
            raise ValueError("Refusing cleanup of an unowned stack")
    except (KeyError, TypeError):
        raise ValueError("Refusing cleanup of an unowned stack") from None
    command(
        [
            "docker",
            "compose",
            "-p",
            project,
            "-f",
            str(config),
            "down",
            "--volumes",
            "--remove-orphans",
        ],
        timeout=700,
    )


def poll_scan(request, scan_id: str, *, timeout=600) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        scan = request("/api/v1/scans/" + scan_id)
        if scan["status"] == "completed":
            if scan.get("mock") is not False:
                raise ValueError("Verification scan is not real")
            return scan
        if scan["status"] == "failed":
            raise ValueError("Verification scan failed")
        time.sleep(2)
    raise ValueError("Verification scan deadline exceeded")


def check_sbom(metadata: dict, payload: bytes) -> str:
    digest = hashlib.sha256(payload).hexdigest()
    if (
        metadata.get("status") != "available"
        or metadata.get("sha256") != digest
        or metadata.get("size_bytes") != len(payload)
    ):
        raise ValueError("Verification SBOM integrity failed")
    return digest


def exercise_stack(
    images: dict[str, str], *, workspace: Path, platform="linux/amd64"
) -> dict:
    if platform != "linux/amd64":
        raise ValueError("Unsupported verification platform")
    project = "containerguard-release-verify-" + uuid4().hex[:12]
    workspace.mkdir(parents=True, exist_ok=True)
    config = workspace / (project + ".json")
    config.write_text(
        json.dumps(stack_document(images, project, secrets.token_hex(24)))
    )
    config.chmod(0o600)
    compose = ["docker", "compose", "-p", project, "-f", str(config)]
    error = None
    try:
        command(
            compose + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "150"],
            timeout=210,
        )
        migration = command(compose + ["ps", "-aq", "migrate"], capture=True).strip()
        if (
            not migration
            or command(
                ["docker", "inspect", "--format", "{{.State.ExitCode}}", migration],
                capture=True,
            ).strip()
            != "0"
        ):
            raise ValueError("Verification migration failed")

        def address(service, port):
            endpoint = command(
                compose + ["port", service, str(port)], capture=True
            ).strip()
            if not re.fullmatch(r"127\.0\.0\.1:[0-9]{1,5}", endpoint):
                raise ValueError("Unexpected verification address")
            return "http://" + endpoint

        base = address("api", 8000)

        def request(path, body=None, *, raw=False, origin=None):
            data = json.dumps(body).encode() if body is not None else None
            req = urllib.request.Request(
                (origin or base) + path,
                data=data,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=20) as response:
                payload = response.read(32 * 1024**2 + 1)
            if len(payload) > 32 * 1024**2:
                raise ValueError("Verification response exceeded bounds")
            return payload if raw else json.loads(payload)

        if request("/health") != {"status": "ok"}:
            raise ValueError("Verification health failed")
        frontend = address("frontend", 8080)
        request("/healthz", raw=True, origin=frontend)
        if b"<html" not in request("/scans", raw=True, origin=frontend).lower():
            raise ValueError("Verification frontend routing failed")
        if request("/api/v1/scans", origin=frontend)["total"] != 0:
            raise ValueError("Verification storage is not fresh")
        accepted = request(
            "/api/v1/scans", {"image_reference": "docker.io/library/alpine:3.20.0"}
        )
        scan_id = str(UUID(accepted["scan_id"]))
        scan = poll_scan(request, scan_id)
        prefix = "/api/v1/scans/" + scan_id
        findings = request(prefix + "/findings")
        if findings.get("mock") is not False:
            raise ValueError("Verification findings are not real")
        metadata = request(prefix + "/sbom/metadata")
        digest = check_sbom(metadata, request(prefix + "/sbom", raw=True))
        rules = {
            "max_critical": 2147483647,
            "max_high": 2147483647,
            "require_sbom": True,
            "unknown_severity_action": "ignore",
        }
        policy = request(
            "/api/v1/policies", {"name": "Release verification", "rules": rules}
        )
        evaluation = request(
            prefix + "/evaluations", {"policy_version_id": policy["policy_version_id"]}
        )
        if evaluation["outcome"] != "passed":
            raise ValueError("Verification permissive policy failed")
        strict = request(
            "/api/v1/policies/" + policy["policy_id"] + "/versions",
            {
                "rules": {
                    **rules,
                    "max_critical": 0,
                    "max_high": 0,
                    "unknown_severity_action": "fail",
                }
            },
        )
        strict_result = request(
            prefix + "/evaluations", {"policy_version_id": strict["policy_version_id"]}
        )
        expected = (
            "failed"
            if any(
                evaluation["counts"][severity]
                for severity in ("CRITICAL", "HIGH", "UNKNOWN")
            )
            else "passed"
        )
        if strict_result["outcome"] != expected:
            raise ValueError("Verification strict policy failed")
        duplicate = request(
            prefix + "/evaluations", {"policy_version_id": policy["policy_version_id"]}
        )
        if (duplicate["evaluation_id"], duplicate["created_at"]) != (
            evaluation["evaluation_id"],
            evaluation["created_at"],
        ):
            raise ValueError("Verification evaluation identity changed")
        command(
            compose
            + [
                "up",
                "-d",
                "--no-build",
                "--force-recreate",
                "--wait",
                "--wait-timeout",
                "150",
                "api",
                "worker",
                "frontend",
            ],
            timeout=850,
        )
        base = address("api", 8000)
        if (
            check_sbom(
                request(prefix + "/sbom/metadata"), request(prefix + "/sbom", raw=True)
            )
            != digest
        ):
            raise ValueError("Verification persisted SBOM changed")
        retained = request(prefix + "/evaluations")["items"]
        if not any(
            item["evaluation_id"] == evaluation["evaluation_id"]
            and item["created_at"] == evaluation["created_at"]
            for item in retained
        ):
            raise ValueError("Verification persisted evaluation missing")
        return {
            "passed": True,
            "project": project,
            "scan_id": scan_id,
            "findings": findings["total"],
            "scanner_version": scan["scanner_version"],
            "sbom_sha256": digest,
            "evaluation_id": evaluation["evaluation_id"],
            "recreation_retained": True,
        }
    except BaseException as caught:
        error = caught
        raise
    finally:
        try:
            cleanup_stack(project, config)
        except Exception:
            if error is not None:
                error.add_note(
                    "Verification cleanup also failed; owned project: " + project
                )
            else:
                raise ValueError(
                    "Verification cleanup failed; owned project: " + project
                ) from None
        else:
            config.unlink(missing_ok=True)
