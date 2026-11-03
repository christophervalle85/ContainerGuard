"""Exercise Docker's context filtering without sending repository contents."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("frontend", [False, True])
def test_context_excludes_nested_local_configuration(tmp_path, frontend):
    context = tmp_path / "context"
    context.mkdir()
    shutil.copyfile(
        ROOT / ("Dockerfile.frontend.dockerignore" if frontend else ".dockerignore"),
        context / ("Dockerfile.frontend.dockerignore" if frontend else ".dockerignore"),
    )
    required = (
        [
            "src/main.tsx",
            "tests/example.ts",
            "package.json",
            "package-lock.json",
            ".npmrc",
            "tsconfig.json",
            "vite.config.ts",
            "nginx.conf",
            "index.html",
        ]
        if frontend
        else [
            "app/main.py",
            "migrations/env.py",
            "pyproject.toml",
            "uv.lock",
            "alembic.ini",
        ]
    )
    if frontend:
        required = ["frontend/" + name for name in required]
    prefix = "frontend/src" if frontend else "app"
    excluded = [
        ".env",
        "notes.md",
        "app/private.py" if frontend else "frontend/private.ts",
        "frontend/.env",
        "frontend/node_modules/private",
        "frontend/dist/private",
        ".git/config",
        f"{prefix}/.env.local",
        f"{prefix}/private.pem",
        f"{prefix}/debug.log",
        f"{prefix}/credentials.json",
        f"{prefix}/.cache/data",
        f"{prefix}/id_rsa",
        f"{prefix}/.git/config",
        f"{prefix}/__pycache__/code.pyc",
    ]
    for name in required + excluded:
        path = context / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("nonfunctional context marker\n")
    dockerfile = context / ("Dockerfile.frontend" if frontend else "Dockerfile.inspect")
    dockerfile.write_text("FROM scratch\nCOPY . /\n")
    if frontend:
        (context / ".dockerignore").write_text("**\n")
    output = tmp_path / "output"
    subprocess.run(
        [
            "docker",
            "build",
            "-f",
            str(dockerfile),
            "--output",
            f"type=local,dest={output}",
            str(context),
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )
    assert all((output / name).is_file() for name in required)
    assert not any((output / name).exists() for name in excluded)


def test_frontend_build_callers_use_root_context(tmp_path, monkeypatch):
    import json
    import os

    import yaml

    compose = yaml.safe_load((ROOT / "compose.yaml").read_text())
    frontend = compose["services"]["frontend"]["build"]
    assert (ROOT / frontend["context"]).resolve() == ROOT
    assert frontend["dockerfile"] == "Dockerfile.frontend"
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    step = next(
        s
        for s in workflow["jobs"]["containers"]["steps"]
        if s.get("name") == "Build runtime image"
    )
    executable = tmp_path / "docker"
    executable.write_text(
        "#!/usr/bin/env python3\nimport json,os,sys\n"
        "open(os.environ['ARGUMENTS'],'w').write(json.dumps(sys.argv[1:]))\n"
    )
    executable.chmod(0o755)
    for service in ("api", "worker", "frontend"):
        output = tmp_path / (service + ".json")
        subprocess.run(
            ["sh", "-eu", "-c", step["run"]],
            check=True,
            cwd=ROOT,
            env={
                **os.environ,
                "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
                "SERVICE": service,
                "ARGUMENTS": str(output),
            },
        )
        args = json.loads(output.read_text())
        assert args[-1] == "."
        assert args[args.index("-f") + 1] == "Dockerfile." + service
