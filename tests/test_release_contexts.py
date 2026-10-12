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
        ROOT / ("frontend/.dockerignore" if frontend else ".dockerignore"),
        context / ".dockerignore",
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
    prefix = "src" if frontend else "app"
    excluded = [
        ".env",
        "notes.md",
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
    dockerfile = tmp_path / "Dockerfile.inspect"
    dockerfile.write_text("FROM scratch\nCOPY . /\n")
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
