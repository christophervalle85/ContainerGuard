# ContainerGuard

A learning project for container vulnerability scanning and security policies.

## Progress

M0 in progress: configuration is prepared; the health endpoint, tests, and CI
are next. Scanning is not implemented yet.

## Development setup

Requires uv and Python 3.14 (uv can install Python if needed).

```bash
uv sync --locked
```

After implementing `app/main.py`, start the local server:

```bash
uv run uvicorn app.main:app --reload --host 127.0.0.1
```

Run checks:

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

Tests will report no tests collected until the first test is written.
Commit `uv.lock`; do not commit `.venv` or real credentials.
