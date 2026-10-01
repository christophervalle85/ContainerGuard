# ContainerGuard

I'm building ContainerGuard to learn how a container security tool fits together,
from accepting an image reference to explaining whether its findings meet a policy.

Right now, the project has a FastAPI health endpoint, an automated test, and CI
that checks tests, linting, and formatting. Image scanning, a database, and a
dashboard are planned for later milestones.

## Run it locally

You'll need Git and [uv](https://docs.astral.sh/uv/getting-started/installation/).
The project uses Python 3.14. If you don't have it, uv can install it for you.

```bash
git clone https://github.com/christophervalle85/ContainerGuard.git
cd ContainerGuard
uv python install
uv sync --locked
uv run uvicorn app.main:app --reload --host 127.0.0.1
```

Open <http://127.0.0.1:8000/health>. You should get:

```json
{"status": "ok"}
```

FastAPI's interactive API docs are at <http://127.0.0.1:8000/docs>.
Use Ctrl+C in the terminal to stop the server.

The server binds to localhost. No credentials, database, Docker setup, or `.env`
file are needed at this stage.

If port 8000 is already in use, add `--port 8001` to the server command and use
that port in the browser.

## Run the checks

From the project folder:

```bash
uv run --locked pytest
uv run --locked ruff check .
uv run --locked ruff format --check .
```

The health test checks both the HTTP status code and the response body. To apply
formatting changes, run `uv run ruff format .`, then repeat the checks.

GitHub Actions runs the same checks on pushes to `main` and on pull requests.
During M0, I deliberately changed the health response on a test branch, watched
the pull request's test fail, and restored the response to get a passing run.
That exercise is recorded in [PR #1](https://github.com/christophervalle85/ContainerGuard/pull/1).

## Where things live

- `app/main.py`: the FastAPI application and health endpoint.
- `tests/test_health.py`: the endpoint's test.
- `pyproject.toml`: dependencies and settings for pytest and Ruff.
- `uv.lock`: exact dependency versions used to recreate the environment.
- `.python-version`: the project's Python version.
- `.github/workflows/ci.yml`: the automated GitHub checks.
- `.env.example`: a placeholder for future configuration, with no credentials.

Commit the lockfile. Keep `.venv`, caches, and real credentials out of Git.
uv recreates the local environment from the committed dependency files.

## Next milestone

M1 adds a scan API with mocked results so I can define and test the interface
before connecting a real scanner. The current health endpoint only confirms
that the API responds; it doesn't check a scanner or any external services.
