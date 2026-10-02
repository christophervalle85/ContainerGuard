# ContainerGuard

I'm building ContainerGuard to learn how a container security tool fits together,
from accepting an image reference to explaining whether its findings meet a policy.

Right now, the API accepts an image reference, creates a mock scan, and lets you
retrieve its record, browse scan history, and filter fictional findings. Tests
and GitHub Actions check the API behavior, linting, and formatting.

The findings are sample data. ContainerGuard does not contact a registry, pull
an image, or run a vulnerability scanner yet.

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

## Try the scan API

The easiest way to try it is through <http://127.0.0.1:8000/docs>. Expand an
endpoint, click **Try it out**, fill in the request, and click **Execute**.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Check that the API responds |
| POST | `/api/v1/scans` | Submit an image reference and create a mock scan |
| GET | `/api/v1/scans` | Browse scan history, newest submissions first |
| GET | `/api/v1/scans/{scan_id}` | Retrieve one scan |
| GET | `/api/v1/scans/{scan_id}/findings` | Browse or filter its fictional findings |

Submit this JSON to `POST /api/v1/scans`:

```json
{"image_reference": "docker.io/library/alpine:3.20"}
```

The API returns `202 Accepted` with a generated `scan_id`, `status`, and
`status_url`. Copy the ID into the retrieval or findings endpoint. The mock
finishes immediately, so its status is `completed`. The contract also defines
`queued`, `running`, and `failed` for later scanner and worker integration.

Each mock scan has three fictional findings: `MOCK-001` (CRITICAL), `MOCK-002`
(HIGH), and `MOCK-003` (UNKNOWN). Findings responses include `mock: true`.
The UNKNOWN example has no known fixed version and returns `fixed_version: null`.

History and findings accept `limit` (default 20, from 1 to 100) and `offset`
(default 0, zero or greater). Both return `items`, `total`, `limit`, and `offset`.
An offset past the last record returns an empty page.

For example, with your generated ID:

```text
GET /api/v1/scans?limit=1&offset=0
GET /api/v1/scans/{scan_id}/findings?severity=HIGH&limit=20&offset=0
```

The optional severity filter accepts `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or
`UNKNOWN`. Filtering happens before pagination, and `total` counts matching
findings. Choosing LOW returns an empty list for the current sample data.

### Validation and errors

Image references must be strings with 1–512 characters after trimming surrounding
whitespace. This is basic input validation; it does not yet validate the full
container reference syntax or check that an image exists.

Invalid request fields, UUIDs, pagination values, and severity filters return
`422` with validation details. An unknown scan UUID returns `404` with
`{"detail": "Scan not found"}`. Both error types use a top-level `detail` field.

### Temporary storage

Scans and findings live in Python dictionaries inside one server process.
Stopping the server or triggering a reload clears them. Run a single process;
multiple workers would each have separate records. M2 will replace this storage
with PostgreSQL.

The health endpoint checks only that the API responds. It does not check a
scanner or any external services. The current mock always succeeds and returns
the same fictional findings for every submitted image.

## Run the checks

From the project folder:

```bash
uv run --locked pytest
uv run --locked ruff check .
uv run --locked ruff format --check .
```

Tests cover the health endpoint, scan submission and retrieval, separate scan
records, request validation, history pagination, and findings filters. Each scan
test starts with empty storage so earlier tests cannot affect its results. To
apply formatting changes, run `uv run ruff format .`, then repeat the checks.

GitHub Actions runs the same checks on pushes to `main` and on pull requests.
During M0, I deliberately changed the health response on a test branch, watched
the pull request's test fail, and restored the response to get a passing run.
That exercise is recorded in [PR #1](https://github.com/christophervalle85/ContainerGuard/pull/1).

## Where things live

- `app/main.py`: the FastAPI application and API routes.
- `app/schemas.py`: request and response models, scan states, and severities.
- `app/store.py`: temporary dictionaries for scans and findings.
- `app/mock_scanner.py`: fictional findings for the API demonstration.
- `tests/test_health.py` and `tests/test_scans.py`: API tests.
- `pyproject.toml`: dependencies and settings for pytest and Ruff.
- `uv.lock`: exact dependency versions used to recreate the environment.
- `.python-version`: the project's Python version.
- `.github/workflows/ci.yml`: the automated GitHub checks.
- `.env.example`: a placeholder for future configuration, with no credentials.

Commit the lockfile. Keep `.venv`, caches, and real credentials out of Git.
uv recreates the local environment from the committed dependency files.

## Next milestone

M2 adds PostgreSQL, SQLAlchemy models, and Alembic migrations so scan history
survives application restarts. Real Trivy scanning follows in M3.
