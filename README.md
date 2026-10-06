# ContainerGuard

I'm building ContainerGuard to learn how a container security tool fits together,
from accepting an image reference to explaining whether its findings meet a policy.

Right now, the API accepts an image reference, creates a mock scan, and lets you
retrieve its record, browse scan history, and filter fictional findings. Scans
and findings are saved in PostgreSQL and survive service restarts. Tests
and GitHub Actions check the API behavior, linting, and formatting.

The findings are sample data. ContainerGuard does not contact a registry, pull
an image, or run a vulnerability scanner yet.

## Run it locally

You'll need Git, Docker with Compose, and [uv](https://docs.astral.sh/uv/getting-started/installation/).
The project uses Python 3.14. If you don't have it, uv can install it for you.

```bash
git clone https://github.com/christophervalle85/ContainerGuard.git
cd ContainerGuard
uv python install
uv sync --locked
docker compose --env-file .env.example up -d --wait db
uv run --env-file .env.example alembic upgrade head
uv run --env-file .env.example uvicorn app.main:app --reload --host 127.0.0.1
```

Open <http://127.0.0.1:8000/health>. You should get:

```json
{"status": "ok"}
```

FastAPI's interactive API docs are at <http://127.0.0.1:8000/docs>.
Use Ctrl+C in the terminal to stop the server.

Start your Docker engine before following the setup commands. Migrations create
the tables; the application does not migrate the database at startup. Run
`alembic upgrade head` again after pulling changes that add migrations.

The API and database ports bind to localhost. `.env.example` contains local
demonstration credentials. For custom settings, copy it to `.env` and use
`--env-file .env` in both Compose and uv commands. Real `.env` files are ignored.

PostgreSQL uses port 5432 inside its container and port 5433 on your computer.
The API runs on your computer, so DATABASE_URL uses port 5433. If that port is
occupied, change both POSTGRES_PORT and the port in DATABASE_URL. The separate
test database uses TEST_POSTGRES_PORT and TEST_DATABASE_URL, defaulting to 5434.
Keep development and test database targets separate.

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
`status_url` after committing the scan and findings together. Copy the ID into
the retrieval or findings endpoint. The mock finishes immediately, so its status is `completed`. The contract also defines
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

Database operation failures return `503` with
`{"detail": "Database temporarily unavailable"}`. Responses exclude raw SQL and
connection details. A failed submission rolls back its scan and findings.

### Saved history and restarts

Submit a scan and keep its ID. Retrieve the scan and findings, stop the API with
Ctrl+C, and restart it using the server command above. Both GET endpoints should
still return the saved data. You can also restart PostgreSQL:

```bash
docker compose --env-file .env.example restart db
docker compose --env-file .env.example up -d --wait db
```

Repeat both GET requests with the same ID. This was checked locally: the scan and
its findings remained available after both application and database restarts.
The development database stores its files in the Compose-managed `postgres_data`
named volume. Stopping or removing its container keeps that volume:

```bash
docker compose --env-file .env.example --profile test down
```

**To deliberately delete all local development scan history**, remove the volume:

```bash
docker compose --env-file .env.example --profile test down --volumes
```

After a reset, start the databases and apply migrations again. The test database
uses temporary storage and loses its contents when its container stops.

The health endpoint checks only that the API process responds. It does not check
PostgreSQL or a scanner, so it can return 200 while scan routes return 503.
The mock returns the same fictional findings for every submitted image. It does
not invent a resolved image digest or real scanner metadata.

## Run the checks

From the project folder:

```bash
docker compose --env-file .env.example --profile test up -d --wait test-db
uv run --locked --env-file .env.example pytest
uv run --locked ruff check .
uv run --locked ruff format --check .
```

Tests cover the API contract, database relationships and constraints, migrations,
atomic writes, pagination, and safe database errors. They require TEST_DATABASE_URL
to point to containerguard_test and reject a target matching development before
cleanup. Test configuration rejects URL query options that could override the
validated target and confirms the connected database name before schema changes.
Tests create disposable schemas inside that database, apply migrations,
and override API sessions to use the isolated storage. They do not clear your
development history. Some tests use real commits and new sessions to verify data.
No separate test migration command is needed locally.

To apply formatting changes, run `uv run ruff format .`, then repeat the checks.

GitHub Actions is configured to start separate PostgreSQL services, apply
migrations, and run the checks on pushes to `main` and on pull requests.
In an earlier CI exercise, I deliberately changed the health response on a test
branch, watched the pull request's test fail, and restored the response to get a passing run.
That exercise is recorded in [PR #1](https://github.com/christophervalle85/ContainerGuard/pull/1).

## Where things live

- `app/main.py`: the FastAPI application and API routes.
- `app/schemas.py`: request and response models, scan states, and severities.
- `app/database.py`: database engine and request session lifecycle.
- `app/models.py`: Image, Scan, and Finding database models.
- `app/repository.py`: database writes, reads, filtering, and pagination.
- `migrations/` and `alembic.ini`: database schema migrations.
- `compose.yaml`: development and test PostgreSQL services.
- `docs/architecture/persistence.md`: storage design and decisions.
- `app/mock_scanner.py`: fictional findings for the API demonstration.
- `tests/`: API and PostgreSQL integration tests.
- `pyproject.toml`: dependencies and settings for pytest and Ruff.
- `uv.lock`: exact dependency versions used to recreate the environment.
- `.python-version`: the project's Python version.
- `.github/workflows/ci.yml`: the automated GitHub checks.
- `.env.example`: local demonstration database configuration.

Commit the lockfile. Keep `.venv`, caches, and real credentials out of Git.
uv recreates the local environment from the committed dependency files.

## Next steps

Replace fictional findings with real Trivy results, record the resolved image
digest and platform, and store scanner metadata and meaningful scan failures.
Background jobs and a dashboard follow later.
