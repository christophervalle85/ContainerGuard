# ContainerGuard

I'm building ContainerGuard to learn how a container security tool fits together,
from accepting an image reference to explaining whether its findings meet a policy.

ContainerGuard resolves public Docker Hub tags, scans their `linux/amd64` images
with Trivy, and stores image identities, findings, scanner metadata, and outcomes
in PostgreSQL. Saved results are available through the API and survive restarts.

Submitting an image queues a background scan through Redis and RQ. A separate
worker runs Trivy while the API stays available. New findings responses use
`mock: false`; older fictional records remain identifiable with `mock: true`.

## Run it locally

For the container setup, you only need Git and Docker with Compose. Start the
Docker engine, then run:

```bash
git clone https://github.com/christophervalle85/ContainerGuard.git
cd ContainerGuard
cp .env.example .env
docker compose --env-file .env up -d --build
```

If you already have a `.env`, keep it and add any missing settings from
`.env.example`. The example credentials are for local demonstrations. Real
`.env` files are ignored by Git and excluded from the image build context.

Compose builds separate API and worker images, starts PostgreSQL and Redis,
and runs `alembic upgrade head` before starting the application services. Check
startup with:

```bash
docker compose --env-file .env ps -a
```

Expect `api`, `db`, `redis`, and `worker` to become healthy. The `migrate` service
should show `Exited (0)`; it has finished its job. A worker health check confirms
its own registration and recent heartbeat, not that every scan will succeed.

Open <http://127.0.0.1:8000/health> for `{"status":"ok"}` and
<http://127.0.0.1:8000/docs> for the interactive API. The first scan can take
longer while Trivy downloads its vulnerability database into the worker's named
cache volume. Internet access is needed for image resolution and scanner updates.

The API image contains Python and the locked application dependencies. The worker
also contains Trivy 0.75.0. Both run as UID/GID 10001, and neither mounts Docker's
socket. Submitted images are inspected remotely, without running them.
Application code is copied during the build, so rebuild after changing it.

### Configuration and ports

Container clients use `CONTAINER_DATABASE_URL` with `db:5432` and
`CONTAINER_REDIS_URL` with `redis:6379`. Host-based development commands use
`DATABASE_URL` at `127.0.0.1:5433` and `REDIS_URL` at `127.0.0.1:6380`.
Inside an application container, localhost means that container itself.

Keep database credentials in both database URLs consistent with `POSTGRES_*`.
Percent-encode special characters in URL credentials, such as `@` as `%40`.
Changing `POSTGRES_PASSWORD` does not change a password in an already initialized
PostgreSQL volume; existing databases need an explicit password change.

Published API, database, and Redis ports bind to localhost. If a port is occupied,
change `API_PORT`, `POSTGRES_PORT`, or `REDIS_PORT`. Update host URLs alongside
changed database/Redis ports; container URLs keep their internal ports. Test
services use separate ports 5434 and 6381 and dedicated storage.

### Update an existing installation

After pulling changes, build the new images, stop the application services,
and explicitly rerun migrations. This sequence does not depend on the exit state
of an older migration container:

```bash
docker compose --env-file .env build api worker
docker compose --env-file .env stop api worker
docker compose --env-file .env up -d --wait db redis
docker compose --env-file .env run --rm --no-deps migrate
docker compose --env-file .env up -d --force-recreate api worker
```

Run the commands one at a time. If migration fails, leave the application stopped
and investigate before continuing. The initial Compose startup also blocks the
API and worker if migrations fail.

### Develop with Python on the host

For editing with automatic API reload, install
[uv](https://docs.astral.sh/uv/getting-started/installation/) and
[Trivy](https://trivy.dev/) on the machine running the worker. The project uses
Python 3.14; uv can install it. On macOS, `brew install trivy` installs the scanner.
Stop the containerized API and worker first so they do not compete with host
processes for ports or jobs:

```bash
docker compose --env-file .env stop api worker
uv python install
uv sync --locked
docker compose --env-file .env up -d --wait db redis
uv run --env-file .env alembic upgrade head
uv run --env-file .env uvicorn app.main:app --reload --host 127.0.0.1
```

In a second terminal, from the project folder:

```bash
uv run --env-file .env python -m app.jobs.worker
```

These commands use the same `.env` configuration as the container setup. Keep the worker running to process jobs and scheduled retries. Restart it
after changing worker code. Ctrl+C requests a graceful stop; an active job may
finish before the worker exits. Apply `alembic upgrade head` after schema changes.

## Try the scan API

The easiest way to try it is through <http://127.0.0.1:8000/docs>. Expand an
endpoint, click **Try it out**, fill in the request, and click **Execute**.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Check that the API responds |
| POST | `/api/v1/scans` | Queue a real image scan |
| GET | `/api/v1/scans` | Browse scan history, newest submissions first |
| GET | `/api/v1/scans/{scan_id}` | Retrieve one scan |
| GET | `/api/v1/scans/{scan_id}/findings` | Browse or filter saved findings |

Submit this JSON to `POST /api/v1/scans`:

```json
{"image_reference": "docker.io/library/alpine:3.20"}
```

The API saves a queued attempt, submits its ID to Redis, and returns
`202 Accepted` with `scan_id`, `status: queued`, and `status_url`. Copy the ID
into the retrieval endpoint to follow its progress. A worker may already have
started by the time you make that GET request.

The usual sequence is `queued` → `running` → `completed` or `failed`. A retryable
failure can return it to `queued` before another attempt. If no worker is running,
the scan waits in the queue. The first scan can take longer while Trivy downloads
its vulnerability database.

Open the findings endpoint after completion. New scans return `mock: false`,
including empty pages. Missing fixes appear as `fixed_version: null`. Try
`docker.io/library/alpine:3.20.0` for the image that produced findings in our
local demonstration; counts can change as the scanner database updates.

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
findings. An empty filtered page can mean there are no findings at that severity.
Check the scan status to distinguish a pending or failed attempt from a completed one.

## Direct scans for debugging

Normal submissions use the API and worker described above. This development
command runs a scan directly, bypassing Redis and background retries. It is
useful for inspecting the stored image identity and scanner metadata. Start
PostgreSQL and apply migrations first, then run it from the project folder:

```bash
uv run --env-file .env python - docker.io/library/alpine:3.20.0 <<'PY'
import json
import sys

from sqlalchemy.orm import Session

from app.api.schemas import ScanSubmission
from app.persistence.database import get_engine
from app.persistence.models import Image, Scan
from app.persistence.repository import get_scan_findings
from app.scanning.workflow import perform_trivy_scan

engine = get_engine()
with Session(engine) as session:
    scan_id = perform_trivy_scan(
        session, ScanSubmission(image_reference=sys.argv[1])
    )

with Session(engine) as session:
    scan = session.get(Scan, scan_id)
    image = session.get(Image, scan.image_id) if scan.image_id else None
    page = get_scan_findings(session, scan_id, limit=5, offset=0)
    print("Scan ID:", scan_id)
    print("Status:", scan.status)
    print("Digest:", image.digest if image else None)
    print("Platform:", image.platform if image else None)
    print("Trivy version:", scan.scanner_version)
    print("Database metadata:", json.dumps(scan.scanner_database_metadata))
    print("Findings:", page.total)
    print("Error:", scan.error_details)
    for finding in page.items:
        print(finding.vulnerability_id, finding.package_name, finding.severity.value)
    raise SystemExit(1 if scan.status == "failed" else 0)
PY
```

The first scan can take longer while Trivy downloads its vulnerability database.
Submitted images are inspected remotely, without running them or accessing
Docker's socket. This direct helper requires Trivy installed on the host.

Copy the printed scan ID into the GET endpoints in the API docs. Real findings
return `mock: false`, even for empty pages. The scan endpoint shows the submitted
reference and status; the command also prints stored identity, metadata, and errors.

For a missing-image demonstration, rerun the command with an intentionally absent
tag such as `docker.io/library/alpine:containerguard-missing-example`. Expect a
saved `failed` attempt, a safe `resolution_failed` message, no image association,
and exit code 1. This differs from a completed scan with zero findings.

### Current scanner limits

The workflow accepts explicit public Docker Hub tags and selects one unambiguous
`linux/amd64` image from an OCI index or Docker manifest list. Private registries,
GHCR resolution, direct single-image manifests, nested indexes, and explicit CPU
variants are not supported. The low-level runner accepts pinned Docker Hub and
GHCR references; the full workflow currently resolves Docker Hub tags only.

Scanner execution defaults to five minutes, 10 MiB of JSON output, and 64 KiB of
diagnostic output. Direct runner callers can change its timeout and output limit.
Registry operations use timeouts and bounded responses. Raw diagnostic text is
not saved as failure details.

Database metadata is an optional snapshot of Trivy's local cache after scanning:
its format version and available update/download timestamps. Missing or unusable
metadata stays null. It is not an immutable database identifier, particularly if
another process changes the shared cache. Zero findings is not proof of security;
unsupported distributions can have incomplete vulnerability coverage.

### Verified demonstrations

Local scans with Trivy 0.75.0 and `linux/amd64` produced these results:

| Case | Observed result | Manifest digest |
| --- | --- | --- |
| `alpine:3.20` | Completed with zero findings; retrieved through the API | `sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e` |
| `alpine:3.20.0` | Completed with 70 persisted findings | `sha256:216266c86fc4dcef5619930bd394245824c2af52fd21ba7c6fa0e618657d4c3b` |
| Randomly generated absent Alpine tag | Saved failure with `resolution_failed` | No resolved image |

The zero-finding case was checked on October 6, 2026. Findings, failure, and
persisted database metadata were checked on October 7, 2026. Alpine 3.20 also
produced an end-of-support warning. Counts may change as scanner databases update;
routine tests use fixtures rather than asserting live counts. The
[scanning notes](docs/architecture/scanning.md) explain the storage decisions.

## API validation and errors

For POST, image references must be strings with 1–512 characters after trimming surrounding
whitespace. This is basic input validation; it does not yet validate the full
container reference syntax or check that an image exists.

Invalid request fields, UUIDs, pagination values, and severity filters return
`422` with validation details. An unknown scan UUID returns `404` with
`{"detail": "Scan not found"}`. Both error types use a top-level `detail` field.

Database operation failures return `503` with
`{"detail": "Database temporarily unavailable"}`. Responses exclude raw SQL and
connection details. A failed database write rolls back its transaction. Redis submission failures
return `503` with `{"detail": "Scan queue temporarily unavailable"}`. If PostgreSQL
is reachable, that queued attempt is marked failed with `enqueue_failed`.

A scan accepted with 202 can still fail later in the worker. Read its status and
safe `error_details`; acceptance does not mean the image has been scanned.

### Saved history and restarts

Submit a scan and keep its ID. Retrieve the scan and findings, then recreate the
application containers without deleting their volumes:

```bash
docker compose --env-file .env up -d --force-recreate api worker
```

Both GET endpoints should still return the saved data. For host-based development,
stop and restart the API process instead. You can also restart PostgreSQL:

```bash
docker compose --env-file .env restart db
docker compose --env-file .env up -d --wait db
```

Repeat both GET requests with the same ID. This was checked locally: the scan and
its findings remained available after both application and database restarts.
The development database stores its files in the Compose-managed `postgres_data`
named volume. Stopping or removing its container keeps that volume:

```bash
docker compose --env-file .env --profile test down
```

**To deliberately delete all local development scan history**, remove the volume:

```bash
docker compose --env-file .env --profile test down --volumes
```

This reset also removes queued work and the Trivy cache. Start the stack again
with `up -d --build`; the migration service recreates the schema. The test database
uses temporary storage and loses its contents when its container stops.

The health endpoint checks only that the API process responds. It does not check
PostgreSQL, Redis, or a worker, so it can return 200 while submissions fail or
scans wait in the queue.

## Queue storage and retries

A local Redis service is available in Compose. Start it and check its connection:

```bash
docker compose --env-file .env up -d --wait redis
docker compose --env-file .env exec redis redis-cli ping
```

The connection check should return `PONG`. Redis listens on localhost port 6380
on the host and port 6379 inside its container. Set REDIS_PORT and the port in
REDIS_URL together if you need a different host port.

Redis keeps its active data in memory and writes an append-only log to the
`redis_data` named volume, with disk synchronization every second. Restarting or
recreating the container keeps that volume. `down --volumes` removes both Redis
queue data and PostgreSQL scan history. PostgreSQL remains the source of saved
scan results.

The worker allows two retries after the first attempt, with delays of 5 and
15 seconds. Temporary registry unavailability, rate limits, and scanner timeouts
qualify. Invalid references, malformed reports, and other classified permanent
failures are saved as failed without repeating the scan.

The worker runs RQ's scheduler for delayed retries. Its optional `--burst` mode
exits when the queue is empty and does not wait for future retries; use the
normal long-running command for the application.

PostgreSQL and Redis do not share a transaction. A crash between their writes can
leave a queued scan without a job, and an interrupted worker can leave a running
scan. Redis's once-per-second disk synchronization can also lose recent queue
writes during a hard crash. There is no automatic reconciliation yet.

### Recover an interrupted scan

Stop **all** scan workers and confirm their job children and scanner subprocesses
have stopped. Keep them stopped throughout recovery, and run one recovery
command at a time. Inspect the scan ID first: recovery accepts only queued or
running Trivy attempts with no saved image or findings.

For the container setup:

```bash
docker compose --env-file .env stop worker
docker compose --env-file .env ps -a worker
docker compose --env-file .env run --rm --no-deps worker \
  python -m app.jobs.recovery SCAN_UUID --workers-stopped
```

The normal worker must show as stopped before recovery. Stop any host workers
or other worker containers too. The one-off recovery container uses the worker
image and configuration; `--no-deps` prevents it from starting dependencies.
Only after recovery succeeds, start the normal worker:

```bash
docker compose --env-file .env start worker
```

For a host-based worker, stop its processes and use:

```bash
uv run --env-file .env python -m app.jobs.recovery SCAN_UUID --workers-stopped
```

Replace SCAN_UUID with the existing ID. The command resets the attempt to queued,
removes a matching old RQ job and its execution metadata, and submits a new job
with the same ID and a fresh retry budget. Then restart the worker and
retrieve that same ID through the API. Completed and failed scans are refused.

Recovery also refuses while Redis still lists a scan worker. A crashed worker
can leave a registration until it expires; absence of a registration does not
prove its processes have stopped. If recovery loses contact with a service,
inspect the scan and rerun the command with workers still stopped.

We verified a submission waiting while the worker was stopped, then completing
with real findings after restart. We also recovered a deliberately created
running record with no active scanner. That second exercise simulated an
interruption; it did not kill a live scan. See the
[background job notes](docs/architecture/jobs.md) for failure windows and guards.

## Container logs and troubleshooting

```bash
docker compose --env-file .env ps -a
docker compose --env-file .env logs --tail=40 api worker migrate
docker compose --env-file .env logs -f worker
```

`--tail=40` shows the last 40 lines per service and exits. `-f` follows new output;
Ctrl+C stops the log viewer without stopping the worker. Application events are
JSON with time, level, logger, and message. Scan/job events include `scan_id` and
`job_id` where available, so the same UUID connects submission with execution.
RQ and Uvicorn access logs retain their native formats. `job_finished` means the
job function returned; check the saved scan status for its actual outcome.

- **API or worker never starts:** check `db`, `redis`, and `migrate` status and
  logs. `migrate` must exit successfully. An exited migration container is normal.
- **Scans stay queued:** check the worker is running and healthy. `/health` only
  checks the API process; it does not verify Redis, PostgreSQL, or worker readiness.
- **First scan is slow:** Trivy may be downloading its database. Worker logs
  show lifecycle events, but scanner download progress is captured internally
  and is not streamed into those logs. Recreating the worker retains its cache;
  future updates still need downloads.
- **A scan stays running after an interruption:** inspect it and follow manual
  recovery above. Restarting a container does not automatically repair the row.
- **Worker refuses to restart after a forced stop:** the fixed worker name can
  still be registered in Redis. Confirm the old container and its processes are
  stopped, allow the registration to expire, then start the worker again. Do not
  delete registrations while a worker might still be alive.
- **Cache permission errors:** stop all workers, then repair only the cache
  directory ownership using the worker image:

  ```bash
  docker compose --env-file .env stop worker
  docker compose --env-file .env run --rm --no-deps --user 0 worker \
    chown -R 10001:10001 /var/cache/trivy
  docker compose --env-file .env start worker
  ```

  The repair command runs as root once; normal worker execution remains non-root.
  It preserves cached data rather than deleting the volume.

Compose gives the worker up to 650 seconds to stop gracefully, longer than its
600-second job timeout. Wait for stop to finish before recovery. A forced stop or
Docker engine crash can interrupt work and leave stale registrations. Do not
start workers during recovery; there is no automatic recovery or exactly-once
guarantee.

Image builds, cached layers, PostgreSQL data, and Trivy's database all consume
Docker disk space. Trivy also needs temporary space and memory for image contents.
The initial database download in the host demonstration was about 119 MiB; that
is not a bound on cache size or total storage. This is a local development setup,
and no universal RAM/disk minimum or production capacity has been established.
A disposable fresh-volume run on Docker configured with 10 CPUs and
7.75 GiB of memory completed its first scan in about 57.3 seconds,
including the database download. This is one observed run, not a sizing target.

Container checks verified a real scan, retained findings after application
container replacement, queued work completing after worker restart, recovery
of a simulated interrupted scan, and completion of an active scan before a
graceful worker stop returned. A separate fresh-volume stack also verified
busy-worker health, one-off recovery,
retry/scheduling fixtures in the worker image, migration reruns, and retained data
and cache after restarts. The recovery exercises did not kill a live scan.
The [container notes](docs/architecture/containers.md) describe the runtime layout
and remaining verification limits.

## Run the checks

From the project folder:

```bash
docker compose --env-file .env --profile test up -d --wait test-db test-redis
uv run --locked --env-file .env pytest
uv run --locked ruff check .
uv run --locked ruff format --check .
```

Tests cover the API, registry responses, bounded subprocesses, Trivy parsing,
optional database metadata, migrations, transactional writes, and safe failures.
Routine checks use fixtures and local stand-in executables; they do not need
Trivy installed or public registry access. TEST_REDIS_URL must point to a
dedicated Redis test service. TEST_DATABASE_URL must point to containerguard_test;
the harness rejects a target matching development before cleanup. Test configuration rejects URL query options that could override the
validated target and confirms the connected database name before schema changes.
Tests create disposable schemas inside that database, apply migrations,
and override API sessions to use the isolated storage. They do not clear your
development history. Some tests use real commits and new sessions to verify data.
Redis tests use disposable queue names and remove only their own jobs; they
never flush the Redis database. Test configuration rejects using the development
Redis server, even with a different logical database number. No separate test
migration command is needed locally.

To apply formatting changes, run `uv run ruff format .`, then repeat the checks.

GitHub Actions starts separate PostgreSQL services and test Redis, applies
migrations, and runs the checks on pushes to `main` and on pull requests.
In an earlier CI exercise, I deliberately changed the health response on a test
branch, watched the pull request's test fail, and restored the response to get a passing run.
That exercise is recorded in [PR #1](https://github.com/christophervalle85/ContainerGuard/pull/1).

## Where things live

- `app/main.py`: the FastAPI application and API routes.
- `app/api/schemas.py`: request and response models, scan states, and severities.
- `app/persistence/database.py`: database engine and request session lifecycle.
- `app/persistence/models.py`: Image, Scan, and Finding database models.
- `app/persistence/repository.py`: database writes, reads, filtering, and pagination.
- `app/registries/`: Docker Hub requests and image digest resolution.
- `app/scanning/trivy/`: Trivy execution, output limits, and report parsing.
- `app/scanning/workflow.py`: coordinates real scans and saves their outcomes.
- `app/jobs/`: Redis connections, submission, worker entry point, and manual recovery.
- `migrations/` and `alembic.ini`: database schema migrations.
- `Dockerfile.api` and `Dockerfile.worker`: separate non-root runtime images.
- `compose.yaml`: API, worker, migration, database, Redis, and isolated test services.
- `app/logging_config.py`: correlated JSON application logs.
- `docs/architecture/containers.md`: container runtime and operational decisions.
- `docs/architecture/persistence.md`: storage design and decisions.
- `docs/architecture/scanning.md`: scanning decisions, current limits, and live test notes.
- `docs/architecture/jobs.md`: queue lifecycle, retries, and recovery decisions.
- `app/scanning/mock_scanner.py`: fictional findings retained for legacy records and tests.
- `tests/`: unit tests and isolated PostgreSQL/Redis integration tests.
- `pyproject.toml`: dependencies and settings for pytest and Ruff.
- `uv.lock`: exact dependency versions used to recreate the environment.
- `.python-version`: the project's Python version.
- `.github/workflows/ci.yml`: the automated GitHub checks.
- `.env.example`: local demonstration database and queue configuration.

Commit the lockfile. Keep `.venv`, caches, and real credentials out of Git.
uv recreates the local environment from the committed dependency files.

## Next steps

The backend runs through Compose. Policy evaluation and a dashboard are still
ahead; interrupted-job reconciliation and deployment hardening remain future work.
