# Backend Containers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for the agreed inline, guided implementation. Steps use checkbox syntax for tracking. Preserve learner checkpoints; do not implement the entire plan in one turn.

**Goal:** Run the API, real scanning worker, migrations, PostgreSQL, and Redis through Compose with reproducible builds and retained data.

**Architecture:** Separate API and worker images contain the same locked Python runtime dependencies; only the worker contains Trivy. Compose gates application startup on healthy dependencies and successful migrations. Named volumes preserve database, queue, and scanner cache data.

**Tech Stack:** Python 3.14, uv, FastAPI/Uvicorn, PostgreSQL 17, Redis 8.2, RQ, Alembic, Trivy 0.75.0, Docker Compose.

**Spec:** [Backend containers](../architecture/containers.md).

## Global constraints

- Existing API responses and scan behavior remain the contract.
- Use Dockerfile.api and Dockerfile.worker in the repository root.
- Run the API and worker as a non-root application user with a consistent UID/GID.
- Container clients use db:5432 and redis:6379; host clients retain their current URLs.
- Preserve postgres_data and redis_data; add a writable trivy_cache volume.
- Neither application container mounts Docker's socket.
- The scanner deadline remains 300 seconds and RQ job timeout remains 600 seconds.
- Keep the current two-retry budget and 5/15-second delays.
- Container source and dependencies come from the build, not a host source mount.
- Names in committed documentation stay neutral to branches, milestones, and dates.
- The learner runs the checkpoint commands and reviews their outcomes; commits remain explicit learner checkpoints.

## Review focus

- Apple Silicon build architecture versus scanned linux/amd64 image: native worker binary must run and still scan the selected remote platform (Tasks 2 and 6).
- New versus reused cache ownership: non-root scans must work in both cases without replacing existing data (Tasks 2 and 6).
- A failed or previously completed migration service: fresh migration failure must block startup, and schema upgrades must rerun migrations (Tasks 3 and 6).
- Stale or unrelated RQ workers: a health probe must check its own name and heartbeat, while recovery keeps workers stopped (Tasks 4 and 6).
- Container shutdown during a job: graceful stop must allow completion; forced interruption requires verified process shutdown and guarded recovery (Task 6).

## File map

| File | Responsibility |
| --- | --- |
| Dockerfile.api | Build the non-root API/migration runtime |
| Dockerfile.worker | Build the non-root worker runtime with Trivy |
| .dockerignore | Exclude local credentials, environments, metadata, and caches |
| compose.yaml | Wire application, migration, dependency, and cache services |
| .env.example | Explain host and container URLs and configurable ports |
| app/jobs/worker.py | Stable worker naming and logging setup |
| app/jobs/health.py | Check one worker's registration and heartbeat |
| app/logging_config.py | JSON application logging configuration |
| app/main.py | Apply logging configuration without changing route behavior |
| app/jobs/tasks.py | Correlated job execution logs |
| app/scanning/workflow.py | Correlated retry/outcome logs where needed |
| app/jobs/recovery.py | Apply logging configuration in recovery CLI |
| tests/test_worker_health.py | Probe behavior with fixture Redis/worker data |
| tests/test_logging_config.py | Log format, correlation, and safe exceptions |
| README.md and docs/architecture/*.md | Setup, architecture, recovery, and verification evidence |

## Task 1: API image and build context

**Files:** Create Dockerfile.api and .dockerignore.

**Interfaces:** Consumes pyproject.toml, uv.lock, app/, migrations/, alembic.ini. Produces local image containerguard-api:dev with /app working directory and /app/.venv/bin on PATH. Use UID/GID 10001 for the application user.

- [x] Resolve explicit Python 3.14 slim and uv 0.12.21 image artifacts for the local build platform; record digest references in the Dockerfile. Do not silently change the project's Python minor version or lockfile.
- [x] Create a build context exclusion file covering .git, .venv, .env and .env.*, caches, tests, documentation, and generated reports. The image does not need .env.example; Compose reads environment configuration outside the image.
- [x] Add a multi-stage API Dockerfile installing runtime dependencies with uv sync --locked --no-dev --no-install-project. Copy the environment and application/migration files into the runtime. Use a direct uvicorn command listening on 0.0.0.0:8000, without reload.
- [x] Learner builds: docker build -f Dockerfile.api -t containerguard-api:dev .
- [x] Learner inspects with docker run --rm --entrypoint python containerguard-api:dev -c 'import os, shutil; import app.main; print(os.getuid()); print(shutil.which("trivy"))'. Expected: 10001 and None; importing the app succeeds without service connections.
- [x] Confirm Alembic is available, development tools are absent, and no real environment file is included. These are runtime inspection checks rather than tests that duplicate Dockerfile text.
- [x] Learner checkpoint: explain image layers, build context, non-root identity, and the distinction between image build and service startup. Suggested commit: Add non-root API container image.

## Task 2: Worker image and scanner cache

**Files:** Create Dockerfile.worker; extend .dockerignore only if needed.

**Interfaces:** Produces containerguard-worker:dev, using the same Python/uv artifact versions and UID/GID as Task 1. Default command: python -m app.jobs.worker. Set TRIVY_CACHE_DIR=/var/cache/trivy; create that directory with application-user ownership.

- [x] Resolve the Trivy 0.75.0 image artifact for the native platform and record its digest. Use its binary in the worker runtime; keep the API image unchanged.
- [x] Build the worker from locked runtime dependencies, copying app code and necessary runtime files. Provide CA certificates and verify binary compatibility with the selected Python runtime.
- [x] Learner builds: docker build -f Dockerfile.worker -t containerguard-worker:dev .
- [x] Learner runs the worker image with entrypoint trivy and argument --version. Expected: executable starts and reports 0.75.0.
- [x] Inspect UID 10001 and non-root writes to TRIVY_CACHE_DIR. Repeat using a new disposable named volume, then reuse it to confirm a marker remains readable and writable. Remove only this explicitly disposable volume after the check.
- [x] Confirm no Docker socket is needed. Explain that the application container's CPU architecture and the scanned image's platform are different choices.
- [x] Learner checkpoint. Suggested commit: Add worker image with pinned Trivy runtime.

## Task 3: Compose application startup and migration gate

**Files:** Modify compose.yaml and .env.example.

**Interfaces:** Add api, worker, and migrate services. Runtime DATABASE_URL and REDIS_URL use explicit CONTAINER_DATABASE_URL and CONTAINER_REDIS_URL configuration. API_PORT defaults to 8000. Keep existing host URLs and test services.

- [x] Add the image builds and explicit environment mappings. API and worker depend on healthy db/redis and successful migrate completion; migrate depends on healthy db and uses the API image with alembic upgrade head.
- [x] Publish API at 127.0.0.1:${API_PORT:-8000}:8000. Add init: true to application containers, worker stop_grace_period: 650s, and the trivy_cache mount. Do not add automatic worker restart during manual recovery.
- [x] Add the API health check using Python's standard library to request http://127.0.0.1:8000/health with a bounded timeout. Keep its liveness meaning unchanged.
- [x] Document the first-run .env copy and container URL fields. Keep custom credentials consistent; explain URL encoding. Do not overwrite an existing .env automatically.
- [x] Validate with docker compose --env-file .env.example config --quiet. Inspect rendered service names, internal hosts, dependencies, localhost publishing, and volume reuse.
- [x] Ask the learner to stop host API/worker processes before launching container equivalents. Run docker compose --env-file .env.example up --build and inspect service state and health.
- [x] Confirm migration exited successfully and /health returns status ok. Verify database connection uses the existing development database without clearing history.
- [x] In a disposable Compose project with separate volumes and nonconflicting ports, force migrate to exit unsuccessfully and confirm API/worker do not start. Never test this by breaking the development schema. Clean up only the disposable project.
- [x] Document upgrade command sequence: build images, stop application services, run migrate with docker compose run --rm --no-deps migrate after db is healthy, then recreate API and worker. Verify an already completed migration container does not skip that explicit upgrade.
- [x] Learner checkpoint. Suggested commit: Run backend services and migrations through Compose. Commit remains learner-controlled.

## Task 4: Worker health and correlated logs

**Files:** Create app/jobs/health.py, app/logging_config.py, tests/test_worker_health.py, tests/test_logging_config.py. Modify worker.py, tasks.py, recovery.py, main.py, workflow.py, and compose.yaml as needed for wiring.

**Interfaces:** worker_is_healthy(connection: Redis, worker_name: str, *, max_heartbeat_age_seconds: int = 120) -> bool. Health CLI reads RQ_WORKER_NAME, uses the configured Redis client, exits 0 for a fresh matching worker and 1 otherwise. Production Compose supplies a stable unique name for its single worker. JsonFormatter.format(record: logging.LogRecord) -> str and configure_logging() -> None provide JSON application logs.

- [x] Write health tests for missing/blank name, missing worker, stale heartbeat, fresh idle worker, fresh busy worker, unrelated fresh worker, and unavailable Redis. Use existing dedicated test Redis and disposable names; never count any worker as evidence this worker is healthy.
- [x] Run the new tests and confirm failures occur because the probe is missing. Implement the smallest probe using installed RQ interfaces and timezone-aware heartbeat comparisons. Check RQ's busy-job heartbeat interval against the threshold before wiring the production probe.
- [x] Pass RQ_WORKER_NAME to SpawnWorker and add the Compose worker health check. Re-run tests and verify live idle and active-job health. Document a fresh registration as health evidence, not proof a scan will succeed.
- [x] Write logging tests asserting valid JSON, time/level/logger/message, scan_id/job_id when supplied, no duplicated handlers on repeat configuration, and no raw exception details in public-safe application records.
- [x] Implement formatting/configuration and wire the API and worker entry points. Add scan/job execution and retry/outcome context without serializing submission bodies, URLs, or scanner diagnostics. Keep third-party/access-log formats explicitly outside the JSON guarantee.
- [x] Run focused tests, Ruff, and the existing isolated suite. Inspect application logs from a real submission later in Task 6.
- [x] Learner checkpoint. Suggested commit: Add worker health checks and correlated application logs. Commit remains learner-controlled.

## Task 5: Container recovery instructions

**Files:** Update docs/architecture/jobs.md and README.md; adjust recovery CLI only if container execution exposes a real incompatibility.

**Interfaces:** Run existing app.jobs.recovery from a one-off worker-image container with the same network/environment. Keep worker stopped and use --no-deps so recovery does not start it.

- [x] Document docker compose stop worker and confirmation that worker/job/scanner processes are gone. Explain graceful versus forced shutdown and stale Redis registrations.
- [x] Document docker compose run --rm --no-deps worker python -m app.jobs.recovery SCAN_UUID --workers-stopped, followed by explicit worker restart only after successful recovery.
- [x] Explain refusals for terminal scans, saved results, mismatched jobs, or registered workers. Preserve the serial-operator requirement and the rerun procedure after a cross-service failure.
- [x] Validate the command's help and refusal behavior using disposable state before the learner recovers a controlled running record in Task 6.
- [x] Learner checkpoint. Suggested commit: Document recovery through the worker container. Commit remains learner-controlled.

## Task 6: Runtime verification and final documentation

**Files:** Update README.md, docs/architecture/containers.md, docs/architecture/scanning.md, and docs/architecture/jobs.md. Add focused regression tests only for behavior gaps found during verification.

**Interfaces:** Same public API and scan IDs as before packaging; no release publishing or new policies.

- [x] Run the full locked Ruff and isolated pytest checks with test-db and test-redis. Address failures before proceeding.
- [x] Submit a real public Docker Hub image through the containerized API, follow the same ID to completion, and retrieve mock: false findings. Record the resolved digest/platform, scanner version, available DB metadata, date, and observed finding count without asserting that live counts are fixed.
- [x] Stop the worker, submit a scan, confirm queued status and API liveness, then start the worker and verify completion under the same ID.
- [x] Exercise the retry budget/scheduling tests inside the worker runtime using a disposable test invocation that supplies the locked dev dependencies without adding them to the shipped image. Fixture-based scanner failures must produce at most three attempts with scheduled retry times; do not rely on network outages. Reuse the existing integration tests and isolated services.
- [x] Create a controlled running record with no live scanner, recover it through the one-off container command, restart the worker, and retrieve completion. Label the exercise simulated interruption.
- [x] Submit a scan and request a graceful worker stop while active. Confirm the scan finishes before worker exit; inspect process cleanup. If forced-stop behavior is also tested, use disposable state and explicitly verify no child scanner remains before recovery.
- [x] Restart and recreate services without removing volumes; retrieve a prior scan and confirm cached Trivy data remains writable and reusable. Test fresh cache ownership separately with disposable volumes.
- [x] Exercise setup in a disposable project from clean volumes, including migration order. Record build/download duration and observed Docker resource settings; describe requirements as observations rather than universal minima.
- [x] Update setup, migration upgrades, first-run download expectations, logs, resource guidance, and reset instructions. Mark the architecture design implemented only after these checks pass.
- [x] Review the complete branch independently using the code-review skill, resolve important findings, and rerun affected checks.
- [ ] Learner commits/pushes; create a PR when requested and verify CI before merge.

## Current verification notes

The locked suite passes with 398 tests; Ruff lint/format, Compose configuration,
and whitespace checks pass. Independent implementation review found no important
code defects. The one-off worker recovery command displays help and refuses
recovery while a normal worker remains registered, without changing a scan.

The learner confirmed 70 saved findings after application container replacement,
queue processing after worker restart, and simulated interrupted-scan recovery
for `cca9a898-6fc6-4e0e-acb9-3d9b93189963` to completed with mock: false. That
learner recovery used `exec api`; a later disposable-stack exercise also verified
the documented one-off worker entry point. Runtime checks are now complete;
commit, push, PR, and CI remain. A simulated interruption still does not stand
in for a forced-crash demonstration.

Documentation review caught and corrected two issues: operational commands now
consistently use the configured `.env`, and troubleshooting explains that Trivy
stderr/download progress is captured internally rather than streamed into worker
logs. Application lifecycle events remain available in those logs.

The learner requested graceful shutdown while scan
`6d4918cf-4c02-4713-a092-52fcd38c775a` was running. Compose reported the worker
stopped after 1.6 seconds, and retrieval after stop returned completed. The
container stop establishes that the worker container is no longer executing;
this was a normal shutdown, not a forced-crash test.

Final isolated verification passed: fresh-volume real scan, busy-worker health,
one-off simulated recovery, explicit migration rerun, 50 worker-image fixture
tests, dependency restart/application replacement with retained findings/cache,
and scoped cleanup. The full host suite passed 398 tests with no internal
logging errors; both image builds, Ruff, Compose, and whitespace checks passed.
Operational evidence is recorded in the architecture notes. Commit, push, PR,
and CI remain the next learner checkpoint.
