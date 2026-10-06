# Persistence implementation plan

Status: implementation, local checks, fresh-environment setup, and code review
complete. Pull request and remote CI verification remain.

Design: [Persistence architecture](../architecture/persistence.md).

## Approach

Keep the existing API compatible while replacing dictionaries with synchronous
SQLAlchemy queries against PostgreSQL. Alembic manages schema changes. Work in
small test-first slices, with prepared infrastructure and learner-written model
and query exercises. No real scanning is introduced here.

## Constraints

- Keep scans, findings, and existing JSON contracts compatible.
- Preserve UNKNOWN severity, nullable fixed versions, and unresolved scans.
- Use a dedicated PostgreSQL test database; never clean development data.
- Commit a submission and its findings atomically before returning 202.
- Keep repository paths neutral; milestone names belong in progress tracking.

## Review focus

- Occupied host ports: support a configurable localhost database port.
- Unsafe test targets: reject development URLs before any cleanup.
- Duplicate vulnerability IDs: allow distinct package/target occurrences.
- Failed submissions: roll back all rows and return a safe documented 503.
- Restarts: preserve data through both application and database restarts.

## 1. Local PostgreSQL

Files: `compose.yaml`, `.env.example`, `README.md`.

- [x] Add PostgreSQL 17 with a named volume, localhost port, and health check.
- [x] Validate using `docker compose --env-file .env.example config --quiet`.
- [x] Start using `docker compose --env-file .env.example up -d --wait db`.
- [x] Query current_database() and current_user through psql; expect
      containerguard and containerguard respectively.
- [x] Document the configuration, occupied-port override, and volume behavior.

## 2. Connection and safe test setup

Files: `app/database.py`, `tests/database_support.py`,
`tests/test_database_config.py`, `tests/test_database_connection.py`,
`pyproject.toml`, `uv.lock`, `compose.yaml`.

- [x] Add and lock SQLAlchemy, Alembic, and a compatible Psycopg driver.
- [x] Write failing configuration tests rejecting a development test target.
- [x] Add engine construction from DATABASE_URL and request-scoped get_session().
- [x] Add a dedicated test database container and TEST_DATABASE_URL guards.
- [x] Verify a real PostgreSQL SELECT 1 through SQLAlchemy and cleanup rejection.

## 3. Schema and migrations

Files: `app/models.py`, `alembic.ini`, `migrations/env.py`,
`migrations/versions/0001_initial_schema.py`, `tests/test_models.py`.

- [x] Write failing integration tests for the three table relationships,
      occurrence uniqueness, repeated CVEs, UNKNOWN severity, null fixed
      versions, failed unresolved scans, and history/finding order.
- [x] Define Image, Scan, Finding using the fields and constraints in the design.
- [x] Create the initial migration with explicit constraints and indexes.
- [x] Apply the initial migration to an empty test schema and verify model parity.
- [x] Run database tests and verify committed rows through a fresh session.

## 4. Persistent API

Files: `app/repository.py`, `app/main.py`, `app/schemas.py`, `tests/test_scans.py`.

- [x] Replace test dictionary cleanup with the isolated database fixture.
- [x] Write failing tests for atomic writes and safe database failure responses.
- [x] Implement create_scan(session, submission), get_scan(session, scan_id),
      get_scan_history(session, limit, offset), and get_scan_findings(session, scan_id,
      severity, limit, offset) returning existing response models.
- [x] Keep count/filter/order/limit/offset work in SQL. Store finding order.
- [x] Inject sessions into routes, document safe 503 responses, and remove
      production dictionary storage once all existing API checks pass.
- [x] Verify full tests, lint, and formatting, including existing 404 schemas.

## 5. CI and restart evidence

Files: `.github/workflows/ci.yml`, `README.md`, `docs/architecture/persistence.md`.

- [x] Add the dedicated PostgreSQL CI service, readiness checks, and migrations.
- [x] Run all tests using the same database engine as development.
- [x] Submit a scan, restart the API, and retrieve its ID and findings.
- [x] Restart the database container without removing its volume; retrieve again.
- [x] Check fresh environment setup and document destructive reset behavior.
      Verified locked installation, Compose configuration, migrations, API reads,
      and the full suite in a temporary copy with a new virtual environment.
      Existing development data was retained; empty-schema migration behavior is
      verified separately by the migration test.
- [ ] Review the branch and open a pull request; merge only after checks pass.
- [ ] Verify the PostgreSQL checks pass on GitHub.
