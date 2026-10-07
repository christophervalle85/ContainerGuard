# Persistence architecture

Status: implemented. Real scan integration is described in [image scanning](scanning.md).

## Scope

Replace process-local dictionaries with durable scan history while preserving
the existing API response shapes. POST now creates queued Trivy attempts;
workers save real findings. See [image scanning](scanning.md) and
[background jobs](jobs.md).

## Architecture

FastAPI routes use a request-scoped synchronous SQLAlchemy session and a small
repository module for queries. PostgreSQL stores records. Alembic owns schema
changes. Docker Compose runs PostgreSQL and Redis; the API and worker run
locally through uv. Full backend containerization is outside this change.

Local development and CI use PostgreSQL 17, SQLAlchemy with Psycopg, and Alembic.
Python dependencies are locked in uv.lock. Integration tests use PostgreSQL.

## Tables and relationships

### Image

UUID primary key, registry, repository, resolved digest, and platform. These
identity fields are non-null. A unique constraint covers their combined identity.
Multiple scan attempts may reference the same image. Mock submission does not
create an Image row or fabricate a digest.

### Scan

UUID primary key, submitted image reference, nullable Image foreign key, status,
UTC creation/start/completion timestamps, nullable scanner name/version and
available database metadata, and nullable safe error details. Keep failed or
unresolved attempts even when no image identity exists. Enforce the four status
values in storage: queued, running, completed, failed.

Mock scans complete immediately, without claiming a real scanner ran. Store
creation/completion times; image association and real scanner metadata stay null.
History orders by creation time descending with a stable UUID tie-breaker. Index
history ordering and the image foreign key.

### Finding

UUID primary key and non-null Scan foreign key, vulnerability ID, package name,
package type, target/path, installed version, nullable fixed version, severity,
and title. Index the scan association and scan/severity lookup. Preserve UNKNOWN
severity and null fixed versions.

A finding identifies an occurrence, not just a CVE. Within one scan, enforce
uniqueness across vulnerability ID, package name/type, target/path, and installed
version. Occurrence-key fields are non-null; mock package type/target values are
explicitly fictional. The same vulnerability may appear for multiple packages
or targets. Deleting a scan may cascade its findings; deleting a referenced
image is restricted so historical scan associations are not silently lost.

## Writes, reads, and errors

Generate the scan UUID and commit a queued Trivy record before submitting its
ID to Redis. The worker claims the row in a short transaction and performs
external work after committing. Completion associates the image, inserts
findings, and marks the scan completed atomically. A failed completion rolls
back before a separate failure transaction. No partially populated scan is
reported as completed. Redis submission and PostgreSQL writes are separate;
manual recovery handles interrupted queued or running attempts.

Get/list operations query PostgreSQL. Apply severity filtering, ordering,
counts, limit, and offset in SQL rather than loading all records into Python.
Keep findings order stable with an explicit internal occurrence-order field;
this preserves the existing mock ordering. Unknown scan IDs still return the
documented 404. Invalid inputs still return 422. Database failures return a safe
503 response without connection strings or raw SQL errors; document this in
OpenAPI and test that failed writes are not accepted.

Use explicit conversion from database records to existing response models.
Expose mock: true for mock scans and mock: false for Trivy attempts, including
empty finding pages.
Routes use the repository directly; no process-local scan store remains.

## Configuration and local development

Read DATABASE_URL from configuration. Document local demonstration credentials
in .env.example; real .env files remain ignored. Never log the database URL.
Bind the development database port to localhost, use a named data volume, and
add a PostgreSQL health check. Document the port and how to change it if occupied.

Run Alembic upgrades as an explicit step before starting the API. Do not call
metadata.create_all at application startup or let every request run migrations.
Explain that container restart preserves the volume, while removing volumes
intentionally deletes data. Database setup instructions must not require a
privileged Docker socket inside the application.

## Test isolation and CI

Use a dedicated PostgreSQL test service/container and a separately configured
TEST_DATABASE_URL. The test harness must reject a test target that matches the
development target and require the dedicated test database name before cleanup.
Only clean the verified test database. Never truncate or drop development tables.

Run Alembic from an empty test database to verify migrations. Isolate API tests
through a test-session dependency override and database cleanup between tests.
Keep transaction rollback tests independent of test harness rollback behavior.
Prove committed records are visible through a new session. Add relationship,
occurrence uniqueness, repeated CVE, UNKNOWN, null fixed-version, and unresolved
failed-scan cases. Exercise safe database-unavailable behavior.

CI starts PostgreSQL services and isolated test Redis, waits for readiness, runs
migrations, then runs
the API/database suite plus existing lint/format checks. No live registry access
is needed. The health-only endpoint remains a process liveness check.

## Verification

- Migrations create the schema from an empty PostgreSQL database.
- Existing API behavior works through PostgreSQL with isolated tests in CI.
- Scan and findings insertion is atomic; storage constraints are verified.
- A failed unresolved attempt can be stored without an Image row.
- Submit through the API, restart the API, and retrieve the same ID and findings.
- Restart the PostgreSQL container without deleting its volume and retrieve again.
- README covers configuration, migrations, test setup, restart/reset semantics,
  and background job configuration.

## Deferred work

Full backend containerization, accounts, policies, the
dashboard, and cloud deployment remain future work. Digest resolution and real
scanner execution are covered in [image scanning](scanning.md).
