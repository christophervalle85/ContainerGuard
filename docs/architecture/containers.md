# Backend containers

The backend runs through Docker Compose. API responses, scan IDs, retry policy,
and persistence behavior are the same as in host-based development.

## Runtime layout

| Service | Runtime | Responsibility |
| --- | --- | --- |
| `api` | API image | Serve FastAPI requests and submit background jobs |
| `worker` | Worker image | Run RQ jobs, resolve image tags, and execute Trivy |
| `migrate` | API image | Apply Alembic migrations, then exit |
| `db` | PostgreSQL 17 | Store image identities, scans, and findings |
| `redis` | Redis 8.2 | Coordinate queued work and scheduled retries |

The separate worker image contains Trivy; the API image does not. Both contain
Python 3.14.7 and the same locked runtime dependencies. Multi-stage builds use
uv 0.12.21 with `uv sync --locked --no-dev --no-install-project`. Python, uv, and
Trivy image artifacts are pinned by digest in the Dockerfiles. PostgreSQL and
Redis use the release tags in Compose; those tags are not immutable digests.

The build context allows only runtime inputs and build definitions. Git metadata,
real environment files, tests, documentation, reports, and host virtual
environments are excluded. Runtime images have no development tools or uv.
Source is copied during the build rather than mounted from the host.

Both application images run as UID/GID 10001. Source and dependencies remain
root-owned and readable by the application user. The worker owns its cache
mount point at `/var/cache/trivy`; its normal execution does not require root.
The Debian runtime provides trusted certificates for HTTPS requests.

Images build natively on the developer's architecture. Trivy still examines the
resolved remote `linux/amd64` image; the worker itself need not run under amd64
emulation. Neither application container mounts Docker's socket, and submitted
images are inspected without running them.

## Configuration and startup

Host-based commands use `DATABASE_URL` and `REDIS_URL` with published localhost
ports. Compose maps `CONTAINER_DATABASE_URL` and `CONTAINER_REDIS_URL` to those
runtime settings, using `db:5432` and `redis:6379`. The API binds port 8000 inside
its container and publishes it on localhost through configurable `API_PORT`.

PostgreSQL and Redis must become healthy before the application services start.
The migration service depends on healthy PostgreSQL. API and worker startup also
require migrations to exit successfully; a failed migration blocks them.
An upgrade explicitly reruns the migration command before application recreation,
so an old completed migration container is not used as evidence of a new upgrade.
See the README for the command sequence and configuration details.

Startup gates do not provide ongoing recovery during service outages. The API
health check requests `/health`, which means the API process responds. It does
not establish database, queue, or scanner readiness.

## Worker health and shutdown

The worker probe reads its own RQ registration, state, and heartbeat without
refreshing them. A matching worker must be registered, idle or busy, have no
recorded death, and have a heartbeat within 120 seconds. Missing configuration,
unusable timestamps, and Redis failures make the probe fail.

The configured worker TTL is 90 seconds, giving an idle dequeue wait of 75
seconds. Busy jobs heartbeat every 30 seconds. Both fit inside the probe's
freshness window. The stable name `containerguard-worker` assumes one normal
worker per configured Redis instance. Scaling needs unique names and probes.
A forced stop can leave a registration that temporarily prevents name reuse.

Application containers use an init process and direct process commands. Compose
gives the worker 650 seconds to stop gracefully, longer than its 600-second RQ
job timeout. Trivy retains its separate 300-second execution deadline and output
bounds. A normal stop lets an active job finish; abrupt interruptions can still
leave work needing manual inspection and recovery.

No automatic application restart policy is configured. Operators keep all worker
and scanner processes stopped throughout manual recovery and run recovery
commands serially. The normal entry point is a one-off worker-image container
with `--no-deps`; it does not start the normal worker. Existing guards against
active registrations, terminal scans, saved results, and mismatched jobs remain
in place. Container packaging adds no automatic reconciliation or exactly-once
guarantee. See [background jobs](jobs.md) for failure windows.

## Storage and logs

The existing `postgres_data` and `redis_data` volumes retain their names and
contents. `trivy_cache` stores the scanner database separately from host caches.
Fresh volumes inherit the cache directory ownership needed by the non-root
worker. The README includes a narrowly scoped ownership repair for existing
cache volumes with incorrect permissions.

Ordinary restarts and application container replacement preserve named volumes.
`down --volumes` deliberately deletes scan history, queued work, and the scanner
cache. A reused cache avoids repeated initial downloads; updates still need
network access. Cache metadata is a post-scan observation, not an immutable
database identity.

Application logs go to stdout as JSON with UTC time, level, logger, and message.
Scan/job events add correlation IDs and safe classified error codes where
available. Raw scanner diagnostics, connection URLs, and arbitrary exception
attributes are not appended by the formatter. Calls must still use safe event
messages; the formatter is not a general-purpose secret redactor.

Spawned job processes configure their own logging. Lifecycle events are emitted
around committed scan state changes. `job_finished` means the task returned,
which can include a saved permanent failure; PostgreSQL scan status is the
outcome to inspect. RQ and HTTP access logs retain native formats. Trivy stderr
is captured internally, so database download progress is not streamed into the
worker logs.

## Verification

Both images built on Apple Silicon. Inspection confirmed UID 10001, Trivy 0.75.0
only in the worker, trusted certificates, no development tools, and writable
fresh/reused cache volumes. A disposable migration-failure exercise blocked
application startup without modifying the development database.

The learner verified real findings through the containerized API, persistence
after application container replacement, queued work completing after worker
restart, and manual recovery of a simulated running attempt. A graceful stop
requested during an active scan returned after that scan reached completed.
The simulation did not kill a live scan. Forced-crash recovery and minimum
production capacity are not established by these checks.

A separate Compose project with clean volumes verified startup ordering and a
real Alpine 3.20.0 scan with 70 persisted findings and mock: false.
The actual SpawnWorker reported busy while its health probe passed. One-off
worker-image recovery completed a simulated interrupted scan under the same ID.
Explicitly rerunning migrations succeeded after the original migration service
had completed. Fifty locked retry, recovery, and health fixture tests passed
inside a disposable worker-image container; pytest dependencies were supplied
only to that temporary container, not added to the shipped image.

Restarting the isolated PostgreSQL/Redis services and replacing application
containers preserved the original findings and writable Trivy database cache.
Only the disposable project's containers, network, and volumes were removed.
The development stack and its saved scans were not used for cleanup.

On this run, Docker reported 10 CPUs, 7.75 GiB of memory,
and architecture aarch64. Startup took about 9.0 seconds;
the first scan with an empty cache took about 57.3 seconds, including
the vulnerability database download. A separate cached rebuild of both images
took 1.15 seconds. These are observations, not minimum resource requirements or
cold-build benchmarks. Network and image contents affect time, disk, and memory.
The full host suite passed 398 tests; lint, formatting, Compose validation, and
whitespace checks also passed. Independent review found no important code defects.
