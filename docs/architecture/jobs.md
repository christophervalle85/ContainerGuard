# Background jobs

The API accepts an image reference without waiting for registry resolution or
Trivy. PostgreSQL holds the scan history; Redis and RQ coordinate the work.
The API and worker use the same database and Redis settings.

## Submission and execution

Submission commits a queued Trivy scan, then enqueues `app.jobs.tasks.run_scan`
with the scan UUID as both its argument and job ID. RQ's unique-job option avoids
two Redis jobs with that ID. The API returns 202 after enqueueing, with a queued
snapshot and a URL for checking the current status.

The production worker uses SpawnWorker and runs the scheduler for delayed
retries. Each job opens its own SQLAlchemy session. A short row-lock transaction
claims a queued scan and marks it running before any registry or scanner work.
A delivery for a scan that is already running or terminal does no scan work.

Successful completion saves the image identity, findings, and completed state
in one transaction. Completion and failure writes require a running Trivy row;
they cannot replace a terminal result. New findings pages use `mock: false` in
all lifecycle states, including empty pages. Legacy mock records still work.

Submission and recovery logs include scan and job IDs. RQ reports job execution;
PostgreSQL status and safe error details explain the saved scan outcome.

## Retry policy

Jobs have at most two retries after their initial attempt, delayed by 5 and
15 seconds. Temporary registry unavailability, rate limiting, and scanner
timeouts are classified as retryable. When budget remains, the workflow commits
a return to queued and raises the safe workflow error for RQ to schedule.
The next claim sets a new start time; the scan UUID and creation time stay fixed.
Timestamps describe the latest attempt, not a separate history of every retry.

A classified permanent failure or exhausted retry budget marks the scan failed.
Invalid references, unusable reports, missing executables, and bounded-output
failures do not trigger another scan. An opaque nonzero scanner exit is treated
as permanent because its diagnostic text is not used to guess a network cause.
The direct synchronous development helper does not use background retries.

RQ can retry an unexpected exception too. That does not guarantee another scan:
if the database still says running, the claim guard skips it. Unexpected worker
or persistence failures may therefore need manual inspection and recovery.

The worker must remain running for delayed retries. Burst mode processes waiting
jobs and exits when the queue is empty; it does not wait for future retry times.
The queue's job timeout is 600 seconds; scanner execution normally has a
300-second deadline and separate bounded registry and metadata operations.

## Storage and failure windows

Redis keeps active queue data in memory and writes an append-only log to the
Compose `redis_data` volume, synchronizing once per second. A hard crash can lose
recent writes. PostgreSQL uses its own `postgres_data` volume for scan records.
Neither volume is removed by ordinary container restarts.

There is no transaction shared by PostgreSQL and Redis, no outbox, and no
automatic reconciliation of interrupted work. A crash after committing a queued
record but before enqueueing can leave that record without a job. A lost enqueue
reply can also leave the API uncertain about whether Redis accepted the job.
Known enqueue failures mark a still-queued record failed when PostgreSQL is
reachable; that write does not overwrite a scan a worker has already claimed.

A worker crash can leave a running row. Database failure during completion or
failure recording can also prevent a durable terminal outcome. These cases
require checking the stored scan rather than assuming RQ's job status is enough.
A row claim prevents overlapping duplicate execution in the normal path; it is
not a lease or an exactly-once guarantee across services.

## Manual recovery

Recovery is an operator procedure, not a live-worker repair loop. For the
container setup, stop the normal worker with
`docker compose --env-file .env stop worker` and confirm it is stopped
with `ps -a worker`. Stop host workers and any other worker containers as well.
The graceful stop budget is 650 seconds; do not recover while it is still stopping.

Follow this sequence:

1. Stop every scan worker and confirm job children and scanner subprocesses have
   also stopped. Keep them stopped until recovery finishes.
2. Inspect the existing scan. Only queued or running Trivy attempts without an
   image association or saved findings can be recovered.
3. Run one recovery command at a time:

   ```bash
   docker compose --env-file .env run --rm --no-deps worker \
     python -m app.jobs.recovery SCAN_UUID --workers-stopped
   ```

4. Only after recovery succeeds, run
   `docker compose --env-file .env start worker` and retrieve the same
   scan ID through the API.

The one-off command uses the worker image, network, and configuration without
starting the normal worker. For host development, the equivalent is
`uv run --env-file .env python -m app.jobs.recovery SCAN_UUID --workers-stopped`.
No automatic restart policy is configured for the application services.

The explicit flag confirms the operator has stopped the processes. Recovery
also refuses while Redis lists a scan worker. Registrations can outlive crashed
processes until they expire; their absence is not proof of process shutdown.
There is no distributed guard against another operator or worker starting during
this procedure, which is why workers stay stopped and commands run serially.

An existing RQ job must match the queue, function, UUID argument, and empty keyword
arguments. Recovery locks and resets the scan, deletes the matching job and its
execution metadata, then enqueues the same ID with a fresh retry budget. It
refuses missing scans, terminal outcomes, saved results, and mismatched jobs.
If a service fails between steps, the scan can remain queued without a job.
Inspect it and rerun recovery with workers still stopped.

## Verification

Routine tests use dedicated PostgreSQL and Redis services. Redis queues have
random names; cleanup removes only their jobs and registries, never a whole
Redis database. Configuration rejects development targets before cleanup.
Tests use real RQ jobs for retry budgets, scheduled times, duplicate submission,
and recovery of old execution metadata. Scanner calls use fixtures, so these
checks do not need Trivy installed or public registry access.

Local checks verified a queued API submission while the worker was stopped,
completion after restart, and retrieval of real findings with `mock: false`.
A second exercise deliberately created a running record without an active
scanner, recovered that ID, and completed it through the worker. This simulated
an interruption; it did not terminate a live Trivy process.

The container verification repeated queued-work restart and simulated recovery
with real Trivy findings. The guided recovery was executed inside the running
API container, which has the same recovery code and dependencies. The documented
one-off worker command is the normal operator entry point; its help output and
refusal while a worker remained registered were verified
separately. Successful recovery through that one-off command was then verified
in a disposable stack using a simulated running attempt. Retry budgets and
5/15-second scheduling were also checked by fixtures inside the worker image;
these tests did not create public-network failures.

An active real scan also completed before the learner's graceful worker stop
returned. This establishes the observed normal-stop behavior; it does not add
a guarantee for engine crashes, forced stops, or cross-service write failures.
