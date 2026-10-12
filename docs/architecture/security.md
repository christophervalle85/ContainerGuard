# Security and quality design

Status: implemented and verified locally and in GitHub CI on October 11, 2026,
including controlled red/green workflow runs and a committed clean checkout.
See [verification](../development/verification.md) for evidence and limits;
independent setup by a second developer remains unverified. This document retains
the rationale behind the controls.

## Purpose and scope

ContainerGuard should be a credible local container-security project that another
developer can run and inspect. We will complete the security checks around our
own software, bound scan submissions, and record reproducible evidence of the
browser workflow. The existing PostgreSQL, Redis/RQ, Trivy, and React architecture
stays in place.

The application remains localhost-only. Authentication, protected public access,
cloud infrastructure, image publication, signing, and provenance belong to later
work. This design adds neither automatic interrupted-job reconciliation nor an
exactly-once guarantee.

## Approach

The recommended approach combines blocking CI checks with a small database-backed
admission limit. Reporting-only scans would provide visibility but would not stop
known failures from merging. A Redis reservation counter would require new
reconciliation rules across Redis and PostgreSQL. Counting active PostgreSQL scan
records under a transaction lock uses the existing source of truth and preserves
capacity across retries and worker restarts.

## Security checks in CI

Keep the backend and frontend checks. Add a dependency/secret job and a matrix
build-and-scan job for the API, worker, and frontend runtime images. Build
linux/amd64 images, matching the application's supported scanning platform; do
not publish them. Test-only service images and builder stages are not covered by
the runtime-image gate and must be described as outside that gate's scope.

Use a pinned Trivy CLI to inspect both committed lockfiles, including development
dependencies, and the three built runtime images. Explicitly verify that reports
contain the expected dependency targets; an empty report caused by unsupported
lockfile parsing is an error, not a clean bill of health. Record the scanner
version and available database metadata with the scan reports.

Use a pinned Gitleaks CLI with redaction to scan reachable repository history
through the checked-out commit. Fetch enough history for that stated scope.
Never upload unredacted secret reports. The documented demonstration credentials
are not production secrets; any necessary allowlist must match only the known
example and location, without suppressing general password or token detection.

Actions use immutable commit references and tools use immutable versions with
verified release checksums or image digests. Continue contents: read and disabled
checkout credential persistence. Use pull_request, not pull_request_target, for
untrusted changes; no release credentials or privileged self-hosted runner.
Repository-owned checks remain reviewable code: a contributor can propose changes
to them, so CI does not substitute for review of workflow and exception changes.

### Vulnerability policy

Block HIGH and CRITICAL vulnerabilities in dependency and runtime-image scans,
including findings without a published fix. Report lower and unknown severities
for inspection. Unknown severity is not equivalent to proven safety. This release
policy is separate from the versioned policies that users apply to submitted
images through the application.

First measure the current baseline. Prefer supported dependency/base-image
updates and re-run the existing tests. Do not raise the threshold or silently
ignore unfixed findings merely to obtain green CI. If an exception is necessary,
record the exact vulnerability, package, applicable target, rationale, owner,
review reference, and UTC expiration date (at most 30 days). Match all identifying
fields; an expired or malformed exception fails the gate. Start with no exceptions.

Scan execution and gate evaluation are separate steps. A scan command error,
timeout, missing or malformed report, missing expected target, or failed database
download must fail the job. Only a successful, validated scan can be evaluated
against the threshold and exceptions. Publish validated vulnerability reports
and a readable summary even when the vulnerability gate fails; do not overwrite
a scanner failure with a passing summary. Bound job execution and report retention.

Controlled fixtures exercise the same gate entry point used by CI: clean input
passes; a fabricated HIGH or CRITICAL finding fails; missing/malformed input and
scanner errors fail; expired and mismatched exceptions fail. A controlled
synthetic secret verifies secret detection without committing a real credential.
Prove the workflow goes red for a deliberate failing test and a controlled
vulnerability-gate fixture on a disposable branch, then restore the correct code.
Keep this evidence separate from live vulnerability counts, which change over time.

## Scan admission and resource bounds

### Validate before accepting work

Reuse the existing Docker Hub reference parser at the submission boundary. Accept
explicit public docker.io tag references already supported by the workflow,
including docker.io/alpine:tag shorthand for the library namespace. Reject other
registries, URL schemes, credentials, digest inputs, malformed references, and
missing tags with 422 before creating a scan or touching Redis. This validates
syntax and supported scope; whether a remote image exists is still worker work.

Update browser validation/help and tests to match. The worker retains its own
validation as a second boundary. Preserve remote-only Trivy operation, fixed
registry resolution endpoints, rejected registry redirects, digest pinning,
argument-list subprocess invocation, timeouts, and bounded diagnostic/report bytes.

### Limit outstanding work

Introduce MAX_ACTIVE_SCANS, default 20, validated as an integer from 1 to 1000.
Configure it identically for application entry points that create scans. It is a
local operator setting, not a capacity benchmark.

An active scan is a real Trivy scan whose persisted status is queued or running.
Retry delays and interrupted scans count. Completed and failed scans do not;
mock records do not. Admission obtains a dedicated PostgreSQL transaction advisory
lock, counts active scans, and inserts the new queued scan within that same
transaction. This serializes competing admissions across API processes and avoids
a check-then-insert race. Bound lock acquisition so contention produces a safe
503 rather than an indefinite wait. Every application entry point that creates a
real active scan must use the same admission mechanism; direct workflow helpers
must not become a bypass.

At capacity, return 429 with a safe message and Retry-After: 30; this is a retry
hint, not a promised completion time. Create neither a scan row nor an RQ job for
a capacity rejection. Show a useful browser error without automatically retrying
the POST. Database and Redis unavailability remain safe 503 responses.

Commit the admitted scan before enqueueing, preserving the existing worker's
visibility requirement. A known enqueue failure marks it failed. A crash between
commit and enqueue can leave a queued scan occupying capacity; the existing
manual recovery procedure handles this. This design deliberately avoids releasing
capacity on a timer while an actual scan might still be running. Recovering an
existing active scan does not acquire a second slot.

### Concurrency and containers

The supported Compose setup runs one worker, processing one scan job at a time.
Multiple operator-started workers increase concurrency; this design does not
introduce a distributed execution semaphore. Document that distinction and the
shared-cache implications. Keep the existing job timeout and bounded retries.

Set explicit local Compose CPU, memory, and process limits for application services
and Redis, and a Redis maxmemory limit with noeviction and persistence retained.
Select and document values after measuring the real scan and cold-cache database
download, leaving headroom for worker subprocesses. Verify configured limits are
applied by Docker and scan success under them. These are operational bounds, not
production sizing claims. They do not bound historical PostgreSQL storage growth;
retention and disk quotas remain operator responsibilities.

## Threat model and failure behavior

Treat submitted references, registry responses, scanner output, and browser/API
inputs as untrusted. Assets include saved findings, SBOM bytes, policy/evaluation
history, service credentials, and host resources. Boundaries are browser-to-API,
API-to-PostgreSQL/Redis, and worker-to-registry/Trivy.

Principal risks are resource exhaustion, command/URL injection, malformed reports,
credential disclosure, vulnerable dependencies, and false confidence from an
incomplete scan. Controls include early validation, atomic admission, process and
container limits, pinned identities, safe error mapping, structured logging, and
CI gates. Containers run without Docker's socket; submitted images are inspected,
not executed. Non-root processes and localhost binding remain required.

Review application logs, RQ exception handling, and API validation/error responses
with sentinel credentials. Fixed application event messages alone do not prove
third-party tracebacks are safe. Do not log raw subprocess stderr, connection URLs,
authorization tokens, or unnecessary request bodies. Negative tests must inspect
actual captured logs and returned errors at the relevant boundaries.

Local users and processes can reach these unauthenticated services. Localhost
binding is not authentication. Container isolation is not a complete sandbox;
scanner/base-image vulnerabilities and supply-chain risks remain. Unsupported
operating systems can have incomplete vulnerability coverage. No findings does
not establish that an image is safe. Interrupted jobs can require manual recovery.

## Verification and portfolio evidence

Test simultaneous submissions against the final available slot using separate
PostgreSQL sessions, alongside capacity release on completion/failure, retry slot
retention, invalid configuration, early validation, enqueue failure, and recovery.
Run the complete existing backend/frontend checks after relevant changes.

Exercise a fresh checkout without the development database, Redis, caches, or
untracked files. Use an isolated Compose project with distinct ports and volumes;
never delete existing development volumes. Follow the documented setup, apply
migrations, submit a real scan, inspect findings, download and verify SBOM bytes,
create/version a policy, and view its evaluation. Record prerequisites, commands,
observed results, scanner versions, and date. Stop only resources created by the
verification. If another developer has not tried it, say so explicitly.

Add a concise system diagram, a short demo walkthrough, and screenshots of actual
completed features. Label fixture-based failure demonstrations. Keep the README
focused on setup, use, checks, and links to the detailed architecture/security
notes. Use neutral filenames such as security.md and quality-plan.md; do not
claim planned controls or checklist items are complete before verification.

## Completion criteria

- CI runs the existing tests, frontend checks, three runtime-image builds,
  dependency/secret scans, and blocking vulnerability gates.
- Controlled failures demonstrate that tests, vulnerability gates, and scanner
  infrastructure errors cannot silently pass.
- Validated submissions and atomic active-scan capacity have meaningful integration
  coverage; browser errors explain rejection without duplicate automatic submission.
- Runtime limits are configured and verified with real scans.
- Logs and API errors pass targeted disclosure checks.
- Fresh-checkout verification and a factual demo record exist.
- README and linked documentation explain architecture, setup, security boundaries,
  known limits, and the exact scope of the evidence.

## Tool references

- Trivy vulnerability scanning: https://www.trivy.dev/docs/dev/guide/scanner/vulnerability/
- Trivy Python lockfile coverage: https://www.trivy.dev/docs/latest/guide/coverage/language/python/
- Trivy language coverage: https://trivy.dev/docs/v0.69/guide/coverage/language/
- Trivy configuration and exit behavior: https://www.trivy.dev/docs/dev/guide/configuration/others/
- Gitleaks CLI and redaction: https://github.com/gitleaks/gitleaks

Tool versions, checksums, exact flags, and supported report schemas must be
verified against the pinned releases when preparing the implementation plan.

## Runtime remediation

The Debian runtime baseline failed the unchanged HIGH/CRITICAL threshold. A
Debian 13 trial still had 52 HIGH findings. The selected runtime uses pinned Alpine
Python, removes unused pip and its vendored packages, updates the frontend's
TIFF/zlib packages, and rebuilds Trivy 0.75.0 with Go 1.27.2/x/net 0.60.0. The
patched scanner identifies itself as `0.75.0+cg.1`. No vulnerability exceptions
were added. See [container maintenance](containers.md#resource-bounds-and-scanner-maintenance)
for the downstream build's upkeep and the actual sizing observations.
