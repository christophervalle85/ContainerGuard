# Image scanning

ContainerGuard scans image contents with Trivy without running the image.
The synchronous real scanning workflow runs alongside the existing mock API. The
submission endpoint still creates fictional findings until that integration
is ready.

## Image identity

A tag can change, and a tag can point to images for several platforms. We resolve
an explicit Docker Hub tag to the digest of its `linux/amd64` image manifest
before invoking Trivy. The registry helper requests anonymous pull access from
Docker Hub's token service, uses fixed HTTPS endpoints, rejects redirects, and
bounds response sizes. Network operations have configurable timeouts.

The selector accepts OCI indexes and Docker manifest lists. It requires one
matching platform entry and validates the selected manifest type and SHA-256
digest. Missing or ambiguous matches are errors. Nested indexes and explicit
CPU variants are currently unsupported. Single-image manifests and GHCR
resolution still need their own handling; the command builder already accepts
pinned references from Docker Hub and GHCR.

Keep the submitted tag separate from the resolved identity. The original
reference explains what the operator requested; the digest and platform identify
what was scanned.

## Scanner execution and output

The command builder passes individual arguments to Trivy, scans a remote image,
and requests vulnerability findings as JSON. Execution uses no shell, with a
wall-clock deadline and separate limits for JSON output and diagnostic output.
Raw diagnostic text is not included in public error messages.

The parser preserves package type, target, installed version, and vulnerability
ID for each finding occurrence. Missing fixed versions stay null. Missing or
unrecognized severity becomes UNKNOWN. A valid report with no vulnerabilities
produces an empty list. Zero findings does not establish that an image is safe;
in particular, an unsupported distribution may no longer receive useful
vulnerability updates.

The workflow compares the reported digest with the pinned input. Scanner version
comes from the report. After scanning, a bounded `trivy --version --format json`
command reads the available local-cache vulnerability database metadata. The
parser checks executable version against the report and validates the database
format version and available timezone-aware timestamps. Missing or unusable
metadata stays null without failing an otherwise successful scan. This is a
post-scan cache snapshot, not an immutable database identity; another process can
change the shared cache. Image OS metadata is not a substitute.

## Persistence boundary

The workflow first commits a running attempt with the submitted reference and
start time. Registry resolution and scanner execution happen outside that
transaction. A completion transaction associates the image, inserts findings,
and marks the scan completed together. The image identity uniqueness constraint
allows repeated scans to share one image row while keeping findings separate.

Failed completion writes roll back before failure is recorded in a separate
transaction. Failed attempts retain a known error code, fixed safe message, and
completion time. Completion and failure lock the scan row and require a running
Trivy attempt; they cannot overwrite an already terminal record.

If the database cannot save an attempt or its failure record, the workflow raises
the database error rather than claiming a durable outcome. Interrupted running
scans have no automatic recovery yet.

API retrieval marks real attempts `mock: false` regardless of finding count,
filtering, or lifecycle state. POST still creates mocks until worker integration.

## Verification

Routine tests use sample registry responses, scanner reports, temporary local
executables, and the isolated PostgreSQL test database. They do not download
images or depend on public registry availability.

A live local smoke test resolved `docker.io/library/alpine:3.20` to
`sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e`
and scanned that pinned image with Trivy 0.75.0 on October 6, 2026. The report
matched the digest and `linux/amd64` platform and contained zero findings. The
earlier tag scan warned that Alpine 3.20 was no longer supported. This smoke
test verified resolution, execution, and parsing; it did not save a scan to the
database.


Persistence was also verified through new database sessions and API retrieval.
On October 7, 2026, `docker.io/library/alpine:3.20.0` resolved to
`sha256:216266c86fc4dcef5619930bd394245824c2af52fd21ba7c6fa0e618657d4c3b`
and produced 70 persisted findings, including a repeated CVE on distinct packages.
A randomly generated absent tag produced a durable failed attempt with no image
link and `resolution_failed: Image reference could not be resolved`.

A subsequent scan saved database format version 2 with `UpdatedAt`
`2026-10-06T13:07:05.606377799Z`, `NextUpdate`
`2026-10-07T13:07:05.606377538Z`, and `DownloadedAt`
`2026-10-06T18:47:47.88503Z`. These observed values are not a freshness guarantee.
The README includes a reproducible development command. Tests also exercise
truncated chunked HTTP responses so interrupted registry transfers become saved
resolution failures instead of leaving a running attempt.
