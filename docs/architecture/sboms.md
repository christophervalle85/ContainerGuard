# SBOM artifacts

Status: implemented and verified through the API and a disposable Compose stack.

An SBOM inventories detected software in the submitted image. This artifact is
separate from ContainerGuard's own future release-image SBOMs. Trivy 0.75.0
supports CycloneDX JSON generation; its default CycloneDX output is an inventory
without vulnerability results. Existing findings remain the policy count source.
See [Trivy's versioned SBOM documentation](https://trivy.dev/docs/v0.75/guide/supply-chain/sbom/).

## Generation and scan behavior

The existing worker resolves the submitted tag once and scans its pinned digest
on `linux/amd64`. After successful vulnerability collection, it attempts a
separate bounded CycloneDX generation command using that exact pinned reference
and platform. It never resolves the tag again. Generation continues to inspect
remote images without a Docker socket or execution of submitted contents.

The existing process runner applies a 60-second SBOM deadline, 10 MiB stdout
limit, and 64 KiB stderr limit. Vulnerability scanning retains its 300-second
limit; the RQ job timeout remains 600 seconds. These are separate stage limits,
not an overall completion guarantee. SBOM failure alone does not trigger a new
vulnerability scan or consume the vulnerability retry budget.

The scan remains running until vulnerability collection and the bounded SBOM
attempt have settled. Successful findings, image identity, and the artifact
outcome are committed together when the scan completes. Expected SBOM generation
or validation failures preserve findings and save a separate safe SBOM failure.
A database persistence failure can still prevent saving results; this design
does not hide that failure or make separate services transactional.

Vulnerability failure retains existing scan/retry behavior and does not attempt
an SBOM. An interrupted job retains the existing guarded recovery procedure.
Recovery cannot replace a completed scan's findings or artifact outcome.

The supported end-to-end SBOM path currently uses Docker Hub references. The
low-level command builder inherits broader registry acceptance from the
vulnerability runner, but GHCR SBOM identity parsing is not supported. Do not
treat command construction as verified GHCR SBOM support.

## Validation and storage

The `sbom_artifacts` table stores one row per scan attempt that reached SBOM generation.
The scan UUID is unique and references the scan. Fields record outcome
(`available` or `failed`), timestamp, format, format version, generating tool
version, pinned digest/platform, original bytes, byte size, SHA-256 checksum,
and a fixed safe error code/message when generation failed.

An available artifact must contain UTF-8 JSON with `bomFormat: CycloneDX` and
`specVersion: 1.7`, the format observed from the pinned Trivy 0.75.0. Root metadata
must contain a container component, a package URL identifying the pinned image,
and a Trivy tool component with version 0.75.0. The inventory is a JSON list of
component objects with nonempty type/name fields and string identifiers/versions
when supplied. Empty inventories are allowed; zero components is not itself an
execution failure. Repeated JSON keys and non-finite numeric constants are rejected.

The package URL must identify the expected repository, SHA-256 digest, and amd64
architecture; canonicalize the known Docker Hub hostname aliases for comparison.
The RepoDigest property must agree. Conflicting duplicate identity properties
are rejected. Trivy's observed package URL carries architecture but no OS field:
record `linux/amd64` from the explicitly selected generation platform and the
already validated vulnerability report, not an invented SBOM OS property.
A temporary real-image probe confirmed this shape before implementation.

Other format/tool versions, missing or mismatched identity, malformed inventory,
invalid encoding, and oversized output are failures, never usable artifacts.
This is scoped validation of pinned Trivy output, not full CycloneDX schema
conformance or proof that Trivy detected every installed component.

Store exact UTF-8 bytes as PostgreSQL binary data, with an application and database
size ceiling of 10485760 bytes. Compute size and checksum over those bytes,
without parsing and reserializing the document. Available rows require payload,
checksum, size, and identity metadata and have no error. Failed rows require a
safe failure code and no usable payload/checksum. A unique scan association and
check constraints protect these invariants. Never fetch payload columns in
ordinary scan history or evaluation listings.

Existing scans keep their data and have no artifact row: report `not_generated`.
Queued/running scans without a row report `pending`; failed scans that never
reached generation report `not_generated`. Absence is not proof of generation
failure. Available/failed rows are final with their completed scan; no artifact
replacement, retry-only endpoint, or backfill is included initially.

The 10 MiB limit bounds each artifact, not total database growth. History and
artifact retention consume disk until a deliberate reset or future retention
feature. PostgreSQL storage keeps artifact persistence and backups together;
files or object storage can be introduced later with an explicit migration.

## Retrieval

Two endpoints are available under `/api/v1`:

- `GET /scans/{scan_id}/sbom/metadata`: status, format/version, tool version,
  digest/platform, size, checksum, timestamp, and safe error information. Never
  includes the payload. Missing scan returns 404.
- `GET /scans/{scan_id}/sbom`: download available bytes as JSON with a safe UUID
  filename and Content-Disposition attachment. Include a checksum-derived ETag.

Download returns 409 if the scan is unfinished, 404 when the existing scan has
no available artifact, and a safe 500 integrity error if stored bytes fail checksum,
size, or scan-association checks. Do not return corrupted bytes. Metadata explains
`failed` versus `not_generated` when download is unavailable. Database outages
use the existing safe 503 response. The response reads at most one bounded
artifact; no filesystem path or submitted image name becomes a filename.

A completed scan without an SBOM fails `require_sbom: true`. A policy that does
not require one can still pass its vulnerability rules. A malformed persisted
artifact is an evaluation error, distinct from an ordinary missing artifact.
See [policies](policies.md) for versioned evaluation behavior.

## Verification

Fixtures and real PostgreSQL tests cover byte preservation, checksum identity,
size boundaries, identity mismatch, malformed reports, missing/legacy artifacts,
safe errors, duplicate writes, and rollback. Process-runner tests cover the
bounded command and controlled generation failures. Existing tests must continue
to pass with artifact generation explicitly stubbed where no external scanner
is intended.

A live container checkpoint verifies that a new scan's downloadable bytes match
its saved checksum and digest/platform. A controlled generation failure verifies
that successful vulnerability findings remain completed and retrievable. Policy
fixtures verify both required and optional SBOM behavior without network faults.
Restart/recreation checks retrieve the same saved artifact bytes afterward.
