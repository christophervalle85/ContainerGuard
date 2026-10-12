# Versioned releases

Status: implemented; first publication and public installation verification are
pending the release checkpoints below.

## Purpose and scope

Publish the API, worker, and frontend as public GHCR images that another developer
can pull and run locally without building source. Each release must identify its
reviewed source commit and exact registry digests. Publication must follow the
quality, vulnerability, and disclosure checks; publication is not cloud hosting.

Public packages must pass the disclosure and security checks described below.
Verification uses isolated resources and must preserve existing development data.
Release tags and publication are explicit maintainer operations after review.

The first release supports linux/amd64, matching the supported scanner platform.
Running that release on Apple Silicon requires Docker's amd64 emulation. Native
ARM64 runtime builds have been exercised previously, but that does not qualify an
ARM64 published release. Additional platforms require their own release checks.

Signing, release-image SBOM distribution, and provenance verification belong to
the supply-chain milestone. This release does not claim those guarantees. Existing
SBOM downloads describe submitted scan targets, not ContainerGuard release images.

## Approach

Use a trusted version-tag workflow with read-only build/check jobs and a separate
publisher. Reuse the existing CI definitions rather than maintaining weaker or
stale copies of the backend/frontend/dependency checks. Export the exact checked
runtime images for publication; do not rebuild after passing a gate.

Alternatives considered:

- Manual local publication is simpler to start, but makes omitted checks and
  accidental inclusion of workstation files harder to prevent and reproduce.
- Building, checking, and publishing with one registry-write job avoids artifact
  transfer, but gives build tools and dependency installation a publishing token.
- Separate checking and publication adds bounded archive transfer and identity
  validation. It keeps registry write permission away from application builds
  and makes the release decision explicit. This is the selected approach.

## Release identity and trusted events

The workflow runs only on version-tag pushes to this repository. Initially accept
stable versions of the form vMAJOR.MINOR.PATCH, with numeric components and no
leading zeroes except zero itself. Reject prerelease suffixes and arbitrary tag
strings until explicitly supported. Do not publish from pull requests,
pull_request_target, workflow_run, or unvalidated manual inputs.

Before invoking release builds, resolve the exact tag to a commit, confirm that
it matches the event's commit, and prove that it is reachable from origin/main.
Fetch enough history for that proof. All jobs use that same resolved source
commit; a green check on a different commit is insufficient. Validate tag-derived
values before use and pass them through quoted environment variables rather than
inserting event text into shell source.

Use these lower-case package names:

- ghcr.io/christophervalle85/containerguard-api
- ghcr.io/christophervalle85/containerguard-worker
- ghcr.io/christophervalle85/containerguard-frontend

Publish a version tag, such as v1.0.0, and a full-commit tag, such as sha-<40 hex
characters>, for each image. Do not publish latest or moving major/minor aliases.
Include OCI source, revision, version, and description metadata before building
and scanning, so metadata is part of the checked image. Do not embed workstation
paths, personal author email, runtime credentials, or environment files in labels.

Serialize publication runs without cancelling a publisher in progress. Before
any upload, check all three packages' intended version and commit tags. An
existing tag causes refusal; do not overwrite it, even on a retry. An authentication
or registry outage must not be interpreted as proof that a tag is absent.

This prevents silent overwrite by this workflow, not modification by every
account with package-write access. Document restricting tag changes through
repository rules where available; deployments and demos use digests regardless.

## Required checks before publication

The release must pass the backend lint/format/test jobs, frontend lint/format/type/
unit/browser/build jobs, reachable-history secret scan, both-lockfile dependency
gate, and all three runtime vulnerability gates at the release commit. Preserve
HIGH/CRITICAL blocking, including unfixed findings, the existing validated
exception policy, and fail-closed scanner execution/report handling. Do not add
exceptions or change thresholds merely to obtain a release.

Build each image once with linux/amd64 and its existing pinned base/tool inputs.
Check the exact local image identified by its immutable image ID. Restrict each
build context to required inputs. The frontend currently has a broad context:
replace it with an allowlist that retains required TypeScript/configuration and
build inputs while excluding environments, logs, Git data, generated output,
local credentials, and unrelated files. The backend context should likewise
reject unintended files beneath included source directories.

Use a fresh committed checkout, not a workstation directory. Never pass registry
or runtime credentials as build arguments or Dockerfile ENV values. The current
application builds require no build secrets. If that changes, it requires a
reviewed secret-mount design; deleting a secret later does not erase an earlier
layer. No public build-cache export is introduced by this work.

Check the runtime filesystem, all exported runtime layers, and image
configuration/history for disclosure. Detection output must be redacted; retain
only safe summaries, paths or rule identifiers where safe, and counts. Never
upload raw secret matches or rejected image archives. Do not extract arbitrary
layer archives unsafely onto the host: inspect bounded regular-file streams,
reject traversal/unsupported archive shapes, and handle symlinks without following
them outside the archive. Preserve enough coverage to catch a secret added in
one layer and deleted in a later layer. Check configuration/history as well as
filesystem bytes. Report coverage and detection limits accurately.

The detector configuration keeps all default rules and adds 20 anchored,
exact-value exceptions for public dependency material: two SQLAlchemy code
expressions, 13 Go module checksums, two embedded policy examples, and three
packed Trivy code strings. These do not exclude files or directories. The
expressions are recorded in `security/gitleaks.toml`; generated credential probes
verify that the affected rules still block new secrets. Trivy source and embedded
checks are pinned by the worker build and its module dependencies.

Prove disclosure checks with synthetic nonfunctional sentinels in a disposable
context/image, including an excluded environment file, a credential-shaped file
under a copied source directory, a secret subsequently deleted in another layer,
and a secret in configuration/history. Sentinels must never reach GHCR, repository
history, or public artifact logs. Invalid/oversized archives and scanner errors
must block release rather than count as clean.

Run an isolated candidate Compose smoke test before publication using the exact
built images and fresh verification-owned services/volumes. Check startup,
migrations, real scan completion, findings retrieval, SBOM download/checksum, and
policy evaluation. Keep development ports, data, worker, and cache untouched.
Do not execute submitted scan-target images or mount Docker's socket into the
application containers. Test-image use of the runner's Docker daemon is separate
from permissions inside the deployed application containers.

## Transfer and publisher permissions

Make CI callable with read-only permissions; export candidate archives only when
explicitly invoked by the trusted release workflow. Ordinary PR jobs cannot
publish or request a publishing token. There is no secrets: inherit handoff.
Pin actions to reviewed full commit SHAs and disable persisted checkout
credentials. Prefer ephemeral runners and avoid privileged shared caches.

Only after all required checks succeed, store short-lived checked image archives
and a machine-readable handoff manifest as artifacts of that same workflow run.
Apply an explicit size bound and short retention, initially one day, for image
archives. Existing safe security summaries can retain their seven-day period.
Treat Actions artifacts as potentially downloadable; disclosure failures must
prevent archive upload. Archives must not include databases, runtime mounts,
Trivy vulnerability caches, application logs, or a developer's Docker config.

The manifest records a schema version, source commit, release version, service,
platform, archive SHA-256, configuration ID, an exported manifest digest when
present, and rootfs layer identity. Docker's classic store identifies a local
image by its configuration, while its containerd store can identify the same
image by its manifest. Both identities must resolve to the same validated
configuration and layers. Checksums also bind the passing vulnerability,
disclosure and smoke evidence to that handoff.
Select artifacts by exact run and artifact identity, not an untrusted name from
another workflow. Validate the manifest's fixed service set, syntax, source,
platform, limits, archive hash, and loaded image identity. A checksum detects
transfer changes; it is not a signature or independent provenance claim.

The publisher runs on a separate fresh runner. Give it only the contents-read,
artifact-read access it needs and packages:write. It must not install application
dependencies, rebuild, execute image payloads, or run commands taken from the
handoff data. Registry login uses the job's temporary GITHUB_TOKEN and a temporary
Docker configuration, never a long-lived personal access token. Clear login
material after the job. GitHub Release creation uses a separate narrow
contents-write release-notes job that creates a draft, rather than giving that
permission to builders. Publishing the GitHub Release is a separate owner action
after the published-image verification below; no extra privileged workflow trigger
is introduced for this first release.

After verifying the handoff and checking for existing tags, load and push the
checked images. Obtain each registry manifest digest from the registry and verify
that its configuration identity corresponds to the checked image, including
platform/source metadata and layer identity. Do not confuse a local Docker image
ID with a registry manifest digest or fabricate one from an archive checksum.
Do not rebuild, alter labels, or otherwise mutate images in the publisher.

## Visibility, release notes, and local use

GHCR initially creates private packages. After checks and the initial upload, the
owner makes the three packages public using GitHub's supported package controls.
Public visibility is an intentional disclosure decision made through the
reviewed first-release procedure. Do not print or
copy credentials to obtain anonymous access.

Verify all three images can be pulled by exact digest using an empty Docker auth
configuration. Recheck pulled identities and run the documented isolated Compose
workflow from published images with no build step. Runtime configuration is
provided separately; database/Redis remain internal services and published
application ports bind to localhost. The release Compose file must preserve
health checks, migration ordering, worker stop behavior, resource limits, and
persistent volumes. Do not reuse development volumes for verification.

Create/update a draft GitHub Release containing the source SHA, platform,
version/commit tags, exact image digests, safe check links, known remaining
findings, and installation instructions. Include a machine-readable release
manifest and digest-pinned Compose configuration. Mark the GitHub Release public
only after anonymous pulls and the published-image workflow succeed. A draft
release does not make already public package bytes private.

## Failure handling

Any failed prerequisite prevents the publisher from running. Missing, malformed,
wrong-source, wrong-platform, oversized, or altered handoffs fail closed. Registry
errors block publication; logs must not reveal tokens or raw secret matches.

Three registry uploads are not atomic. A failure after the first upload can leave
partial candidate packages or tags. Do not announce a successful release or
silently overwrite them. Record the partial state, keep the GitHub Release draft,
and require an explicit recovery decision, normally a new version. Automatic
package deletion and rollback are outside this first release workflow. The
commit tag can also be partially occupied, so recovery may require a new reviewed
commit as well as a new version. Spell out the actual affected tags in safe logs.

A passing scanner is a dated observation, not a permanent safety guarantee.
LOW/MEDIUM/UNKNOWN remain visible under the approved policy. Builder images and
PostgreSQL/Redis images are not covered by the current runtime vulnerability gate;
report those boundaries and do not claim an audit of every deployed component.
The downstream Trivy build remains a maintenance responsibility. Secrets
recognition cannot prove that every possible sensitive value is absent.

## Completion evidence

Before declaring this milestone complete, record:

1. Negative verification of invalid/non-main release refs, existing tags, failed
   gates, secret-disclosure cases, and altered/missing artifact handoffs.
2. Passing required checks for the exact release commit and images, with links.
3. Three actual GHCR manifest digests and matching source/platform identities.
4. Anonymous pulls and the full published-image smoke test without rebuilding.
5. A public GitHub Release with notes and digest-pinned run instructions.
6. Updated documentation separating completed verification from remaining work.

Exercise failures before the first release, following the lesson from the
security-gate verification. Verify dry-run publication behavior without registry writes
where possible, then explicitly approve the first version-tag push. A second
developer's setup test remains unclaimed unless one actually performs it.

## Documentation changes

Keep the release design here. Put the implementation plan in
`docs/development/releases-plan.md`, the operator walkthrough in `docs/releases.md`,
and scripts/workflows under neutral release names. Keep repository documentation
separate and linked from the README; do not concatenate it or copy it into runtime
images. Release notes link to the documentation at the exact version tag. Finish
the required installation documentation before creating that tag. Update README
links and the
previous verification record with already established clean-clone and red/green
CI evidence. New release evidence must remain marked pending until observed.

## References

- [GitHub: publishing Docker images](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images)
- [GitHub: reusable workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows)
- [GitHub: secure Actions use](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub: container registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
- [Docker: build contexts](https://docs.docker.com/build/concepts/context/)
- [Docker: build secrets](https://docs.docker.com/build/building/secrets/)
- [Docker: image exporters](https://docs.docker.com/build/exporters/image-registry/)
