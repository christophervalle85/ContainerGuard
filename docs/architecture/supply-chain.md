# Release supply-chain security

Status: approved; native SLSA v1 capture correction approved. The published v0.1.0 release has no signatures, release-image
SBOMs or verified build provenance. This design applies to a future release;
it does not change v0.1.0 or claim that the proposed checks already pass.

## Purpose

An operator should be able to establish that each ContainerGuard application
image came from the intended release workflow and reviewed source, retrieve its
dependency inventory, and reject missing or inconsistent evidence before running
it. Verification covers the API, worker and frontend on linux/amd64. The migration
service uses the same verified API digest. PostgreSQL and Redis are separately
pinned dependencies; this milestone does not sign or attest their upstream builds.

Preserve the existing quality, vulnerability, disclosure and isolated runtime
checks. Keep application builds, registry publication, signing and release notes
in separate jobs. Keep application containers unprivileged and preserve all
existing development data. Work in the existing checkout with neutral document
names. Commits, pushes, PR creation, version tags and publication remain explicit
maintainer actions after review.

## Approach and alternatives

Use Cosign keyless image signatures and signed SBOM/provenance attestations,
with GitHub Actions OIDC providing the signing identity. There is no long-lived
private signing key in repository secrets or on a development machine.

The candidate job captures BuildKit provenance from the actual build and generates
Trivy CycloneDX SBOMs from the resulting application images. The publisher copies
checked OCI image manifests without changing their digests. A separate job signs
those digests and attaches the validated evidence. A read-only job independently
retrieves and verifies everything before the notes job may create a release draft.

Alternatives considered:

- GitHub artifact attestations provide maintained provenance/SBOM generation and
  GitHub CLI verification. They are a valid alternative, but adding a second
  attestation system alongside the requested Cosign verification would duplicate
  policy and retrieval paths. Use one Cosign-based consumer procedure initially.
- A permanent signing key or cloud KMS introduces key custody, rotation and possibly
  cloud costs. Those are unnecessary for this public GitHub Actions release flow.
- Signing a publisher-generated description of its upload would be easier, but
  does not establish what the actual build consumed. Do not label upload metadata
  as builder-generated provenance.

## Build identity and provenance

The current Docker save/load/push flow verifies configuration and filesystem
identity but does not require the registry manifest digest to match a build-time
manifest digest. That is insufficient for directly binding BuildKit provenance to
an unchanged manifest. Replace the release candidate's canonical transfer format
with a single-platform OCI image archive and use digest-preserving publication.
Ordinary development Compose builds remain unchanged.

Build each service once with a pinned Buildx/BuildKit toolchain. Export its OCI
archive and capture native BuildKit SLSA v1 provenance from that exact build
reference. Use build-result metadata for output identity, not its converted
v0.2 provenance predicate. Retrieve only the required native history attachment;
do not export history logs or arbitrary build records. Keep provenance separate from the runnable image index;
the canonical archive contains exactly one unambiguous linux/amd64 application
manifest. Validate OCI wrapper indexes without treating them as runnable manifests.
No additional platform or embedded attestation manifest is silently accepted.

Use the native SLSA provenance v1 predicate produced by the pinned BuildKit
history interface before conversion. Retrieve the attachment by exact build
reference and content digest, preserve its bytes and verify their association
with that build's output manifest/configuration. Require the actual source repository/revision, Dockerfile
entry point, target platform, build invocation and resolved material digests.
Reject absent, dirty, unexpected or conflicting source metadata. GitHub context
also records the release tag, source SHA, workflow, run ID and attempt in a small
versioned build record. It supplements, rather than substitutes for, native build
provenance. Do not invent complete dependency coverage or reproducibility claims.

Validate the build metadata's output manifest/configuration against the canonical
archive. Keep archive hashes, OCI index hashes, runnable manifest digests, config
IDs and layer identities distinct. Generate local Docker-compatible images for
scanning and the full-stack smoke test from that same OCI archive without
rebuilding. Validate their configuration and uncompressed layer identities before
accepting any reports. The canonical checked manifest is the one to publish.

Use Skopeo's digest-preserving copy for the selected linux/amd64 manifest. Require
both version and full-commit tags to resolve to the captured manifest digest.
Refuse format conversion, recompression or a changed manifest digest rather than
editing provenance to describe different bytes. Preserve occupied-tag checks,
source rechecks, partial-publication records and same-run artifact-ID binding.

Before implementing the integration, prove this export/metadata/local-import/copy
path with the pinned tools in an isolated local fixture and registry. This probe
must preserve manifest identity, expose usable native source provenance and avoid
rebuilding. If it cannot meet those requirements, revise this design before
changing the production release path. A tool-version mismatch is not permission
to synthesize missing evidence or weaken identity checks.

## Release-image SBOMs

Generate one CycloneDX JSON SBOM for each canonical application image using the
existing patched Trivy build, with vulnerability scanning kept as a separate gate.
These inventories describe ContainerGuard itself, not the user-submitted image
SBOMs stored by the application. Do not add database tables or API endpoints.

Require valid CycloneDX structure, supported spec version, scanner identity,
component identities and an explicit association with the canonical image digest,
service, platform and source commit. A dependency inventory is not a vulnerability
verdict and does not establish that every component was detected.

Use bounded files and strict JSON parsing: maximum 16 MiB per SBOM, 4 MiB per native
provenance/build record, 24 MiB per signed verification response and 256 MiB combined
release evidence. Apply limits before allocation; reject duplicate keys, symlinks,
unsafe filenames and unknown evidence fields. Keep existing image archive limits.
The implementation plan must pin the supported tool/predicate/schema versions and
validate them with real fixtures before freezing command interfaces.

Extend the candidate handoff with hashes, sizes, schema versions and image
associations for every SBOM and provenance file. Revalidate them before upload,
publication and signing. Run the existing pinned disclosure detector over evidence
before any upload. Provenance and SBOM metadata can reveal paths, package names or
build parameters. The pinned native history interface emits `mode=max`; preserve
that full predicate within the evidence limits and retrieve only its required
attachment. Use fixed public package names and reviewed public build inputs;
never pass secrets through build arguments. Reject evidence that fails disclosure
rather than stripping its fields. Never include tokens, runtime configuration, arbitrary
environment dumps or private source URLs. Do not silently strip evidence fields
after signing or add detector exceptions merely to make publication pass.

## Workflow permissions and transfer

The trusted stable-version tag and main-ancestry guard remain mandatory. Jobs use
the exact guarded source commit; pull requests cannot sign or publish releases.

| Job | Responsibility | Additional permissions |
| --- | --- | --- |
| Candidate | Build, SBOM, provenance, security checks, isolated smoke, checked export | None; no OIDC or registry-write token |
| Publisher | Validate handoff and preserve exact digests on GHCR | packages: write; contents/actions: read |
| Signer | Validate build evidence and registry identities; sign images and evidence | id-token: write; packages: write; contents/actions: read |
| Verifier | Retrieve signatures/attestations anonymously; enforce consumer policy | Read only; no OIDC or package write |
| Notes | Create draft and attach verified installation/evidence files | contents: write; actions: read |

Use exact artifact IDs from the current run and attempt; do not select artifacts by
name from another run. The signer downloads the sealed evidence produced by the
candidate and the publisher's digest manifest, rechecks source and identities, and
never executes application images or installation scripts from their payloads.
Candidate jobs never receive publication/signing credentials. Pin third-party
Actions to full commit SHAs and verify installed tool versions and distribution
integrity; never download an unpinned latest binary during a release.

The signer uses Cosign to sign each exact image digest and attach signed CycloneDX
and SLSA provenance attestations. Preserve the native predicate without relabeling
the signer job as the builder. Include a separately signed build-record predicate
linking native provenance/SBOM hashes to the guarded source and actual build run.
All signed statements must identify the same canonical image digest and package.
Publish retrievable evidence as OCI referrers, and retain portable verification
bundles plus raw SBOM/provenance files as release assets. Attaching evidence must
not change the runnable image manifest digest. Fixture coverage must establish
that the pinned Cosign version can retrieve and verify that storage format on GHCR.

Keyless signing publishes workflow identity and signing metadata through Sigstore's
public services. Treat the certificate and transparency-log entry as public data;
never put secrets in signed payloads. OIDC tokens remain ephemeral and are never
printed, saved in evidence, or provided to the build job.

## Consumer trust policy

A valid cryptographic signature alone is insufficient. Verification must require:

- The fixed ContainerGuard repository/package for the chosen service.
- The requested stable version and expected full source commit, supplied explicitly
  by the operator or an independently selected trusted release reference.
- The exact image manifest digest, not a mutable tag or an unchecked manifest file.
- Issuer `https://token.actions.githubusercontent.com`.
- Certificate identity exactly
  `https://github.com/christophervalle85/ContainerGuard/.github/workflows/release.yml@refs/tags/<version>`.
- Available certificate source/workflow claims matching the guarded repository,
  source commit and trusted tag event. Test the pinned Cosign certificate claim
  behavior; absent required claims fail rather than becoming optional.
- Valid Sigstore trust roots, signature and transparency-log inclusion evidence;
  no insecure certificate, TLS or log-verification bypass.
- Signed CycloneDX and native build-provenance attestations with the expected
  predicate types, correct subjects, source, platform and consistent material data.
- A signed build record tying the downloaded raw evidence hashes and build run to
  the same subject and source. Hashing an untrusted file by itself proves no origin.

The workflow path above is deliberately the top-level release workflow, whose
signer job is not a reusable workflow. If that arrangement changes, update and
review the trust policy instead of accepting a repository-wide identity wildcard.
The expected identity/issuer are trusted constants, never learned from downloaded
release.json or from a certificate whose trust has not been verified.

Provide a reusable verify-release command and documented direct Cosign equivalents.
Verify all three services before starting any containers. Only verified input may
produce the installation Compose file. Preserve legacy schema-1 handling for
v0.1.0 in its existing explicit unsigned installation path; the signed-release
command must reject it, not fall back to unsigned execution. Use a new versioned
manifest/evidence schema for signed releases with separate strict validators.

A network error, absent signature, malformed predicate, unsupported schema,
changed source, mismatched SBOM, wrong signer or issuer returns nonzero and stops
installation/draft readiness. Print safe failure categories without raw credential
or scanner output. Online verification is the initial supported mode; do not
promise offline verification until bundled trust material and freshness policy
have been separately designed and tested.

## Failure and recovery

Pushed images are candidates until all required evidence verifies. A failed signer
or verifier prevents draft creation even if image bytes are already public. A
signature proves origin, not vulnerability freedom or application correctness.

Publication and attachment are not atomic. Keep a safe record of attempted image
and evidence operations. Never overwrite image version/commit tags or delete
partial published state automatically. Initial recovery is operator inspection
followed by a newly reviewed commit/version; no blind rerun or automated repair
of partially signed releases. Do not move v0.1.0 or retroactively qualify it as a
signed release. The future demonstration version is selected only after checks.

## Verification and completion evidence

Tests must exercise the trust decisions, not just successful command construction:
unsigned images, wrong identity/issuer/source, changed subject, unrelated valid
signatures, malformed/oversized evidence, swapped SBOMs, metadata-only source
claims, tampered bundles, unavailable registry/log services and partial signing
must fail closed. Inject synthetic fixtures without committing usable secrets.

Use real local Cosign signatures with disposable fixture keys to validate parsing
and negative behavior, clearly distinct from the actual GitHub OIDC trust policy.
Real release identity requires execution in the trusted tagged workflow; local
fixtures or mocked OIDC cannot satisfy that checkpoint.

Complete a new release with all three canonical images, signed retrievable SBOMs,
provenance, build records and image signatures. Run the read-only consumer policy
with empty registry authentication, then exercise the published images in a fresh
owned stack using the existing real scan/SBOM/policy/persistence verification.
Record source/tag/digests, run links, tool versions, signature identities, predicate
hashes and negative-case evidence. Preserve development data and remove only owned
verification resources. An independent second developer's setup remains unclaimed
until a separate person actually performs it.

## Documentation and boundaries

Keep this architecture in `docs/architecture/supply-chain.md`, the implementation
plan in `docs/development/supply-chain-plan.md`, operator instructions in
`docs/releases.md` and observed evidence in `docs/development/verification.md`.
Do not commit execution logs, local credentials or raw rejected disclosure reports.

This work adds no cloud deployment, ARM64 release qualification, multi-tenant
accounts, automatic interrupted-job recovery or admission controller. It makes no
SLSA level, complete dependency inventory, reproducible-build or exhaustive
security-audit claim. Trust still depends on repository governance, the protected
release workflow, GitHub, the selected build tools and Sigstore's trust services.

## Capture feasibility review

The first implementation review found that the pinned BuildKit/Buildx minimal
v0.2 metadata path cannot supply the required native target-platform field.
BuildKit filters the frontend `platform` argument; conversion to v0.2 retains
builder platform but drops target platform. These are different identities.
The probe therefore remains ineligible for production integration. Its unit
tests are not a successful native Linux transport demonstration.

**Approved correction:** capture BuildKit's native SLSA v1
history predicate from the exact build reference, before Buildx's v0.2 metadata
conversion. Use that v1 predicate as the signed build provenance for the future
release. Continue using build-result metadata to check output manifest/config
identity; never promote its converted v0.2 predicate into evidence of a target
field it does not contain. Because the signed-release format is not published,
using one native provenance schema avoids maintaining two signed predicates
with overlapping claims.

The probe must retrieve the attachment by its exact build reference and content
digest, preserve its bytes, and check native source revision, Dockerfile,
`buildDefinition.internalParameters.targetPlatform`, resolved dependencies and
invocation identity against that build's checked image output. The history reference
and native invocation ID are separate builder identifiers: retain both and bind
them through the exact history record, attachment digest and checked output;
do not require them to be equal. Missing or
ambiguous attachments, another build's predicate, conflicting source materials,
wrong target platform or unequal output digests fail closed. The exact history
retrieval/association must be proven on Linux before any production integration.

This changes provenance capture and the expected predicate type to
`https://slsa.dev/provenance/v1`. It does not change the image bytes, rebuild
policy, keyless signing identity, disclosure requirements or resource limits.
The corresponding plan, validators, tests and operator examples use this
contract together. No signed release or successful history capture is claimed
by approval of the correction.

Evidence: [BuildKit's separate native target/builder fields](https://github.com/moby/buildkit/blob/v0.34.0/solver/llbsolver/provenance/types/types.go),
[Buildx's conversion](https://github.com/docker/buildx/blob/v0.38.0/build/provenance.go),
and [build-history attachment retrieval](https://docs.docker.com/reference/cli/docker/buildx/history/inspect/attachment/).

## References

- [Cosign container signing and attestations](https://docs.sigstore.dev/cosign/signing/signing_with_containers/)
- [GitHub Actions OIDC identity verification](https://docs.sigstore.dev/quickstart/quickstart-ci/)
- [Buildx build-result metadata](https://docs.docker.com/reference/cli/docker/buildx/build/#write-build-result-metadata-to-a-file---metadata-file)
- [BuildKit provenance](https://docs.docker.com/build/metadata/attestations/slsa-provenance/)
- [Digest-preserving Skopeo copy](https://github.com/podman-container-tools/skopeo/blob/main/docs/skopeo-copy.1.md)
- [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
