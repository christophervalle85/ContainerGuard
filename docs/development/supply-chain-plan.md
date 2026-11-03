# Release supply-chain implementation plan

**Goal:** Let an operator verify the origin, build provenance and dependency inventory of all three application images before installation.

**Architecture:** Build and test one canonical OCI image per service, transfer sealed evidence, publish without changing its manifest digest, then sign in a separate GitHub OIDC job. An anonymous verifier enforces the consumer trust policy before installation files or a release draft become eligible.

**Tech stack:** Python 3.12-compatible release scripts, pytest, Docker/Buildx/BuildKit, Skopeo, Cosign, patched Trivy, Gitleaks, GitHub Actions and GHCR.

**Spec:** [Release supply-chain security](../architecture/supply-chain.md).

Status: implementation in progress.

- Task 1 passed native Linux transport and unchanged-evidence disclosure qualification in [run 39170299034](https://github.com/christophervalle85/ContainerGuard/actions/runs/39170299034), at commit `ab0e6b83bc1a6f55aec3659f689f9bb35fa5ec0f`. Source, platform, history and output bindings passed; the audit reported no private-source matches or secret findings.
- Task 2 has a reviewed local implementation and a real containerd import check. Pinned Linux Skopeo copy and a real classic Docker-store import remain to be qualified before production integration.
- Task 3 has a reviewed local implementation for bounded evidence, native provenance and image-bound build records. Real patched-Trivy output passes full offline CycloneDX validation and disclosure checks. Production host generation and compatibility with a newly captured real native predicate remain integration checkpoints.

Signing and publication remain pending.

The probe captures the complete native predicate after disabling optional GitHub event-context injection at builder creation. Rejected and raw records stay in runner temporary storage; qualification did not upload them. Local follow-up work is batched for review before another push to conserve Actions minutes.

## Global constraints

- Use the existing checkout and `feat/supply-chain-security`; preserve development containers, volumes and approved documentation. No worktrees.
- Commits, pushes, PRs, version tags and publication require explicit maintainer instruction. Every task ends with an uncommitted, reviewable diff unless instructed otherwise.
- Exactly `api`, `worker`, `frontend`, platform `linux/amd64`, packages `ghcr.io/christophervalle85/containerguard-{api,worker,frontend}`. Migration uses the verified API digest. Do not change application APIs, database schema or user-image SBOM behavior.
- Preserve stable-tag/main-ancestry checks, all existing quality/security gates and occupied-tag refusal. No new exceptions, weaker vulnerability thresholds, application rebuilds in privileged jobs or automatic repair of partial releases. Install source/checksum-pinned release tools before exposing step-scoped publication credentials; do not execute candidate-supplied tools.
- Require native SLSA provenance v1 (`https://slsa.dev/provenance/v1`), CycloneDX JSON spec 1.7 (`https://cyclonedx.org/bom`), and custom build-record predicate `https://github.com/christophervalle85/ContainerGuard/attestations/build-record/v1`. The build-record schema is version 1; signed release/handoff schemas are version 2.
- Limits: SBOM 16 MiB; native provenance/build record 4 MiB each; signed verification response or bundle 24 MiB; combined evidence 256 MiB. Retain archive limits: 2 GiB per archive, 4 GiB total, 1 GiB per member, 8 GiB expanded, 200,000 members. Enforce limits while reading, before JSON parsing or base64 decoding.
- Reject duplicate JSON keys, unsafe paths, symlinks, unknown fields in owned schemas, missing evidence and conflicting identities. For third-party documents, validate the pinned schema and allow only its specified fields; never apply the build-record field set to a CycloneDX document.
- The trusted issuer is `https://token.actions.githubusercontent.com`. The exact certificate identity is `https://github.com/christophervalle85/ContainerGuard/.github/workflows/release.yml@refs/tags/<version>`. Expected version and full source commit come from explicit operator inputs or independently guarded workflow inputs, never downloaded evidence.
- No insecure TLS, certificate, transparency-log or claims bypass. Online verification only. Disposable-key tests are not GitHub OIDC qualification.
- Keep v0.1.0 unchanged and explicitly unsigned. Signed verification rejects schema 1; there is no fallback. A future release version is selected after checks.
- Disable optional Buildx GitHub Actions event-context injection before building with `--driver-opt provenance-add-gha=false`; reject unsupported-option errors without fallback. Preserve complete native `mode=max` evidence and all binding/disclosure checks. Required trusted release tag, source SHA, workflow, run ID and attempt still belong in the versioned build record; excluding the full event payload does not remove that requirement.
- Upload only validated allowlisted files. Exclude smoke-stack runtime configuration, passwords, private paths, environment dumps, rejected reports and execution logs. The pinned native history interface emits `mode=max`: preserve its full predicate bytes within the evidence limits, retrieve only the required attachment, and reject disclosure failures rather than stripping fields. Never pass secrets through build arguments; do not rewrite evidence to conceal a failed check.

## Review focus

1. Build metadata describes the wrapper index rather than the runnable image: reject a subject mismatch before upload (Tasks 1–3).
2. Valid evidence is swapped between services or commits: reject despite a valid signature (Tasks 3, 6–7).
3. A credential appears only in temporary smoke configuration: it never enters an artifact or release asset (Tasks 4, 8).
4. A signature has the right repository name but the wrong workflow/ref/source: refuse installation, including when JSON claims the right values (Tasks 6–7).
5. A timeout or partial signing leaves public images: retain a safe operation record, stop draft creation and never overwrite or silently resume (Tasks 5–8).

## File responsibilities

Keep existing release orchestration modules. Add focused helpers under `scripts/releases/supply_chain/`:

- `__init__.py`: package marker only.
- `tools.py`: pinned installation/version checks; `security/release-tools.json` stores the pins.
- `oci.py`: canonical archive inspection, same-archive local import and digest-preserving registry copy.
- `evidence.py`: bounded readers, owned evidence schemas, hashes and safe file enumeration.
- `provenance.py`: native BuildKit provenance validation and supplemental build records.
- `sbom.py`: release-image SBOM generation and pinned CycloneDX validation.
- `signing.py`: keyless signing, bundle collection and safe partial-operation records.
- `verification.py`: Cosign trust enforcement, attestation/predicate validation and verified release result.
- `manifest.py`: strict schema-2 handoff/release validation, kept distinct from schema 1.

Modify `candidate.py`, `publish.py`, `commands.py`, `disclosure.py`, `compose.py`, `notes.py`, `verify.py`, `__main__.py` and the release/CI workflows only at the integration tasks below. Reuse archive traversal, fixed registry handling, source guards and `smoke.exercise_stack`; do not duplicate them.

Place new tests in corresponding `tests/test_supply_chain_*.py` files and extend existing `tests/test_release_*.py` regressions. Put sanitized, small real-tool fixtures in `tests/fixtures/releases/`; generated keys, archives, bundles and execution records remain outside tracked source.

## Task 1: Pin tools and prove the transport path

**Qualification follow-up:** run the bounded evidence-disclosure check inside the probe job while the raw predicate is still present. Reuse the pinned detector and shared release-disclosure mechanism; log only safe categories, counts, sizes and hashes. No raw evidence upload is authorized. The minimal document-checking portion of Task 3 is pulled forward for this checkpoint; Task 3 extends and reuses that implementation rather than duplicating it.

**Files:** create `security/release-tools.json`, `scripts/install_release_tools.sh`, `scripts/releases/supply_chain/{__init__,tools}.py`, `scripts/probe_release_supply_chain.py`, `tests/test_supply_chain_tools.py`, `tests/test_supply_chain_probe.py`, `.github/workflows/supply-chain-probe.yml`; extend the Python-3.12 syntax regression.

**Interfaces:** `tools.install_tools(destination: Path) -> dict`; `tools.verify_tools() -> dict`; `probe_release_supply_chain.run_probe(workspace: Path) -> dict`. The probe result contains tool versions, source commit, one build invocation, canonical manifest/config/diff IDs, copied digest, native provenance hash and `passed: bool`; no credentials or raw environment.

Pin the initial Linux/amd64 toolchain to the following upstream identities, checked while preparing this plan:

| Tool | Pin and integrity anchor |
| --- | --- |
| Cosign | v3.1.3, `cosign-linux-amd64`, SHA-256 `4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71` |
| Buildx | v0.38.0, `buildx-v0.38.0.linux-amd64`, SHA-256 `4fe4cc38adf48169132749b6ca22a990928db0118e3407584ee553723115d287` |
| BuildKit | v0.34.0, amd64 image `docker.io/moby/buildkit@sha256:3eea2ed5d1766c44eb4740853abf56ba85ad40b2c8d4a22e047cbacf15f463c8` |
| Skopeo | v1.24.1, upstream commit `77f3d92f861271c7cb9175afcf876017bcae9202`; verify the checkout object and `go mod verify` before compilation |
| Skopeo compiler | Go 1.27.2 from the existing digest-pinned Go image in `Dockerfile.worker`; `GOTOOLCHAIN=local`, `CGO_ENABLED=0`, `-mod=readonly`, `-tags=containers_image_openpgp,exclude_graphdriver_btrfs`, `-trimpath` |
| Inventory/disclosure | Existing Trivy 0.75.0+cg.1 and Gitleaks 8.30.1 pins in `security/tools.json` |

Use the checksum-verified upstream binaries for Cosign/Buildx. Build Skopeo from its exact checkout in a separate tool build, export the binary and execute it on the Linux host. Never mount Docker's socket into an installer container. Use Buildx's owned builder with the pinned BuildKit image. Record generated tool binary hashes; never treat a locally computed hash as an upstream signature. Pin probe registry images by digest before running them and record the resolved upstream version/digest in the tool manifest.

- [ ] Write installer/probe tests: `test_wrong_tool_digest_refuses_execution` asserts the runner was not called; `test_probe_requires_native_source_and_equal_manifest` asserts `passed is False` for missing source or a changed registry digest; `test_probe_builds_once_and_cleans_only_owned_resources` asserts one build and no development-resource deletion.
- [ ] Run `uv run pytest tests/test_supply_chain_tools.py tests/test_supply_chain_probe.py -q`; expect missing implementation failures.
- [ ] Implement the pinned installer and a small committed fixture Git context in an owned temporary repository. Export one OCI archive and native SLSA v1 history provenance from the exact Buildx build reference; import that archive for local inspection and copy the selected manifest with Skopeo `--preserve-digests` to a loopback-only disposable registry. Confirm source revision, Dockerfile, platform, invocation/materials and identical published manifest digest. Do not use application builds or GHCR writes for this probe.
- [ ] Capture `buildx.build.ref` from the build-result metadata, enumerate native history attachments only for that exact reference, select one SLSA v1 predicate, and retrieve it by descriptor digest. Bound and hash-check the raw response before parsing; reject missing, duplicate/ambiguous or wrong-build attachments. Match that history record's output manifest/config to the canonical archive and require its native targetPlatform, source, materials and invocation. Never select the latest build, substitute builderPlatform, convert v0.2 into v1 or add invented native fields. Add regressions for wrong-reference, wrong-content-digest, wrong-source, conflicting materials and wrong/missing native target platform.
- [ ] Run the focused tests again; expect pass. Run `python3 scripts/probe_release_supply_chain.py --output-dir <fresh-temporary-directory>` on a Linux/amd64 Docker host. Expect `passed: true`, matching manifest digest and usable native SLSA v1 provenance; save sanitized native fixtures. The probe workflow has `contents: read` only, no OIDC/package write, full-SHA actions and bounded execution.
- [ ] Review the probe result before Task 2. On this Mac, Linux CI may be needed; prepare the small probe diff and request commit/push authorization if required. If export/provenance/import/copy fails, stop integration and revise the design. Do not synthesize provenance, accept changed bytes or claim a mocked probe passed.

## Task 2: Canonical OCI image transport

**Local checkpoint:** archive selection/import/copy helpers are implemented and reviewed. The focused tests pass, and a small real OCI fixture was imported and verified on the local containerd store. Its [fixture notes](../../tests/fixtures/releases/README.md) record the tool versions and origin. Task 1's raw runner artifacts were not retained; this fixture is newly generated local output, not captured CI evidence. Pinned Linux Skopeo copy and a real classic-store run remain required before production integration. No Actions run or registry write was used for this checkpoint.

**Files:** create `scripts/releases/supply_chain/oci.py`, `tests/test_supply_chain_oci.py`; modify `scripts/releases/artifacts.py` only to expose reusable strict traversal if needed.

**Interfaces:** `oci.inspect_canonical(path: Path) -> dict`; `oci.import_for_checks(path: Path, reference: str) -> dict`; `oci.copy_preserving_digest(path: Path, destination: str, *, authfile: Path) -> str`. Inspection returns the existing identity fields plus `index_digest`, non-null runnable `manifest_digest`, archive SHA-256/size and the selected OCI descriptor. Only the copy helper writes a registry.

- [x] Write fixtures/tests: `test_wrapper_is_not_image_subject` asserts index and runnable digests differ and the runnable digest is selected; `test_extra_platform_or_attestation_rejected` raises `ValueError`; `test_descriptor_size_or_blob_hash_mismatch_rejected` raises before import. Extend tar traversal tests for duplicate members, links, compressed expansion and limits.
- [x] Run `uv run pytest tests/test_supply_chain_oci.py tests/test_release_artifacts.py -q`; expect new tests to fail.
- [x] Implement exact-one-image selection through validated wrapper indexes, with descriptor hashes/sizes/config platform/layers checked. Import via a Docker-compatible export of the same archive, comparing config and uncompressed diff IDs on both classic and containerd stores. Canonical publication uses the original OCI blobs, without format conversion/recompression. Skopeo failure or an unequal returned digest raises before success is recorded.
- [x] Run the focused command again; expect pass, including the attributable local real-tool archive fixture described above. Do not treat this as pinned Linux transport qualification. Review diff; leave uncommitted.

## Task 3: Bounded SBOMs, native provenance and build records

**Local checkpoint:** reviewed helpers reject oversized, malformed and conflicting evidence, and bind the SBOM's reported image configuration ID to the canonical image before creating a build record. The raw native predicate hash is checked against the capture receipt independently of invocation and output identities. A real 71-component Trivy fixture passes full schema, format and disclosure checks; the isolated Python 3.12 dependency installation is hash-locked. Native validation tests use an explicitly synthetic producer-shaped fixture. Host scanner orchestration and a fresh real native capture still need integration qualification; the local tests do not establish signing or release readiness.

**Files:** extend the existing `scripts/releases/supply_chain/evidence.py` and its tests from Task 1. Create `scripts/releases/supply_chain/{provenance,sbom}.py` and their focused tests. Extend `scripts/releases/commands.py` for bounded file output; reuse the disclosure scanner. Store the pinned upstream schemas, license and integrity manifest under `security/schemas/cyclonedx-1.7/`, and hash-locked release dependencies in `security/release-requirements.txt`. Mirror direct validator pins in the development dependency group and `uv.lock`; application production dependencies stay unchanged.

**Standalone validation environment:** provision an isolated Python 3.12 environment and install `security/release-requirements.txt` with `pip install --require-hashes`. An offline install requires a prepared package cache or wheelhouse. Runtime schema validation uses only the hash-checked local schemas and refuses remote references or missing format checkers. Task 8 must provision this environment before invoking the integrated release helpers; the current workflow is unchanged.

**Interfaces:** `evidence.read_document(path: Path, *, kind: str) -> dict`; `evidence.describe_file(path: Path, *, kind: str) -> dict` returns `{path, kind, size_bytes, sha256}` with basename-only paths; `evidence.check_disclosure(paths: list[Path], output: Path) -> dict`; `provenance.validate_native(document: dict, *, image: dict, context: dict) -> dict`; `provenance.build_record(*, image: dict, context: dict, files: dict) -> dict`; `sbom.generate(reference: str, output: Path) -> Path`; `sbom.validate(document: dict) -> dict`.

The shared context has exactly `version`, `commit`, `repository`, `workflow`, `run_id`, `run_attempt`. GitHub repository/workflow are fixed public values, run identifiers are positive decimal strings. Build-record fields are exactly `schema_version`, `service`, `reference`, `manifest_digest`, `platform`, `context`, `build_invocation`, `builder`, `sbom`, `provenance`. `sbom` and `provenance` are file descriptors. `build_invocation` and `builder` are validated native identifiers/tool versions, not invented builder facts. The record binds raw evidence hashes; it does not replace native provenance.

- [x] Write tests with explicit assertions: a 16 MiB + 1 byte SBOM or 4 MiB + 1 byte predicate raises before JSON parsing; duplicate keys and a symlink raise; aggregate evidence over 256 MiB raises. `test_sbom_swapped_between_services_rejected` rejects a record/file digest mismatch. `test_source_only_in_supplement_is_insufficient` rejects absent native Git revision even when the build record names it.
- [x] Run `uv run pytest tests/test_supply_chain_evidence.py tests/test_supply_chain_provenance.py tests/test_supply_chain_sbom.py -q`; expect failures.
- [x] Implement bounded streaming/hash checks and per-schema validation. Validate actual Task-1 native SLSA v1 fields: clean intended Git source and Dockerfile in buildDefinition.externalParameters, linux/amd64 in buildDefinition.internalParameters.targetPlatform, resolvedDependencies, runDetails invocation identity and exact history-to-output manifest/config association. Generate CycloneDX 1.7 with patched Trivy from the imported canonical image, checking scanner identity and components; bind service/source/platform/image through the build record. Vendor any schema needed for validation by an immutable upstream revision/hash and include its license; no runtime schema downloads or arbitrary `$ref` network access.
- [x] Add tests proving truncation, over-limit base64, unsupported versions, private-source metadata and credential sentinels block evidence; failures print only safe categories. Do not change Gitleaks exceptions. Re-run focused tests for pass. Review diff; leave uncommitted.

## Task 4: Seal the candidate and restrict artifact contents

**Local checkpoint:** implementation and independent review passed. The covering run passed 121 tests with no skips, including real disclosure and Docker context-filter checks. The transfer contains 14 explicitly selected files and revalidates copied bytes before creating the handoff. Full pinned Linux/amd64 candidate execution remains pending; the Mac host correctly fails the producer preflight. Historical RED output was not saved and is not claimed as verified.

**Files:** create `scripts/releases/supply_chain/manifest.py`, `tests/test_supply_chain_manifest.py`; modify `candidate.py`, `tests/test_release_candidate.py`, `tests/test_release_disclosure.py`.

**Interfaces:** `manifest.write_handoff(images: dict, directory: Path, *, context: dict) -> Path`; `manifest.validate_handoff(document: dict, directory: Path, *, context: dict) -> dict`; `manifest.stage_transfer(document: dict, directory: Path, output: Path) -> list[Path]`. New schema-2 handoff has exactly `schema_version`, `context`, `images`, `checks`; exactly three image entries bind canonical identity/archive descriptor and SBOM/provenance/build-record descriptors. `checks` binds existing validated vulnerability/disclosure/smoke summaries by file hash. Keep legacy schema-1 validation separate.

- [x] Write `test_candidate_builds_once_exports_native_evidence` asserting three builds, no registry writes/OIDC and identical checked/canonical config/diff IDs; `test_transfer_excludes_runtime_configuration` creates a sentinel password in `verification/compose.yaml` and asserts neither that path nor sentinel bytes appear anywhere in staged transfer; `test_mutated_evidence_invalidates_handoff` raises before staging.
- [ ] Run `uv run pytest tests/test_supply_chain_manifest.py tests/test_release_candidate.py tests/test_release_disclosure.py -q`; expect new behavior failures.
- [x] Integrate the proven build flags, canonical archive inspection/import, vulnerability gate, SBOM/provenance validation, disclosure and existing full-stack smoke. Use a fresh owned evidence directory and abort on every generation exception; an older destination file is not evidence of a successful current invocation. Use scratch and transfer directories with separate lifetimes. Keep exactly `service.oci.tar`, `service.sbom.json`, `service.provenance.json`, `service.build-record.json`, validated safe check summaries and `handoff.json` in transfer; explicitly enumerate those files. Revalidate hashes after smoke and before staging. Any failure removes eligibility/handoff, not development resources.
- [x] Re-run focused tests for pass and independently review the local implementation; leave uncommitted.
- [ ] Run one full owned Linux candidate without publication using the pinned toolchain. Expect all original gates and smoke assertions plus sealed evidence to pass.

## Task 5: Publish the unchanged manifests

**Local checkpoint:** implementation and review passed. Publication compares the sealed identity inside the exact upload snapshot, checks every destination before writes, refuses partial retries, and retains findings from a hash-checked summary snapshot. The initial covering run passed 120 tests; the summary-binding fix passed 50 covering tests and scoped re-review. Registry writes were mocked. A dry-run of a fully qualified Linux candidate and real registry transport remain pending.

**Files:** modify `publish.py`, `registry.py`, `tests/test_release_publish.py`, `tests/test_release_registry.py`; extend `supply_chain/manifest.py` and its tests.

**Interfaces:** preserve `publish_candidate(directory: Path, *, version: str, commit: str, dry_run: bool) -> dict`, changing newly produced releases to schema 2; `manifest.validate_release(document: dict, *, version: str, commit: str) -> dict`. The schema-2 release has exactly `schema_version`, `version`, `commit`, `platform`, `images`, `remaining_findings`, `checks_url`, `build_context`. Each image keeps existing identity/reference/tag fields and adds `evidence` with exactly SBOM/provenance/build-record descriptors and expected predicate types. Bundles are transferred separately with signed statement associations; unsigned file descriptors never establish trust.

- [x] Write `test_publish_preserves_captured_manifest_for_both_tags` asserting both tags equal the candidate runnable digest; `test_changed_digest_stops_remaining_writes` asserts later services are untouched; `test_previous_partial_publication_is_not_resumed` refuses occupied state. Preserve moved-tag, error-status and source-ancestry regressions.
- [x] Run focused publisher, registry and manifest tests; observe new transport/schema failures before implementation.
- [x] Replace Docker push with Task-2 preserving copy after complete handoff/source/occupied-tag validation. Check all six tag destinations before any write, then verify each published digest/config/layer/source association. Auth files live in owned temporary directories and are deleted. Record only safe attempted/succeeded operations on failure; never overwrite or delete public state.
- [x] Re-run focused tests and fixture dry-run for pass, assert zero registry mutations, and independently review the diff; leave uncommitted.
- [ ] Dry-run a fully qualified Linux candidate and verify real registry transport in the approved qualification environment.

## Task 6: Sign exact subjects and attach evidence

**Local checkpoint:** implementation and independent review passed. The signer binds all candidate evidence and published identities before signing, retains exact evidence and bounded bundles, and records partial operations without automatic resume. The initial covering run exercised 247 cases, including a separately enabled detector test. A review finding led to strict nested bundle validation; all 63 signing tests then passed and scoped re-review approved the fix. Signing, OIDC and registry boundaries were mocked. A separate pinned Linux/amd64 disposable-key local registry fixture stored and retrieved four typed bundles, verified fixture signatures, and preserved the runnable manifest (see `.superpowers/sdd/supply-chain-plan/task-8-local-registry.md`). Actual tagged GHCR, GitHub OIDC and transparency-log qualification remain pending.

**Files:** create `scripts/releases/supply_chain/signing.py`, `tests/test_supply_chain_signing.py`; extend `commands.py` for bounded Cosign outputs.

**Interfaces:** `signing.sign_release(manifest: dict, directory: Path, *, context: dict, output: Path) -> dict`. Result has schema version 1, guarded context, each service/digest's completed image-signature and three predicate operations, bundle descriptors and a safe operation status. It is an operation receipt, not a substitute for verification.

- [x] Write `test_signer_refuses_source_or_subject_mismatch_before_oidc` asserting zero signing calls; `test_signing_failure_records_partial_operations` asserting no blind resume/cleanup writes; `test_attaching_evidence_does_not_change_manifest` asserts unchanged digest after every service. Verify production commands cannot accept fixture private keys or insecure flags.
- [x] Run focused signing tests and observe missing implementation and malformed-bundle rejection failures before their fixes.
- [x] Revalidate candidate files, guarded context and published identities, then use Cosign v3.1.3 keyless signing for the exact digest plus CycloneDX, native SLSA v1 and custom build-record attestations. Explicitly select the pinned version’s bundle/referrer path (`--new-bundle-format=true` on sign and attest); use full predicate-type URIs to avoid alias normalization, and retain portable bundles and exact raw evidence. Preserve native predicate bytes and validate Cosign's actual emitted wrapper. No application loads, starts or payload script execution in this module/job. Never capture OIDC tokens or raw process errors in output.
- [x] Run focused tests for pass and independently review the implementation and bundle-validation fix; leave uncommitted.
- [x] Exercise real disposable-key signatures against the owned probe registry on the pinned Linux/amd64 toolchain to establish storage, bundle parsing and tamper detection. Keep this fixture-only helper outside production signing policy; generated keys stay temporary. GHCR retrieval and actual OIDC qualification remain Task 9.

## Task 7: Enforce the consumer trust policy before installation

**Local checkpoint:** implementation and scoped review passed. Final covering run: 47 tests, zero skips, including 13 real pinned-Cosign controlled-certificate cases with matching-policy controls. The correct certificate passed; wrong or missing workflow, issuer, SHA, repository, event and ref were rejected. Separate real fixture checks rejected changed payloads, signatures, predicate types and digests. Fixture tests use a temporary authority and bypass log/SCT only within the fixture; actual GitHub OIDC, log and GHCR qualification remain pending. Ambiguous Cosign failures report an explicit nonzero indeterminate outcome.

**Files:** create `scripts/releases/supply_chain/verification.py`, `tests/test_supply_chain_verification.py`; modify `compose.py`, `verify.py`, `__main__.py` and existing release compose/verify tests.

**Interfaces:** `verification.verify_release(manifest: Path, evidence_dir: Path, *, version: str, commit: str, output: Path) -> dict`; `compose.render_verified_compose(manifest: dict, verification: dict) -> str`. The verifier reads, parses and hashes one bounded manifest-file snapshot. Verification result binds version, commit, manifest file hash, all three subjects, exact verified identities/issuer, evidence hashes, tool versions and successful trust checks. Keep validation policy in this helper, not duplicated in workflows.

CLI: `python3 -m scripts.releases verify-release --manifest PATH --version VERSION --commit FULL_SHA --evidence-dir PATH --output-dir PATH [--exercise]`. The command always independently retrieves/verifies registry evidence anonymously; provided local files/bundles are untrusted until checked. `--exercise` starts the existing owned smoke stack only after every signature and predicate passes. Without it, no container starts. The existing schema-1 installation/verification instructions explicitly identify unsigned v0.1.0; schema 2 cannot use that path.

- [x] Write trust-decision tests: valid cryptography with wrong workflow, issuer, commit, event or subject returns nonzero; right JSON/source labels with missing certificate claims also fail. `test_one_unsigned_service_prevents_all_container_starts` asserts zero smoke/Compose output. `test_signed_command_rejects_schema_one` asserts no fallback. `test_missing_log_or_registry_is_not_success` rejects missing/unavailable evidence.
- [x] Run `uv run pytest tests/test_supply_chain_verification.py tests/test_release_compose.py tests/test_release_verify.py -q`; expect new behavior failures.
- [x] Implement exact identity/issuer verification plus required certificate workflow SHA, repository, `push` event and tag ref claims, using the pinned Cosign interface. Validate log inclusion/trust roots and each cryptographically verified attestation's predicate type, fixed package/digest, native source/materials/platform and build-record associations/raw hashes. Reject an unrelated valid signature, swapped files, conflicting duplicates, malformed/tampered bundles and oversized responses. Do not learn trusted constants from the manifest or choose a permissive regex.
- [x] Separate schema-1 and schema-2 render/verify paths. Compose creation follows successful verification of all services and uses the fixed package digests. Production registry operations use an empty Docker config and stripped registry-token environment. Safe failures distinguish policy rejection from unavailable infrastructure; both are nonzero.
- [x] Run focused tests plus real fixture-key cryptographic positive/negative cases; expect pass. Fixture-key successes remain labeled local parser/crypto checks. Review diff; leave uncommitted.

- [ ] Qualify actual GitHub-issued certificates, trust-root/log services and GHCR referrer retrieval through the reviewed tagged release in Task 9.

## Task 8: Connect workflow gates and release assets

**Local checkpoint:** implementation and independent review passed. Focused suite: 107 tests; repository Ruff/format, pinned actionlint and Python 3.12 grammar checks passed. Workflow order, permissions, current-attempt artifact checks, post-download contexts and the 24-file verified draft asset set are implemented. A separate real pinned-Cosign/local-registry fixture stored and anonymously retrieved four typed bundles, verified their fixture-key signatures and preserved the runnable manifest. Hosted workflow, GHCR, OIDC, log and full Linux candidate qualification remain pending.

**Files:** modify `.github/workflows/{ci,release}.yml`, `notes.py`, `tests/test_release_workflow.py`, `tests/test_release_notes.py`; add workflow/source-context regressions to signing/verification tests.

**Interfaces:** workflow order `guard → quality/candidate → publish → sign → verify → draft`. `sign` is a job in top-level `release.yml`, never a reusable workflow. `verify` calls Task-7 CLI without application credentials; Task-9 qualification separately exercises runtime. `notes.create_draft` consumes schema-2 files only after validating this run's successful verification receipt and asset hashes; consumers still perform their own cryptographic verification.

- [x] Write `test_only_signer_has_oidc_permission`, `test_draft_requires_successful_verification`, `test_all_transfers_bind_current_run_and_attempt` and `test_candidate_upload_uses_transfer_allowlist`. Assert a rerun that references an older attempt's artifact is rejected rather than silently reused. Assert failure records contain no token or temporary runtime configuration.
- [x] Run `uv run pytest tests/test_release_workflow.py tests/test_release_notes.py tests/test_supply_chain_signing.py tests/test_supply_chain_verification.py -q`; expect workflow/asset failures.
- [x] Wire permissions exactly: candidate contents-read only; publisher packages-write plus contents/actions-read; signer id-token/packages-write plus contents/actions-read; verifier read-only/no OIDC; notes contents-write/actions-read. Reuse existing full-SHA action pins. Before every download validate artifact ID, producing job, guarded commit and current run/attempt via GitHub artifact/job metadata plus sealed context; never search by artifact name. Upload only the staged allowlist and safe partial-operation records with bounded retention.
- [x] Draft assets include schema-2 `release.json`, verified Compose, raw per-service SBOM/native provenance/build records, portable signature/attestation bundles and a sanitized verification summary. Validate file counts/sizes/hashes and disclosure before each upload. No runnable image archives or test configuration become GitHub Release assets. If publishing, signing or verification fails, draft creation is ineligible.
- [x] Re-run focused tests and pinned actionlint; expect pass. Validate all trusted tag/source/job conditions, Python 3.12 syntax and full-SHA actions. Leave changes uncommitted for the final whole-branch review in Task 9.
- [x] Review the complete branch diff and obtain maintainer instruction before commits, pushes or PR changes.

## Task 9: Document and qualify the actual signed release

**Local checkpoint (2026-11-02):** Local implementation, operator documentation and final review are complete. All 1,370 backend tests, 181 frontend tests and 14 browser tests passed, along with lint, formatting, TypeScript, frontend build, workflow validation and source secret scanning. Review fixes cover dependency-free CLI startup, exact build-input bindings and public native build metadata. A small real pinned BuildKit fixture confirmed the Python material, environment and cache representation. The maintainer authorized one commit and push with CI skipped; a full native candidate and actual tagged Linux/GHCR/OIDC/transparency-log qualification remain pending.

**Files:** modify `README.md`, `docs/releases.md`, `docs/architecture/{releases,supply-chain}.md`, `docs/development/verification.md`; update this plan's checkboxes from observed results only.

- [x] Add operator instructions for explicit expected version/full SHA, installing pinned Cosign, retrieving bounded assets, `verify-release`, direct Cosign verify/verify-attestation equivalents with exact identity/issuer/source claims and OCI-referrer selection, then installation. Explain unsigned v0.1.0 separately, online trust dependencies, public signing metadata, residual vulnerabilities, partial-release recovery and unsupported guarantees.
- [ ] Run `uv run ruff check .`, `uv run ruff format --check .`, and `uv run --env-file .env.example pytest`; expect all checks pass. Run existing frontend checks if frontend files changed. Run the qualified full candidate/security/disclosure/smoke pipeline and fixture crypto negatives. Record actual counts/tool versions, not projected outcomes. Perform a fresh whole-branch review and fix material findings before integration.
- [ ] After explicit commit/push/PR instructions, inspect required GitHub checks. Merge only on maintainer instruction. Prepare a new unused stable version/source for review; request authorization before creating a tag or publishing anything. Never retag v0.1.0.
- [ ] Run the actual tagged workflow: all three signatures and typed attestations must verify on GHCR with the top-level workflow identity and required source claims. If the pinned interface or registry cannot satisfy the policy, record failure and revise the reviewed implementation; do not weaken checks. Confirm image manifests remain unchanged after attachments.
- [ ] With empty registry authentication, retrieve public evidence and run `verify-release ... --exercise` in a fresh owned workspace. Expect all trust checks plus real scan, mock:false, user-image SBOM hash, policy/idempotency and recreation/persistence checks to pass. Confirm owned resources were removed and development data was preserved. Test an intentionally wrong expected commit and tampered evidence; expect nonzero before any installation.
- [ ] Record tag/source/digests, candidate and signing run/attempt, exact identity/issuer, tool versions, predicate/bundle hashes, negative-case results and qualification limitations. Publish the prepared GitHub Release only on explicit instruction after review. Do not claim a second developer verified it without that person's actual result.

## Plan review

Spec coverage maps build identity to Tasks 1–2, native provenance/SBOM/bounds to Task 3, handoff and disclosure to Task 4, publication/recovery to Task 5, signing to Task 6, consumer trust to Task 7, workflow/asset permissions to Task 8 and real qualification/documentation to Task 9. Each task includes failing tests and a passing verification checkpoint. The feasibility probe is a blocking checkpoint, not a promise that the chosen tools are already compatible.

Upstream pins were checked against official [Cosign v3.1.3](https://github.com/sigstore/cosign/releases/tag/v3.1.3), [Buildx v0.38.0](https://github.com/docker/buildx/releases/tag/v0.38.0), [BuildKit v0.34.0](https://github.com/moby/buildkit/releases/tag/v0.34.0) and [Skopeo v1.24.1](https://github.com/podman-container-tools/skopeo/releases/tag/v1.24.1). Cosign's [versioned verification options](https://github.com/sigstore/cosign/blob/v3.1.3/cmd/cosign/cli/options/verify.go) and [certificate options](https://github.com/sigstore/cosign/blob/v3.1.3/cmd/cosign/cli/options/certificate.go) inform the initial interfaces; real fixtures and the tagged workflow establish compatibility.
