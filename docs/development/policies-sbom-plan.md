# Policies and SBOM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for the agreed guided inline execution. Steps use checkbox syntax. Preserve learner checkpoints and learner control of commits; do not implement this whole plan in one turn.

**Goal:** Generate downloadable image SBOMs and save explainable, versioned security-policy evaluations.

**Architecture:** The existing worker collects findings and attempts bounded SBOM generation for the same pinned image. PostgreSQL stores the immutable artifact outcome, policy versions, and evaluations. A pure policy evaluator has no database or network dependencies; persistence and API modules coordinate its inputs and results.

**Tech Stack:** Existing Python 3.14, FastAPI/Pydantic, SQLAlchemy/PostgreSQL, Alembic, Redis/RQ, Trivy 0.75.0, pytest, Ruff, and Compose. Use the standard library for JSON, hashing, and package-URL parsing; no new service is needed.

**Specs:** [SBOM artifacts](../architecture/sboms.md), [security policies](../architecture/policies.md).

## Global constraints

- Continue on `feat/policies-sbom` in the existing VSCode checkout; no additional worktree.
- No changes to existing scan statuses or legacy findings contracts.
- Trivy 0.75.0, CycloneDX 1.7, remote image access, and `linux/amd64` remain explicit.
- Resolve a submitted tag once; findings and SBOM use that same pinned reference.
- SBOM deadline: 60 seconds; stdout: 10485760 bytes; stderr: 65536 bytes. Existing vulnerability deadline: 300 seconds; RQ job timeout: 600 seconds.
- Preserve exact UTF-8 artifact bytes. Store size and SHA-256 over those bytes.
- Successful vulnerability collection survives expected SBOM failures; SBOM failure alone causes no vulnerability retry.
- Final findings/image/artifact outcome are saved in one short completion transaction; external commands stay outside it.
- Policy thresholds are strict integers from 0 through 2147483647. Require all four rules; reject extra fields and coercion.
- Count saved finding occurrences, including repeated CVEs on distinct occurrences.
- Versions and evaluations cannot be overwritten through the API. Evaluate an explicit policy-version UUID; no implicit latest version.
- Missing required artifacts cause rejection; corrupted available artifacts cause evaluation error.
- Database/queue outage responses remain safe; never expose raw diagnostics, URLs, or secrets.
- Reuse existing isolated PostgreSQL/Redis test harnesses. No public-network calls in routine tests and no development-volume cleanup.
- Keep new filenames neutral. Commits, pushes, and PR creation remain explicit learner checkpoints.

## Review focus

1. Root package URLs omit OS: validate repository/digest/amd64 without inventing an OS property; use the verified command/report platform. Task 1 tests this.
2. Unexpected JSON, duplicate properties, or conflicting identities must fail safely without dropping successful findings. Tasks 1 and 4 test this.
3. A 10 MiB limit applies to bytes, not characters or reserialized JSON; listings must not load payloads. Tasks 1, 2, and 5 test this.
4. Simultaneous version creation/evaluation must preserve unique versions and one immutable result. Tasks 6 and 8 use real concurrent database sessions.
5. Legacy scans and corrupted saved artifacts must not accidentally produce a policy pass or a usable download. Tasks 5, 7, and 8 test this.

## File map

| File | Responsibility |
| --- | --- |
| `app/scanning/trivy/sbom.py` | Immutable parsed artifact, identity/structure/byte validation |
| `app/scanning/trivy/sbom_runner.py` | Bounded CycloneDX command and classified outcome |
| `app/scanning/workflow.py` | Attempt generation after successful findings collection |
| `app/persistence/models.py` | Four new database models and constraints |
| `app/persistence/artifacts.py` | Artifact insertion, metadata lookup, integrity verification |
| `app/persistence/policies.py` | Policy/version creation and pagination |
| `app/persistence/evaluations.py` | Load evidence, evaluate, conflict-safe insert, list results |
| `app/persistence/repository.py` | Extend existing atomic scan completion to include artifact outcome |
| `app/policies/schemas.py` | Strict rules, policy/evaluation requests and response types |
| `app/policies/evaluator.py` | Pure rule evaluation and explanations |
| `app/api/sbom_schemas.py` | Artifact metadata response types |
| `app/api/sboms.py` | Artifact metadata/download routes |
| `app/api/policies.py` | Policy/version routes |
| `app/api/evaluations.py` | Evaluation routes |
| `app/main.py` | Register the new routers; preserve existing endpoints |
| `migrations/versions/0002_sbom_artifacts.py` | Artifact table migration |
| `migrations/versions/0003_policy_evaluations.py` | Policy/version/evaluation migration |
| `tests/test_sbom_*.py` | Validation, storage, runner, workflow, and HTTP tests |
| `tests/test_policy_*.py` | Strict rules, evaluator, database concurrency, and HTTP tests |
| `tests/fixtures/trivy/cyclonedx.json` | Small representative Trivy 0.75.0 fixture |

Existing models/repository remain in place; new feature persistence gets focused
modules. Do not split unrelated code just to rearrange the repository.

## Shared verification commands

At execution setup, start only the dedicated test services:

```bash
docker compose --env-file .env.example --profile test up -d --wait test-db test-redis
```

Expected: both dedicated services healthy. Use `.env` consistently instead if
that is the learner's configured file; its test targets must remain separate.

After each checkpoint, run the focused tests below, then:

```bash
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked --env-file .env.example pytest
```

Expected: lint/format exit 0, full suite passes. Do not silently skip a failed
command because a later command succeeded. Test totals grow during execution;
record actual totals rather than prescribing a number.

## Task 1: Validate an SBOM without services

**Files:** Create `app/scanning/trivy/sbom.py`, `tests/test_sbom_parser.py`, and
`tests/fixtures/trivy/cyclonedx.json`; extend the fixture README.

**Interfaces produced:**
- Frozen `ParsedSbom(payload: bytes, format: str, format_version: str,
  scanner_version: str, pinned_reference: str, platform: str,
  size_bytes: int, sha256: str)`.
- `parse_sbom(payload: bytes, *, pinned_reference: str, platform: str,
  scanner_version: str) -> ParsedSbom`; invalid input raises `ValueError`.
- Frozen `SbomOutcome(artifact: ParsedSbom | None, error_code: str | None)`
  in the same module; exactly one field is present. This transport type has no
  database dependency and is shared by generation and persistence.
- `MAX_SBOM_BYTES = 10485760`.

- [x] Write parser tests first. A representative test must assert:

  ```python
  artifact = parse_sbom(
      payload, pinned_reference=pinned, platform="linux/amd64", scanner_version="0.75.0"
  )
  assert artifact.payload == payload
  assert artifact.size_bytes == len(payload)
  assert artifact.sha256 == hashlib.sha256(payload).hexdigest()
  assert artifact.format_version == "1.7"
  ```

  Add named cases for exact-size success and one-byte-over failure using JSON
  whitespace padding; non-ASCII byte accounting; malformed/deep JSON; duplicate
  JSON keys; NaN/Infinity; wrong format/tool version; missing metadata; wrong
  digest/repository/architecture; conflicting RepoDigest properties; empty
  inventory success; malformed components. Parameterize Docker Hub aliases
  `docker.io`, `index.docker.io`, and `registry-1.docker.io` as one registry.
  A valid root purl without OS must succeed, not fail for an absent OS field.
- [x] Run `uv run --locked pytest tests/test_sbom_parser.py -q`.
  Expected: RED because the new parser/interface is absent, not because of an
  unrelated fixture or test setup error.
- [x] Implement the interface with strict JSON decoding and semantic identity
  comparison. Preserve bytes; normalize only identity comparisons. Reject
  recursive/unusable structures with safe ValueError. Do not claim full schema
  validation or parse references by loose substring matching.
- [x] Repeat the focused command. Expected: all parser cases pass. Run shared
  lint/format/full checks. Explain checksum versus completeness to the learner.
- [ ] Learner checkpoint. Suggested commit: `Validate bounded CycloneDX artifacts`.

## Task 2: Store artifact outcomes

**Files:** Modify `app/persistence/models.py`; create `app/persistence/artifacts.py`,
`migrations/versions/0002_sbom_artifacts.py`, and `tests/test_sbom_storage.py`;
extend `tests/test_migrations.py`.

**Interfaces:** Consume Task1's ParsedSbom/SbomOutcome and add `SbomArtifact` ORM
model. Safe codes are `sbom_timeout`,
`sbom_unavailable`, `sbom_execution_failed`, `sbom_output_limit`, and
`sbom_invalid_report`, mapped to fixed public messages in the artifact module.
`add_sbom_outcome(session: Session, scan_id: UUID, outcome: SbomOutcome) -> None`
adds/flushes in its caller's transaction and never commits on its own.

- [x] Write real-PostgreSQL tests asserting byte-identical readback/checksum,
  available/failed row invariants, unique scan association, foreign key validity,
  exact 10 MiB acceptance, oversized rejection, and caller rollback removing the
  inserted artifact. Add migration tests preserving an existing scan/findings
  across the upgrade and confirming old scans receive no fabricated artifact.
- [x] Run `uv run --locked --env-file .env.example pytest tests/test_sbom_storage.py tests/test_migrations.py -q`.
  Expected: RED for missing model/migration/interfaces.
- [x] Implement the model/migration and insertion helper. Store payload with
  SQLAlchemy LargeBinary/PostgreSQL bytea, deferred by default. Enforce
  available/failed consistency, checksum shape, and octet_length/size agreement
  in database constraints. Failed rows have null payload/checksum/size; safe
  format/reference metadata can be nullable when generation failed. Index the
  unique scan association; timestamp is timezone-aware.
- [x] Repeat focused tests and shared checks. Expected: GREEN with old data
  preserved. Do not migrate the development DB until this isolated check passes.
- [ ] Learner checkpoint: apply `uv run --env-file .env.example alembic upgrade head`.
  Expected: revision 0002 applied without resetting history. Suggested commit:
  `Persist scan-associated SBOM outcomes`.

## Task 3: Generate CycloneDX with bounded execution

**Files:** Create `app/scanning/trivy/sbom_runner.py` and `tests/test_sbom_runner.py`.

**Interfaces consumed:** Tasks 1–2 types and the existing `run_bounded_command`.
**Produced:** `build_sbom_command(pinned_reference: str) -> list[str]` and
`collect_sbom(pinned_reference: str, *, platform: str, scanner_version: str) -> SbomOutcome`.

- [x] Write command assertions for remote source, platform `linux/amd64`, format
  `cyclonedx`, timeout `60s`, argument separator, and exact pinned reference.
  Confirm no tag resolution or vulnerability scanner option is added. Stub the
  process runner and assert invocation bounds 60/10485760/65536. Test success
  preserves UTF-8 bytes. Map each existing ProcessExecutionError code to the
  fixed SBOM code; invalid output/parser failures map to sbom_invalid_report.
- [x] Run `uv run --locked pytest tests/test_sbom_runner.py -q`.
  Expected: RED for absent runner functions.
- [x] Implement using existing pinned-reference validation without relaxing its
  registry/digest restrictions. Classified generation/validation failures return
  a failed outcome; programming and database errors are not broadly swallowed.
- [x] Repeat focused/shared checks. Expected: GREEN. Explain that another Trivy
  invocation still uses the same image identity rather than resolving the tag.
- [ ] Learner checkpoint. Suggested commit: `Generate SBOMs with bounded Trivy execution`.

## Task 4: Preserve findings when generation fails

**Files:** Modify `app/scanning/workflow.py` and `app/persistence/repository.py`;
create `tests/test_sbom_workflow.py`; update existing workflow/queued/retry/job
fixtures that would otherwise launch a real SBOM command.

**Interfaces:** Extend `TrivyResult` with `sbom_outcome: SbomOutcome | None = None`.
Real `collect_trivy_result` always supplies it after successful findings parsing.
Extend `complete_trivy_scan` with keyword-only
`sbom_outcome: SbomOutcome | None = None`; None permits existing direct repository
fixtures/legacy callers, not the real collector's new scan path.

- [x] Write tests asserting the resolver runs once, generation receives exactly
  the findings' pinned digest/platform/tool version, and vulnerability failure
  never calls generation. For every classified SBOM failure, assert scan
  completed, findings retained, failed artifact saved, and no retry requested.
  Assert successful findings/image/artifact commit atomically and artifact-write
  failure rolls back all completion writes. Confirm redelivery cannot replace a
  terminal artifact. Add a test that real collection never returns None outcome.
- [x] Run `uv run --locked --env-file .env.example pytest tests/test_sbom_workflow.py tests/test_scan_completion.py tests/test_scan_retry_workflow.py -q`.
  Expected: RED because generation/outcome integration is absent.
- [x] Wire collection after validated findings, outside the completion transaction.
  Insert its outcome through Task 2's helper in the existing transaction. Keep
  scan and queue lifecycle guards; log only safe SBOM outcome/code fields.
- [x] Repeat focused/shared checks. Expected: GREEN with no scanner/network calls
  in routine tests. Add assertions that existing mocked collectors stay mocked.
- [ ] Learner checkpoint: rebuild worker, submit a real scan, inspect completed
  findings and its stored artifact outcome. Expected: completed and available;
  record identity and checksum without assuming a fixed vulnerability count.
  Suggested commit: `Save SBOM outcomes with completed scans`.

## Task 5: Download saved artifacts

**Files:** Create `app/api/sbom_schemas.py`, `app/api/sboms.py`, and
`tests/test_sbom_api.py`; extend `app/persistence/artifacts.py` and register its
router in `app/main.py`.

**Interfaces:** `get_sbom_metadata(session: Session, scan_id: UUID) -> SbomMetadata | None`;
`load_verified_sbom(session: Session, scan_id: UUID) -> ParsedSbom`.
Use typed missing/not-ready/integrity exceptions mapped by the router.

- [x] Test both spec endpoints and all states: missing scan 404, queued/running
  metadata pending and download409, failed/legacy not_generated and download404,
  failed artifact metadata explaining failure and download404, available download
  identical to original bytes with quoted SHA-256 ETag and UUID-only attachment
  filename. Tampered checksum/size/identity must return safe500 without bytes.
  Database failure returns safe503. Assert metadata queries and scan history do
  not select payload columns using SQL capture, not timing guesses.
- [x] Run `uv run --locked --env-file .env.example pytest tests/test_sbom_api.py -q`.
  Expected: RED for missing endpoints/helpers.
- [x] Implement metadata without loading payload; verify a bounded artifact on
  download using Task1 validation plus saved size/checksum/scan image comparison.
  Return original bytes with application/json. Do not implement backfill/update.
- [x] Repeat focused/shared checks. Expected: GREEN. Learner downloads one real
  artifact and confirms its checksum; recreate application containers and retrieve
  the same bytes again. Expected: matching checksum and retained artifact.
- [x] Learner checkpoint. Suggested commit: `Expose SBOM metadata and downloads`.

## Task 6: Strict policies and immutable versions

**Files:** Create `app/policies/__init__.py`, `app/policies/schemas.py`,
`app/persistence/policies.py`, `app/api/policies.py`, `tests/test_policy_schemas.py`,
`tests/test_policy_versions.py`, and `tests/test_policy_api.py`. Modify models/main;
create `migrations/versions/0003_policy_evaluations.py` including Task8's evaluation
model/table so this migration is complete before any production evaluation write.

**Interfaces:** `PolicyRules(max_critical: int, max_high: int, require_sbom: bool,
unknown_severity_action: Literal['fail','ignore'])`; `PolicyCreate(name: str,
rules: PolicyRules)`; `PolicyVersionCreate(rules: PolicyRules)`.
Persistence produces `create_policy(session: Session, name: str, rules: PolicyRules) -> PolicyVersionRecord`
and `create_policy_version(session: Session, policy_id: UUID, rules: PolicyRules) -> PolicyVersionRecord`.
Record types include UUIDs, version number, rules, and timestamps. List functions
`list_policies` and `list_policy_versions` accept keyword-only limit/offset and
return the existing page shape; order policies by created_at/id descending and
versions by version_number descending. Missing parent is a typed not-found error.

- [x] Test strict rules: each missing/extra field, bool/string/fraction/negative
  thresholds, 2147483647 accepted and 2147483648 rejected, strict boolean, actions,
  trimmed name length1/100 versus0/101, case-sensitive uniqueness. API tests cover
  the four spec routes, 201/404/409/422/503, stable pagination, no update routes.
  Database tests assert atomic policy/version1 creation, parent existence,
  concurrent allocations yielding distinct consecutive versions, old rules
  unchanged after new version, and rollback without orphan records.
- [x] Run `uv run --locked --env-file .env.example pytest tests/test_policy_schemas.py tests/test_policy_versions.py tests/test_policy_api.py tests/test_migrations.py -q`.
  Expected: RED for absent schema/persistence/routes/models.
- [x] Implement validated types, Policy/PolicyVersion/Evaluation ORM tables and
  migration, parent-row locking for next version, and uniqueness/check/FK/index
  constraints. Include evaluation status checks, immutable-result unique pair,
  RESTRICT scan/version references, JSON counts/explanations/rule snapshot, safe
  nullable error details, evaluator version, and timezone-aware timestamp.
  Evaluation insert/read behavior belongs to Task8. Policy creation owns its
  transaction; internal helpers must not open nested implicit transactions.
- [x] Repeat focused/shared checks; migrate development only after isolated tests
  pass. Expected: old scans/artifacts preserved. Learner creates version1 and
  version2 through API docs and retrieves both unchanged.
- [x] Learner checkpoint. Suggested commit: `Add strict policies and immutable versions`.

## Task 7: Pure, explainable evaluation

**Files:** Create `app/policies/evaluator.py` and `tests/test_policy_evaluator.py`;
extend policy response types in `app/policies/schemas.py`.

**Interfaces:** frozen `EvaluationEvidence(counts: dict[Severity, int],
sbom_available: bool)`; `evaluate_policy(rules: PolicyRules, evidence: EvaluationEvidence) -> PolicyDecision`.
PolicyDecision retains all five normalized counts, has passed/failed outcome,
and exactly four RuleExplanation records
with rule_id, passed, actual, expected, reason. Stable IDs match the four rule
names; evaluator version is the constant `1`.

- [x] Write a boundary matrix: thresholds0/5 and actual below/at/above, combined
  failures with all explanations retained, UNKNOWN0/1 crossed with fail/ignore,
  required/optional SBOM crossed with available/missing, and nonzero MEDIUM/LOW
  that remain visible without rejecting. Representative assertions:

  ```python
  assert evaluate_policy(rules_max_high_5, evidence_high_5).outcome == "passed"
  rejected = evaluate_policy(rules_max_high_5, evidence_high_6)
  assert rejected.outcome == "failed"
  assert next(r for r in rejected.rules if r.rule_id == "max_high").actual == 6
  ```

  Missing severity keys normalize to zero; reject unknown keys, bool/noninteger/
  negative counts as invalid evidence. Tests must need neither DB nor network.
- [x] Run `uv run --locked pytest tests/test_policy_evaluator.py -q`.
  Expected: RED for missing evaluator/types.
- [x] Implement the pure function with fixed explanatory text and all five
  counts retained. Optional/ignored rules pass with explicit explanations.
- [x] Repeat focused/shared checks. Expected: GREEN. Explain why a test expecting
  policy rejection passes when the evaluator correctly returns failed.
- [x] Learner checkpoint. Suggested commit: `Evaluate security rules with clear explanations`.

## Task 8: Save evaluations and expose them

**Files:** Create `app/persistence/evaluations.py`, `app/api/evaluations.py`,
`tests/test_policy_evaluations.py`, and `tests/test_policy_evaluation_api.py`;
extend schemas/main as needed.

**Interfaces:** `EvaluationRequest(policy_version_id: UUID)`;
`evaluate_scan(session: Session, scan_id: UUID, policy_version_id: UUID) -> EvaluationRecord`;
`list_evaluations(session: Session, scan_id: UUID, *, limit: int, offset: int) -> EvaluationPage`.
EvaluationRecord exposes IDs/version number/rule snapshot/evaluator version,
outcome/counts/reasons/timestamp and nullable safe error. Order lists by timestamp
and UUID descending. Use typed missing/ineligible exceptions, not unsafe strings.

- [x] Test completed real scans with and without artifacts, repeated CVEs on two
  occurrences counted twice, legacy mock rejection, missing scan/version404,
  queued/running/failed409 with no evaluation row, corrupted artifact producing
  error with safe `invalid_evidence`, and safe DB503. First/duplicate POST returns
  200; list uses standard pagination. A pair of concurrent sessions must return
  one result UUID and leave one row. Creating version2 must leave version1's
  result byte-for-byte unchanged. Saved error results are duplicate-safe too.
- [x] Run `uv run --locked --env-file .env.example pytest tests/test_policy_evaluations.py tests/test_policy_evaluation_api.py -q`.
  Expected: RED for missing service/routes.
- [x] Load fixed completed-scan evidence, aggregate saved findings by severity
  in SQL, verify available artifact integrity, and call Task7. Insert using
  PostgreSQL ON CONFLICT DO NOTHING, then read the stored winner. Never update
  the existing evaluation. Persist fixed error outcomes for unusable evidence;
  DB failures propagate to safe503 rather than fabricating a saved result.
  Do not load all findings into Python or return artifact bytes in evaluations.
- [x] Repeat focused/shared checks. Expected: GREEN. Learner evaluates one scan
  against an explicit version, repeats it, and verifies the same evaluation ID.
- [x] Learner checkpoint verified duplicate evaluation identity. Suggested commit: `Persist versioned scan policy evaluations`. Commit remains learner-led.

## Task 9: Integrated verification and documentation

**Files:** Update README and architecture notes; update container/recovery fixture
coverage only where artifact invariants require it. No frontend or release scope.

- [x] Run shared full checks and build both images. Expected: all checks pass;
  API image still has no Trivy and worker reports 0.75.0. Apply upgrades through
  the documented stopped-application migration sequence.
- [x] In containers, scan a real image, retrieve findings and SBOM, compare
  checksum/digest/platform/tool version, and repeat after recreation. Expected:
  unchanged bytes and same scan association, mock false.
- [x] Use controlled SBOM failure fixtures to verify completed findings survive
  and required-SBOM policy fails while optional-SBOM policy may pass. Expected:
  correct separate statuses and no extra vulnerability retries.
- [x] Show one policy pass and one rejection with the determining explanations,
  then create a stricter version and confirm the old evaluation is unchanged.
  Choose demonstration thresholds from observed counts; do not hardcode live
  vulnerability counts into tests or promise a scan is secure.
- [x] Exercise the new models/migrations/API in an isolated disposable stack and
  confirm recovery/retained history still works. Expected: artifacts cannot be
  overwritten by a duplicate/recovered terminal scan; only disposable resources
  are removed. Record actual scan identity/tool/date/environment and results.
- [x] Update docs from proposed to implemented only after the relevant checks.
  Explain per-file versus total storage, separate SBOM failures, immutable
  versions, occurrence counting, strict eligibility, error versus rejection,
  no backfill, and checksum limits. Expected: commands reflect actual behavior.
- [x] Use the requesting-code-review skill for a fresh independent whole-branch
  review. Resolve important findings with focused tests and rerun affected checks.
  Expected: no unresolved important defects; report limitations honestly.
- [ ] Learner reviews final scope, commits, and pushes. Open PR only when requested;
  wait for passing CI before merge. Expected: documented evidence matches shipped
  behavior, no secrets/reports/cache files in the commit.

## Execution handoff

The design summary was approved before this plan was written. The established
method is guided inline execution in the current checkout, with learner-run
checkpoint commands and explanations. Review this written plan before execution;
then start Task1 only. Tasks 1–8 have been implemented and verified at learner checkpoints. Final
integrated checks and documentation are recorded under Task 9; commits and the
pull request remain learner-led.
