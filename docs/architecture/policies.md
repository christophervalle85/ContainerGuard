# Security policies

Status: implemented and verified through the API and a disposable Compose stack.

ContainerGuard evaluates saved vulnerability findings against a named,
versioned policy and explain each decision. An evaluation describes one completed
scan under one explicit policy version. It is not permission to deploy an image
and does not establish that an image is secure.

## Agreed behavior

- Policies have stable identities and immutable versions. Changing rules creates
  a new version rather than changing old evaluations.
- Thresholds count saved finding occurrences, not distinct CVE IDs. The same CVE
  on two distinct package occurrences counts twice.
- Counts equal to a maximum pass that rule; counts above it fail.
- A missing required SBOM fails its rule. UNKNOWN severity behavior is explicit.
- Failed, queued, and running scans cannot pass policy evaluation.
- Repeating evaluation for the same scan/version returns the existing result.
- Evaluation processing errors remain distinct from policy rejection.

## Policy definition

The initial rules are deliberately limited:

```json
{
  "max_critical": 0,
  "max_high": 5,
  "require_sbom": true,
  "unknown_severity_action": "fail"
}
```

All four fields are required. Thresholds are strict integers from 0 through
2147483647; booleans, fractional values, numeric strings, and negative values
are rejected. `require_sbom` is a strict boolean. UNKNOWN action accepts only
`fail` or `ignore`. Unexpected fields are rejected so misspelled rules cannot
silently disappear. Names are trimmed, case-sensitive, nonempty strings up to
100 characters, unique across policies.

MEDIUM and LOW findings are counted and reported but have no threshold in this
initial version. UNKNOWN is always counted; `ignore` means it does not reject
an evaluation. No exception lists, arbitrary expressions, YAML upload, or policy
language interpreter is included.

## Persistence

Three new records serve separate purposes:

- `policies`: UUID, unique name, creation timestamp.
- `policy_versions`: UUID, policy UUID, positive version number, creation
  timestamp, and explicit columns for the four validated rules.
- `evaluations`: UUID, scan UUID, policy-version UUID, timestamp, evaluator
  version, outcome, severity counts, rule explanations, and safe error details.

Creation inserts a policy and its first version in one transaction. New version
allocation locks the parent policy row; `(policy_id, version_number)` is unique.
Versions cannot be edited or deleted through the API. Evaluation references use
RESTRICT semantics to protect history. Foreign-key lookups have supporting
indexes; existing composite unique indexes can supply their leading-column
lookup without redundant indexes.

`(scan_id, policy_version_id)` is unique. Concurrent evaluation uses a database
conflict-safe insert that preserves the winner, never overwriting its result.
Both callers receive that persisted result. The version and saved scan evidence
are fixed inputs; evaluation performs no external scanner or registry requests.
Rule explanations are a bounded JSON list with stable rule IDs, pass/fail,
actual value, expected value, and a clear reason. Counts include all five
severities. Completed scans with zero findings are valid inputs.

## Evaluation lifecycle and errors

New evaluations accept completed real Trivy scans with a saved image identity.
Legacy fictional scans are rejected rather than presented as real evidence.
Missing scans or policy versions return 404. Ineligible scan state returns 409
without inserting an evaluation. Invalid requests return 422.

The evaluator computes CRITICAL and HIGH threshold rules, required-SBOM presence,
and UNKNOWN behavior. Every applicable rule receives an explanation; it does
not stop at the first rejection. A disabled SBOM requirement or ignored UNKNOWN
rule still has an explanation. Outcome is `passed` only if all rules pass;
otherwise it is `failed`.

Scan reference, platform, and scanner version are checked even if the policy
does not require an SBOM. Valid older Trivy versions remain eligible when no
artifact is required. Unusable persisted evidence, such as a malformed scan
identity or an artifact checksum mismatch,
produces `error` with a fixed safe code rather than pretending it is a policy
rejection. The evaluation stores no raw SQL, scanner diagnostics, or connection
URLs. A database outage returns the existing safe 503 convention; if no record
was committed, a later request may try again. Once a result is saved, including
an error result, duplicate evaluation returns that result. There is no force
reevaluation endpoint in this version.

Artifacts and evaluation inputs become final when the scan completes. No SBOM
backfill or result replacement endpoint is included, so an old evaluation cannot
change because evidence is added later. A fresh scan is the way to collect new
evidence. Future reevaluation/backfill would need an explicit evidence-version
contract rather than relaxing this guarantee silently.

## API additions

Paths are under `/api/v1`:

| Method | Path | Behavior |
| --- | --- | --- |
| POST | `/policies` | Create a named policy and version 1 from explicit rules |
| GET | `/policies` | Paginated policy list |
| GET | `/policies/{policy_id}/versions` | Paginated immutable version history |
| POST | `/policies/{policy_id}/versions` | Create a new version from explicit rules |
| POST | `/scans/{scan_id}/evaluations` | Evaluate the supplied policy-version UUID |
| GET | `/scans/{scan_id}/evaluations` | Paginated saved results, including explanations |

Create requests return 201. Evaluation returns 200 for both first and duplicate
requests, allowing one response contract. Duplicate policy names return 409.
Lists use existing `items`, `total`, `limit`, and `offset` conventions with stable
ordering. Evaluation responses expose scan ID, policy ID/version ID/number,
policy rule snapshot, evaluator version, outcome, counts, reasons, and timestamp.
No implicit latest-policy selection is allowed during evaluation.

## Code boundaries and verification

`app/policies/` contains validated policy types and a pure evaluator. Persistence
and HTTP wiring stay outside that evaluator. Keep artifact generation and
validation under `app/scanning/trivy/` and artifact persistence/download separate
from policy logic. Existing persistence/API files may be split by responsibility
when adding these features, without unrelated reorganizations.

Tests cover below/at/above thresholds, repeated CVEs, every severity including
UNKNOWN, missing/failed/available SBOM, invalid rules, ineligible scans, and safe
error outcomes. PostgreSQL tests cover immutable history, concurrent version
allocation, concurrent duplicate evaluation, rollback, and migration of existing
scan data. API tests verify validation, status codes, pagination, and rule-level
responses. Live demonstrations show one pass and one rejection with reasons;
fixture tests do not depend on live vulnerability counts.

Implementation was completed through learner checkpoints: artifact model/validation,
bounded generation, persistence/download, policies/versioning, pure evaluation,
then evaluation persistence/API and end-to-end evidence. Each checkpoint included
focused tests and an explanation before proceeding. Commits remain learner-led.
See [SBOM artifacts](sboms.md) for the artifact half of the design.
