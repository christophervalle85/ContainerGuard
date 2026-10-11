# Local verification record

These observations were recorded on October 11, 2026, on Apple Silicon with
Docker Desktop. They describe this branch's local behavior, not a guarantee about
future vulnerability databases or production capacity.

## Scope and remaining work

An isolated source-only snapshot included the pending tracked and new branch
files, excluding Git metadata, local environments, ignored credentials, and
caches. All three linux/amd64 runtime images built from that snapshot. A separate
Compose project used fresh PostgreSQL, Redis, and Trivy cache volumes and ports
18080/18000/15433/16380. Development containers and volumes were not reused.
Application recreation preserved downloaded SBOM bytes.

This was an **uncommitted source snapshot**, not a committed fresh checkout.
After committing and pushing, repeat the setup from a clean clone and record the
GitHub run links. The new security jobs, Linux installer as a whole, and controlled
red CI demonstrations have not yet run on GitHub. No second developer has tried
this setup. Local gates and negative tests do not establish those remaining facts.

## Checks

- Backend lint and formatting passed. The final complete suite passed 825 tests.
- Frontend lint, formatting, types, build, 181 unit tests, and 14 browser tests passed.
  Browser regression tests use intercepted fixture responses.
- A separate real browser session navigated actual saved findings, downloaded the
  SBOM, submitted an evaluation of an explicit version, and viewed both policy
  versions. Its screenshots are under `docs/images/`.
- Gate/runner tests exercise clean, blocked, absent, malformed, wrong-target,
  timed-out, unsuccessful, and stale reports, plus invalid/expired exceptions.
  Installer tests reject unsupported platforms and a corrupted archive before
  installing a binary. Fake scanners are deliberately fictional.
- A real redacted Gitleaks 8.30.1 history scan found no secrets in the 16 reachable
  commits at the branch base. A separate scan of the pending source-only snapshot
  also found no leaks. A temporary repository containing a synthetic token
  triggered detection without printing the token. Pending changes become part of
  reachable history only after commit; CI must scan that commit again.
- Native ARM64 API/worker builds succeeded; worker imports and the patched scanner's
  version command passed. The full runtime exercise used linux/amd64 images under
  emulation, matching the CI image platform.

Run the commands in the [README](../../README.md#run-the-checks) to repeat checks.
Tests use dedicated PostgreSQL/Redis services and disposable schemas/queues.

## Vulnerability gate and remediation

The initial Debian 12 runtime scan reported 69 blocking API findings and 73
blocking worker findings. The frontend had one blocking finding. A Debian 13
trial still had 52 HIGH findings. The threshold remained HIGH/CRITICAL, including
unfixed findings. No exceptions were added.

The selected images use pinned Alpine Python, omit runtime pip, and rebuild
Trivy 0.75.0 from checksum-pinned source with Go 1.27.2 and x/net 0.60.0. The
patched binary identifies itself as `0.75.0+cg.1`. Nginx's TIFF/zlib runtime
packages are updated during build. This introduces downstream scanner maintenance;
see [containers](../architecture/containers.md#resource-bounds-and-scanner-maintenance).

Final local linux/amd64 image scans with host Trivy 0.75.0 and a refreshed database:

| Target | HIGH / CRITICAL | Other findings | Result |
| --- | --- | --- | --- |
| API | 0 / 0 | zlib CVE-2026-85091, MEDIUM; fix 1.3.2-r1 | Pass |
| Worker | 0 / 0 | same zlib MEDIUM; x/crypto GO-2026-5932 UNKNOWN, no listed fix | Pass |
| Frontend | 0 / 0 | None reported | Pass |
| Both lockfiles | 0 / 0 | None reported | Pass |

The lockfile scan recognized 38 uv packages and 263 npm packages, including
development dependencies. The local runner accepts reviewed upstream 0.75.0 and
patched 0.75.0+cg.1; CI installs the patched build exported from Dockerfile.worker.
A passing threshold is not a vulnerability-free assertion. UNKNOWN remains visible.
Builder stages and PostgreSQL/Redis images are outside this runtime gate.

## Real scan, artifact, and policies

The disposable stack scanned `docker.io/library/alpine:3.20.0`, resolved to:

```text
sha256:216266c86fc4dcef5619930bd394245824c2af52fd21ba7c6fa0e618657d4c3b
```

Scan `e101c6fe-e0fa-49f8-8887-250b34841da3` completed with `mock: false`,
platform linux/amd64 and scanner 0.75.0+cg.1. It recorded 70 occurrences:
2 CRITICAL, 21 HIGH, 20 MEDIUM, 27 LOW, and 0 UNKNOWN. Vulnerability database
UpdatedAt was `2026-10-11T13:06:05.155544028Z`.

Its available CycloneDX 1.7 artifact was 25,487 bytes. Downloaded bytes matched
saved SHA-256 `aee4165b4af66eee2328a0bede775a794569b97be9b538d40241aecf62182f3f`,
including after API/worker/frontend recreation. The real browser download was
checked separately. These IDs identify disposable evidence, not records expected
in another developer's installation; timestamps and hashes vary on new scans.

A permissive demonstration policy version (max critical/high 1000, required SBOM,
unknown severity fails) passed. A new version with both maxima zero failed with
explained critical/high count breaches. Repeating the original evaluation returned
the same saved ID, timestamp, and rule snapshot. The deliberately permissive
version demonstrates versioning; it is not a recommended release policy.

![Real findings](../images/scan-findings.png)
![Real SBOM metadata and download](../images/scan-sbom.png)
![Real evaluation rules](../images/policy-evaluation.png)
![Immutable versions](../images/policy-versions.png)

## Resource and failure observations

Docker HostConfig confirmed the CPU/memory/PID limits in
[containers](../architecture/containers.md#resource-bounds-and-scanner-maintenance).
Redis reported maxmemory 134217728 bytes and noeviction. A fresh-cache real scan
ran from 19:01:44.601 UTC to 19:01:54.515 UTC, including a database download.
Five samples taken during submission/processing observed these maxima:

| Service | Sampled memory maximum | Sampled CPU maximum |
| --- | ---: | ---: |
| API | 103.5 MiB | 0.24% |
| Worker | 274.5 MiB | 100.89% |
| Redis | 12.34 MiB | 0.98% |
| Frontend | 25.32 MiB | 1.12% |

Docker CPU percentages use one logical core as 100%. Sampling can miss peaks;
these values are not minimum requirements or load-test results. Docker/network
caches and the small submitted image affect elapsed time and resource use.

With only the disposable worker stopped, temporarily setting that Redis service's
maxmemory to one byte made submission return 503 with `Scan queue temporarily
unavailable`. The configured limit was restored before restarting the worker.
Integration tests separately check that known enqueue failures save failed state.
No memory limit was changed on the development or shared test Redis services.

Real PostgreSQL concurrency tests cover the last-slot race and lock timeout.
Retries, recovery, interrupted enqueue gaps, terminal capacity release, invalid
startup configuration, safe 422/429 responses, and actual RQ stored tracebacks/logs
have targeted coverage. No live job was killed to manufacture interruption.

## Repeating isolated setup

Use a clean clone after the branch is committed. Copy `.env.example` to a local
verification env file, choose a unique Compose project, and change all published
ports. Update host database/Redis URLs to match; container URLs still use db/redis.
From that clone:

```bash
docker compose --env-file .env.verify -p containerguard-verify up -d --build
docker compose --env-file .env.verify -p containerguard-verify ps -a
```

Follow [the demo](../demo.md), then recreate application containers and repeat the
SBOM download/checksum comparison. Record your commit, versions, results, and CI
links. Remove only this verification project's resources afterward:

```bash
docker compose --env-file .env.verify -p containerguard-verify down --volumes
```

That last command deletes the verification project's saved scans and cache. Never
run it with the normal development project name when you intend to retain data.

## Independent review

The final independent review inspected tracked changes and new untracked files
against base `c4c597900f9ec8756faa9434c5aae1af1d385552`. It found one Important
issue: standalone security scripts initially used Python 3.14-only exception
syntax, while Ubuntu 24.04 CI invokes Python 3.12. A failing grammar regression
reproduced it; parenthesized exception tuples and a per-file Ruff target fixed it.
The reviewer independently checked the repair. No Critical, Important, or Minor
issues remain from that review. The reviewer did not independently rerun the
service-backed suites or image builds.

The executor accepted these explicit review boundaries, with no deferred code fixes:

- Public deployment/authentication/authorization stay outside this localhost work.
- Distributed execution limits stay outside the supported one-worker deployment.
- Automatic reconciliation and transactional outbox delivery remain future work;
  the documented enqueue gap and manual recovery remain.
- Exactly-once execution is not promised.
- Historical database/AOF/cache/layer disk growth remains an operator responsibility.
- Builder stages and database/Redis service images remain outside the runtime gate.
- LOW/MEDIUM/UNKNOWN remain visible; only HIGH/CRITICAL block this approved gate.
- Complete sandbox isolation and safety of every submitted image are not claimed.
- Signing, provenance, publication, and independently reproducible scanner binaries
  remain deferred; the current downstream build has an ongoing maintenance cost.
- Deliberate contributor changes to CI or exceptions require repository review.
- Broad accessibility certification, load capacity, and large-image sizing are not
  established by targeted browser checks and a sampled small-image run.

Other execution decisions: retain the existing checkout and leave commits/pushes
to the learner; keep synthetic gate reports in test builders rather than duplicate
JSON fixtures; enforce the configured scanner deadline without an extra grace
period. Full Linux installer execution remains pending CI: automatic approval
review rejected a proposed tool-container test that mounted the host Docker
socket because of the broader daemon control it would grant. That command was
not executed or bypassed. Application containers never received Docker's socket.

Only verification-owned containers, volumes, and network were removed. The isolated
worker passed its health checks. A later development-worker check found a live
heartbeat but missing RQ registration fields, including state. The original cause
of that metadata loss was not established. With no waiting or started jobs, a
graceful worker restart restored its PID, hostname, idle state, and passing health
probe. A real scan (`959dea6c-44f5-481d-874f-59f6c7d66ca3`) then completed with
70 findings, mock false, and an available SBOM. That existing deployment still
uses upstream Trivy 0.75.0; the separate patched-image verification above used
0.75.0+cg.1. No development volumes were removed or saved jobs edited.
