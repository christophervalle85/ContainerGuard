# Running a release

[ContainerGuard v0.1.0](https://github.com/christophervalle85/ContainerGuard/releases/tag/v0.1.0)
is published. Anonymous image pulls and a fresh installation without rebuilding
source passed a real scan, SBOM integrity checks, policy evaluation and persistence
after application recreation. See the [verification record](development/verification.md#published-release-verification)
for the source commit, image digests and observed results. This release is not
signed and has no release-image SBOM or verified build provenance. Its installation
and verification instructions use schema 1.

For a signed schema-2 release, `verify-release` reports an indeterminate verifier
result when it cannot determine whether verification failed because of a trust
rejection or unavailable verification infrastructure. Trust is not established
in either case; the command exits nonzero.

A release contains separate API, worker and dashboard images. You run them locally
with PostgreSQL and Redis; publishing the images does not host the application.
The first release targets `linux/amd64`. Docker Desktop on Apple Silicon needs
amd64 emulation, so startup and scans can take longer than native builds.

## Verify a future signed release before installation

No schema-2 release has yet been qualified. Use these instructions only after one
is published and its exact version and full 40-character source commit have been
independently established from a trusted review. Do not obtain either expectation
from `release.json`, `verification.json`, or other downloaded evidence. Run from
an independently reviewed checkout of that source on Linux/amd64, with Python and
the project's locked dependencies installed. The signed verifier rejects schema 1;
use the separate unsigned v0.1.0 instructions below for that release.

Install the pinned Linux/amd64 Cosign 3.1.3 from the reviewed checkout's
`security/release-tools.json`. The checksum is
`4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71`.
For example, in a private directory:

```sh
mkdir -p "$HOME/cg-release-tools"
curl --fail --location --proto '=https' --proto-redir '=https' --max-filesize 268435456 \
  --output "$HOME/cg-release-tools/cosign" \
  https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64
printf '%s  %s\n' 4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 "$HOME/cg-release-tools/cosign" | sha256sum --check || exit 1
chmod 755 "$HOME/cg-release-tools/cosign"
export CG_RELEASE_TOOLS="$HOME/cg-release-tools"
```

Retrieve the published `release.json` and nine evidence files named
`<service>.<kind>.json`, where service is `api`, `worker`, or `frontend`, and
kind is `sbom`, `provenance`, or `build-record`. Put them in a new private
folder. Bound each SBOM to 16 MiB and the manifest, provenance and build record
to 4 MiB each while downloading; reject larger responses instead of truncating
them. The full published allowlist additionally contains `compose.release.yaml`,
`verification.json`, and twelve `<service>.<kind>.bundle.json` files for kinds
`signature`, `sbom`, `provenance`, and `build-record`. Bundles are at most 24 MiB
and all evidence together is limited to 256 MiB. The verifier independently
retrieves OCI-referrer bundles from the registry; published bundles and receipts
are not a substitute for its checks. Do not unpack arbitrary archives or follow
symlinks into the evidence directory.

For example, the following streaming downloader enforces the per-file bounds for
the ten required inputs before writing them. Set `VERSION` independently first;
run in a fresh directory. A network or size error aborts the command; remove its
partial directory and investigate before retrying.

```sh
export VERSION=vX.Y.Z
python3 - <<'PYCODE'
import os, re, urllib.request
from pathlib import Path
from urllib.parse import quote
version = os.environ['VERSION']
if not re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version):
    raise SystemExit('invalid stable version')
dest = Path('evidence')
dest.mkdir(mode=0o700)
base = 'https://github.com/christophervalle85/ContainerGuard/releases/download/' + quote(version) + '/'
files = {'release.json': 4 * 1024 * 1024}
for service in ('api', 'worker', 'frontend'):
    for kind in ('sbom', 'provenance', 'build-record'):
        files[f'{service}.{kind}.json'] = (16 if kind == 'sbom' else 4) * 1024 * 1024
for name, limit in files.items():
    with urllib.request.urlopen(base + quote(name), timeout=60) as source, (dest / name).open('xb') as target:
        total = 0
        while chunk := source.read(min(65536, limit + 1 - total)):
            total += len(chunk)
            if total > limit:
                raise SystemExit(f'{name} exceeds limit')
            target.write(chunk)
PYCODE
```

```sh
# Set these from independent review, and use a new output directory.
VERSION=vX.Y.Z
COMMIT=FULL_40_CHARACTER_SOURCE_COMMIT
python3 -m scripts.releases verify-release \
  --version "$VERSION" --commit "$COMMIT" \
  --manifest /path/to/evidence/release.json \
  --evidence-dir /path/to/evidence --output-dir /path/to/new-verified-output
```

The command checks the three fixed GHCR image digests, retrieves each image's
referrers anonymously, verifies the signature and three typed attestations, binds
the predicates to the downloaded evidence, and writes a digest-only Compose file
only after all checks pass. Add `--exercise` for the isolated full-stack scan,
policy, idempotency and persistence exercise; it creates and removes its own
resources. It does not verify a future release until actually run against it. An
unavailable tool or registry and an indeterminate Cosign result both exit nonzero;
the latter may be either a trust rejection or unavailable trust infrastructure.
Treat any nonzero result as failure and do not install.

For inspection, the equivalent Cosign primitive for **each selected OCI-referrer
bundle** uses the same policy. Obtain the bundle from
`cosign download attestation --predicate-type PREDICATE_TYPE <image-by-digest>`,
retain exactly one bounded JSON line of the intended type, and verify its subject digest.
Select a modern OCI-referrer DSSE bundle, not a legacy attestation; reject missing,
ambiguous or unexpected output. The four exact types are
`https://sigstore.dev/cosign/sign/v1`, `https://cyclonedx.org/bom`,
`https://slsa.dev/provenance/v1`, and
`https://github.com/christophervalle85/ContainerGuard/attestations/build-record/v1`.
For each of the four types and each image:

```sh
"$CG_RELEASE_TOOLS/cosign" verify-blob-attestation \
  --bundle /path/to/selected.bundle.json --digest IMAGE_SHA256_HEX --digestAlg sha256 \
  --type PREDICATE_TYPE \
  --certificate-identity="https://github.com/christophervalle85/ContainerGuard/.github/workflows/release.yml@refs/tags/$VERSION" \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-github-workflow-sha="$COMMIT" \
  --certificate-github-workflow-repository=christophervalle85/ContainerGuard \
  --certificate-github-workflow-trigger=push \
  --certificate-github-workflow-ref="refs/tags/$VERSION"
```

These individual checks do not replace `verify-release`: it also enforces the
inventory, schemas, associations, limits and evidence hashes. Online registry,
Sigstore trust root and transparency services are required. Certificate identity,
source and signing metadata are public. Signatures do not prove absence of defects,
compromise, or vulnerabilities; LOW/MEDIUM/UNKNOWN findings remain possible.
After successful verification, change into the new output directory and use its
generated `compose.release.yaml` with the runtime configuration and startup steps
below. Skip the unsigned release download step.

## Install unsigned v0.1.0 without rebuilding

Download `release.json` and `compose.release.yaml` from the same
[GitHub Release](https://github.com/christophervalle85/ContainerGuard/releases).
Keep them in a new directory, separate from a development checkout. The Compose
file uses the exact image digests listed in the manifest, including the API image
used for migrations. It has no build instructions.

Generate a local database password and keep the configuration private:

```sh
umask 077
python3 - <<'PY'
import secrets
from pathlib import Path
Path('runtime.env').write_text('POSTGRES_PASSWORD=' + secrets.token_hex(32) + '\n')
PY
```

Do not commit or upload `runtime.env`. Its generated hexadecimal password is also
safe to use in the database connection URL. Keep this file when restarting an
existing database; changing the value does not change an initialized PostgreSQL
password automatically.

To confirm public access without using saved registry credentials:

```sh
auth_dir=$(mktemp -d)
printf '{"auths":{}}\n' > "$auth_dir/config.json"
DOCKER_CONFIG="$auth_dir" docker compose --env-file runtime.env -f compose.release.yaml pull
rm -rf "$auth_dir"
docker compose --env-file runtime.env -f compose.release.yaml up -d --no-build --wait --wait-timeout 150
docker compose --env-file runtime.env -f compose.release.yaml ps -a
```

The migration container should exit successfully; the API, worker and frontend
should become healthy. Open the dashboard at `http://127.0.0.1:8080` or the API
docs at `http://127.0.0.1:8000/docs`. The database and Redis have no host ports.
Application ports bind to localhost. To use different ports, add `API_PORT` and
`FRONTEND_PORT` values to `runtime.env` before starting.

Submit `docker.io/library/alpine:3.20.0` as a scan target. The first worker scan
may download Trivy's vulnerability database into its own persistent cache. Wait
for `completed`, confirm `mock: false`, retrieve findings, download the SBOM, and
compare its SHA-256 with the SBOM metadata. Counts change as vulnerability data
changes; a completed scan is not a security-policy verdict. Create and evaluate
an explicit policy version to obtain that decision.

If startup or a scan fails, inspect the local service logs:

```sh
docker compose --env-file runtime.env -f compose.release.yaml logs --tail=80 api worker migrate
```

Never paste configuration, credentials or unreviewed logs into a public issue.

## Persistence and shutdown

Named volumes retain PostgreSQL data, Redis state and the Trivy cache when
application containers are recreated. A normal `docker compose ... down` preserves
those volumes; adding `--volumes` deletes this installation's stored data.
The worker has a 650-second graceful-stop window. Interrupting or losing a worker
can still leave jobs requiring [manual recovery](architecture/jobs.md); releases
do not add automatic reconciliation or an exactly-once guarantee.

Back up data before upgrades. Migrations run before the API and worker start.
Rolling an image back does not reverse database migrations; inspect migration
compatibility and restore a suitable backup when necessary.

## Maintainer release procedure

1. Review and merge the release branch. Require green main CI for the exact source
   commit; finish installation docs before tagging it.
2. Choose an unused stable `vMAJOR.MINOR.PATCH` tag. Review repository tag rules and
   package write access. The workflow refuses existing version and full-commit
   image tags; it does not prevent every other authorized writer changing tags.
3. After explicit approval, push that tag at the reviewed commit. The release
   workflow validates main ancestry and reuses backend, frontend, dependency and
   reachable-history checks. It builds each runtime image once, applies the
   HIGH/CRITICAL vulnerability gate, scans all layers and metadata for disclosure,
   and exercises a fresh full stack before transferring any image archives.
4. A separate publisher validates archive/config/layer/check identities and checks
   all six destination tags before uploads. It pushes the checked bytes without
   rebuilding or running their payloads, then verifies GHCR manifest digests.
   A separate signer attaches signatures and typed attestations. An independent
   verifier checks them before a separate notes job creates a **draft** with the
   verified assets.
5. New GHCR packages may be private. Review the checked contents, then intentionally
   make the three ContainerGuard packages public in GitHub's package settings.
   Verify anonymous access before announcing the release.
6. For v0.1.0 only, from the release source checkout, run the published-image verification below. For a future schema-2 release use the signed verification procedure above instead.
   It uses empty Docker auth, exact manifest digests, random localhost ports and
   a fresh `containerguard-release-verify-*` project. It verifies a real scan,
   findings, SBOM integrity, policy decisions, duplicate evaluation identity and
   persistence after application recreation, then removes only its own volumes.
7. Record the actual tag, source SHA, three registry digests, CI links and verification
   result. Only then publish the GitHub Release through its draft page.

```sh
python3 -m scripts.releases verify-published \
  --manifest /path/to/release.json \
  --output-dir /tmp/containerguard-published-verification
```

A version tag is the workflow's publication trigger. Plan approval alone does not
authorize that operation. The publisher and notes jobs have separate credentials;
PR/build jobs receive no package-write access. Image archives remain in Actions
for one day. Check summaries retain for seven days. Avoid copying them elsewhere
without reviewing what will be disclosed.

## Partial publication and boundaries

Uploading three images and two tags each, and attaching their signatures and
attestations, is not atomic. If an upload fails, inspect
its safe partial-publication record: an attempted push might have reached GHCR even
when the command failed. Keep any GitHub Release in draft. Do not rerun assuming
existing tags will be replaced: this workflow refuses overwrite. Recovery normally
needs a new version and may also need a new reviewed commit because a `sha-` tag
can already exist. Check the affected destinations before deciding.

Checks are dated observations, not an exhaustive audit. LOW/MEDIUM/UNKNOWN findings
remain visible in release notes. All runtime layers and image configuration/history
are inspected as bounded regular-file streams, with one level of supported secret
encoding detection; arbitrary nested archives, arbitrary binary encodings and every
possible sensitive value are not guaranteed to be recognized. The detector's
limits and any reviewed false-positive corrections belong in the verification
record. Failed or oversized checks block transfer rather than count as clean.

The API, worker and frontend runtime images are vulnerability-gated. Their builder
images and the separately digest-pinned PostgreSQL/Redis images are outside that
runtime gate. Neither application container receives Docker's socket. Public cloud
hosting and an independent second developer's setup verification remain separate
work.
