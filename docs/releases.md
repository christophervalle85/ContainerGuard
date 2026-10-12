# Running a release

[ContainerGuard v0.1.0](https://github.com/christophervalle85/ContainerGuard/releases/tag/v0.1.0)
is published. Anonymous image pulls and a fresh installation without rebuilding
source passed a real scan, SBOM integrity checks, policy evaluation and persistence
after application recreation. See the [verification record](development/verification.md#published-release-verification)
for the source commit, image digests and observed results. This release is not
signed and has no release-image SBOM or verified build provenance.

A release contains separate API, worker and dashboard images. You run them locally
with PostgreSQL and Redis; publishing the images does not host the application.
The first release targets `linux/amd64`. Docker Desktop on Apple Silicon needs
amd64 emulation, so startup and scans can take longer than native builds.

## Install without rebuilding

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
   A separate notes job creates a **draft** with the manifest and Compose assets.
5. New GHCR packages may be private. Review the checked contents, then intentionally
   make the three ContainerGuard packages public in GitHub's package settings.
   Verify anonymous access before announcing the release.
6. From the release source checkout, run the published-image verification below.
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

Uploading three images and two tags each is not atomic. If an upload fails, inspect
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
runtime gate. Neither application container receives Docker's socket. Signing,
release-image SBOM distribution, provenance, public cloud hosting and an independent
second developer's setup verification remain separate work.
