# Local OCI transport fixture

`local-buildx-oci.tar` is a newly generated, sanitized real-tool fixture, **not**
retained Task 1 CI evidence. Generated locally on macOS on 2026-10-19 using Docker
Desktop Engine 29.8.2, Docker Buildx 0.37.2 (the release pin is 0.38.0), desktop-linux
Docker driver and its containerd image store. This does not qualify pinned Linux
tools, a classic image store, Skopeo, a registry, signing or GitHub OIDC.

The disposable build context contained only this Dockerfile and a `hello` file:

```dockerfile
FROM scratch
COPY hello /hello
```

`hello` contains `ContainerGuard sanitized transport fixture` followed by newline.
Build command (temporary context path omitted):

```
docker buildx build --platform linux/amd64 --provenance=false --sbom=false \
  --output type=oci,dest=tests/fixtures/releases/local-buildx-oci.tar CONTEXT
```

No evidence payload is produced; no registry or network source is involved.
Canonical archive SHA-256:
`5df81ccf262565a1994624dd7ec9ac43cfbfa7128ea66be3348c4888ef00d6b4`.
The regression test pins its runnable manifest and config digests. Local real
`import_for_checks` also passed load → inspect → save → validated config/diff IDs;
only disposable tag `cg-task2-owned-fixture:local` was created and removed.

The unchanged real image configuration contains one `Env` entry: the builder's
standard public default `PATH`. It contains no additional environment values.
Controller Gitleaks scanning of source, fixture JSON blobs and the decompressed
layer reported zero findings. The generic native-evidence privacy classifier
flags any `Env` field; that classifier is not an acceptance audit for Docker
image configuration. No audit allowance was changed and no fixture bytes were
stripped or rewritten.
