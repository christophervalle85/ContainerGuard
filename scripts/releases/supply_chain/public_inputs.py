"""Reviewed public inputs for the pinned Dockerfiles and BuildKit producer."""

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SOURCE = "https://github.com/christophervalle85/ContainerGuard"
DOCKERFILES = dict(
    zip(
        ("api", "worker", "frontend"),
        (
            "e981f24ea307af6d9363165501c5ac39c9a83bca5830d70041f6405f8e2e48e7",
            "80486fb2e1fc0fec745bf160fd64b7a84a40caa6abf419c44b7951120bd26597",
            "7de9990fb674f428dab3a2b29b99ec509d45e6528766d7b41bffb56799a05980",
        ),
        strict=True,
    )
)
PYTHON = (
    "python",
    "3.14.7-alpine",
    "9e9fde4d32eedce0b661d9ab91e826b62dddf28e928c230ec55f1866cac66b01",
)
UV = (
    "ghcr.io/astral-sh/uv",
    "0.12.21",
    "a7aed3216253ee804de3e2d8afa5073baa1a177335345d43845cd4165e43b711",
)
GO = (
    "golang",
    "1.27.3-alpine",
    "d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb",
)
NODE = (
    "node",
    "24-alpine",
    "ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1",
)
NGINX = (
    "nginxinc/nginx-unprivileged",
    "stable-alpine",
    "f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03",
)
IMAGES = {"api": (PYTHON, UV), "worker": (PYTHON, UV, GO), "frontend": (NODE, NGINX)}
HTTP = (
    "https://codeload.github.com/aquasecurity/trivy/tar.gz/591e9799316a602e703f0b484f6c6d7b234ec8f3",
    "4a5bb1c16ccc55368843eb95ee9a25519a0bfef26609a8b4295f2060af43077e",
)
BASE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PY_ENV = {
    "PATH=/usr/local/bin:" + BASE_PATH,
    "PYTHON_VERSION=3.14.7",
    "PYTHON_SHA256=3b48dac8fb59f62eaa67ac83c1eb12bda1b7a08406dd286e252c11a66be27f81",
    "UV_PYTHON_DOWNLOADS=never",
    "UV_LINK_MODE=copy",
    "PYTHONDONTWRITEBYTECODE=1",
    "PYTHONUNBUFFERED=1",
    "PATH=/app/.venv/bin:/usr/local/bin:" + BASE_PATH,
}
GO_ENV = {
    "PATH=/go/bin:/usr/local/go/bin:" + BASE_PATH,
    "GOLANG_VERSION=1.27.3",
    "GOTOOLCHAIN=local",
    "GOPATH=/go",
    "TARGETARCH=amd64",
}


def bound(document, service, commit):
    try:
        config = document["buildDefinition"]["externalParameters"]["configSource"]
        return (
            service in DOCKERFILES
            and isinstance(commit, str)
            and len(commit) == 40
            and all(c in "0123456789abcdef" for c in commit)
            and hashlib.sha256(
                (ROOT / ("Dockerfile." + service)).read_bytes()
            ).hexdigest()
            == DOCKERFILES[service]
            and config
            == {
                "uri": SOURCE + "#" + commit,
                "digest": {"sha1": commit},
                "path": "Dockerfile." + service,
            }
        )
    except (KeyError, TypeError, OSError):
        return False


def materials(document, service, commit):
    if not bound(document, service, commit):
        raise ValueError("unreviewed source")
    approved = {(SOURCE + "#" + commit, commit, "sha1")}
    for name, tag, digest in IMAGES[service]:
        uri = f"pkg:docker/{name}@{tag}?digest=sha256:{digest}"
        approved.add((uri + "&platform=linux%2Famd64", digest, "sha256"))
    if service == "worker":
        approved.add((HTTP[0], HTTP[1], "sha256"))
    seen = set()
    for item in document["buildDefinition"]["resolvedDependencies"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"uri", "digest"}
            or not isinstance(item["digest"], dict)
            or len(item["digest"]) != 1
        ):
            raise ValueError("invalid material")
        algorithm, digest = next(iter(item["digest"].items()))
        material = (item["uri"], digest, algorithm)
        if material not in approved or material in seen:
            raise ValueError("unreviewed material")
        seen.add(material)


def has_image(document, image):
    name, tag, digest = image
    prefix = f"pkg:docker/{name}@{tag}?digest=sha256:{digest}"
    return any(
        item
        in (
            {"uri": prefix, "digest": {"sha256": digest}},
            {"uri": prefix + "&platform=linux%2Famd64", "digest": {"sha256": digest}},
        )
        for item in document["buildDefinition"]["resolvedDependencies"]
    )


def metadata(document, service):
    env, cache = set(), set()
    if service in ("api", "worker") and has_image(document, PYTHON):
        env |= PY_ENV
        if service == "worker":
            env.add("TRIVY_CACHE_DIR=/var/cache/trivy")
        if has_image(document, UV):
            cache.add("/root/.cache/uv")
    if service == "worker" and has_image(document, GO):
        env |= GO_ENV
        cache.add("/root/.cache/go-build")
    if service == "frontend":
        if has_image(document, NODE):
            env |= {"PATH=" + BASE_PATH, "NODE_VERSION=24.21.0", "YARN_VERSION=1.22.22"}
        if has_image(document, NGINX):
            env |= {
                "PATH=" + BASE_PATH,
                "NGINX_VERSION=1.30.6",
                "PKG_RELEASE=1",
                "DYNPKG_RELEASE=1",
                "NJS_VERSION=1.0.2",
                "NJS_RELEASE=1",
            }
    return env, cache
