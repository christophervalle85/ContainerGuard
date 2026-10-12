import hashlib
import io
import json
from email.message import Message
from urllib.error import HTTPError

import pytest

from scripts.releases import registry


class Response(io.BytesIO):
    def __init__(self, raw, headers=None, status=200):
        super().__init__(raw)
        self.headers = headers or {}
        self.status = status


def test_authenticated_challenge_then_confirmed_missing(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "nonfunctional-test-value")
    monkeypatch.setenv("GITHUB_ACTOR", "owner")
    requests = []

    def fetch(url, headers):
        requests.append((url, headers))
        if "/token?" in url:
            assert headers["Authorization"].startswith("Basic ")
            return 200, {}, b'{"token":"test-bearer"}'
        if headers.get("Authorization") == "Bearer test-bearer":
            return 404, {}, b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}'
        return (
            401,
            {
                "WWW-Authenticate": 'Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:christophervalle85/containerguard-api:pull"'
            },
            b"",
        )

    monkeypatch.setattr(registry, "_fetch", fetch)
    assert registry.Registry().manifest("api", "v1.0.0", allow_missing=True) is None
    assert len(requests) == 3


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503, 302])
def test_registry_failures_never_mean_absent(monkeypatch, status):
    monkeypatch.setattr(registry, "_fetch", lambda *args: (status, {}, b"not absent"))
    with pytest.raises(ValueError):
        registry.Registry().manifest("api", "v1.0.0", allow_missing=True)


def test_anonymous_404_and_ambiguous_error_fail_closed(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(
        registry,
        "_fetch",
        lambda *args: (404, {}, b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}'),
    )
    with pytest.raises(ValueError):
        registry.Registry().manifest("api", "v1.0.0", allow_missing=True)


def test_manifest_and_config_digest_identity(monkeypatch):
    config = json.dumps(
        {
            "os": "linux",
            "architecture": "amd64",
            "rootfs": {"diff_ids": ["sha256:" + "a" * 64]},
            "config": {"Labels": {"source": "expected"}},
        }
    ).encode()
    config_id = "sha256:" + hashlib.sha256(config).hexdigest()
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": config_id, "size": len(config)},
            "layers": [{"digest": "sha256:" + "b" * 64}],
        }
    ).encode()
    digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
    monkeypatch.setattr(
        registry,
        "_fetch",
        lambda url, headers: (
            (200, {"Docker-Content-Digest": digest}, manifest)
            if "/manifests/" in url
            else (200, {}, config)
        ),
    )
    result = registry.Registry().manifest("api", "v1.0.0")
    assert result["digest"] == digest
    assert result["image_id"] == config_id
    monkeypatch.setattr(
        registry,
        "_fetch",
        lambda *args: (200, {"Docker-Content-Digest": "sha256:" + "0" * 64}, manifest),
    )
    with pytest.raises(ValueError):
        registry.Registry().manifest("api", "v1.0.0")


def test_network_layer_rejects_redirects_and_bounds(monkeypatch):
    with pytest.raises(ValueError):
        registry._fetch("https://evil.invalid/token", {})

    class Opener:
        def open(self, request, timeout):
            raise HTTPError(
                request.full_url, 302, "redirect", Message(), io.BytesIO(b"")
            )

    monkeypatch.setattr(registry.urllib.request, "build_opener", lambda *args: Opener())
    with pytest.raises(ValueError):
        registry._fetch("https://ghcr.io/token", {})


def test_real_http_transport_handles_authentication_and_refuses_redirect(monkeypatch):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            if self.path.startswith("/token?"):
                status, raw = 200, b'{"token":"test-bearer"}'
            elif self.path.endswith("/manifests/v2.0.0"):
                status, raw = 302, b""
            elif self.headers.get("Authorization") == "Bearer test-bearer":
                status, raw = 404, b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}'
            else:
                status, raw = 401, b""
            self.send_response(status)
            if status == 401:
                self.send_header(
                    "WWW-Authenticate",
                    'Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:christophervalle85/containerguard-api:pull"',
                )
            if status == 302:
                self.send_header("Location", "https://evil.invalid/exfiltrate")
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    opener = registry.urllib.request.build_opener(registry.NoRedirect())

    class LocalTransport:
        def open(self, request, timeout):
            parsed = registry.urllib.parse.urlsplit(request.full_url)
            url = (
                f"http://127.0.0.1:{server.server_port}"
                + parsed.path
                + ("?" + parsed.query if parsed.query else "")
            )
            return opener.open(
                registry.urllib.request.Request(
                    url, headers=dict(request.header_items())
                ),
                timeout=timeout,
            )

    monkeypatch.setattr(
        registry.urllib.request, "build_opener", lambda *args: LocalTransport()
    )
    monkeypatch.setenv("GITHUB_TOKEN", "nonfunctional-test-value")
    monkeypatch.setenv("GITHUB_ACTOR", "owner")
    try:
        client = registry.Registry()
        assert client.manifest("api", "v1.0.0", allow_missing=True) is None
        with pytest.raises(ValueError):
            client.manifest("api", "v2.0.0", allow_missing=True)
        assert len(seen) == 4
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize(
    "challenge",
    [
        'Bearer realm="https://evil.invalid/token",service="ghcr.io",scope="repository:christophervalle85/containerguard-api:pull"',
        'Bearer realm="https://ghcr.io/token",service="other",scope="repository:christophervalle85/containerguard-api:pull"',
        'Basic realm="ghcr.io"',
    ],
)
def test_untrusted_authentication_challenge_never_receives_credentials(
    monkeypatch, challenge
):
    seen = []

    def fetch(url, headers):
        seen.append(url)
        return 401, {"WWW-Authenticate": challenge}, b""

    monkeypatch.setattr(registry, "_fetch", fetch)
    monkeypatch.setenv("GITHUB_TOKEN", "nonfunctional-test-value")
    monkeypatch.setenv("GITHUB_ACTOR", "owner")
    with pytest.raises(ValueError):
        registry.Registry().manifest("api", "v1.0.0", allow_missing=True)
    assert len(seen) == 1


@pytest.mark.parametrize("code", [302, 307])
def test_blob_cdn_redirect_strips_authorization(monkeypatch, code):
    requests = []

    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            if len(requests) == 1:
                headers = Message()
                headers["Location"] = (
                    "https://pkg-containers.githubusercontent.com/ghcr1/blobs/config?signature=public-fixture"
                )
                raise HTTPError(
                    request.full_url, code, "redirect", headers, io.BytesIO()
                )
            response = Response(b"{}")
            response.code = 200
            return response

    monkeypatch.setattr(registry.urllib.request, "build_opener", lambda *args: Opener())
    assert (
        registry._fetch(
            "https://ghcr.io/v2/owner/image/blobs/sha256:" + "a" * 64,
            {"Authorization": "Bearer test-only"},
        )[2]
        == b"{}"
    )
    assert requests[0].get_header("Authorization") == "Bearer test-only"
    assert requests[1].get_header("Authorization") is None


@pytest.mark.parametrize(
    "destination",
    [
        "http://pkg-containers.githubusercontent.com/blob",
        "https://pkg-containers.githubusercontent.com.evil.invalid/blob",
        "https://user@pkg-containers.githubusercontent.com/blob",
        "https://pkg-containers.githubusercontent.com:444/blob",
        "https://evil.invalid/blob",
    ],
)
def test_blob_redirect_refuses_untrusted_destination(monkeypatch, destination):
    requests = []

    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            headers = Message()
            headers["Location"] = destination
            raise HTTPError(request.full_url, 307, "redirect", headers, io.BytesIO())

    monkeypatch.setattr(registry.urllib.request, "build_opener", lambda *args: Opener())
    with pytest.raises(ValueError):
        registry._fetch(
            "https://ghcr.io/v2/owner/image/blobs/sha256:" + "a" * 64,
            {"Authorization": "Bearer test-only"},
        )
    assert len(requests) == 1


def test_blob_redirect_chain_is_bounded(monkeypatch):
    requests = []

    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            headers = Message()
            headers["Location"] = "https://pkg-containers.githubusercontent.com/loop"
            raise HTTPError(request.full_url, 307, "redirect", headers, io.BytesIO())

    monkeypatch.setattr(registry.urllib.request, "build_opener", lambda *args: Opener())
    with pytest.raises(ValueError):
        registry._fetch("https://ghcr.io/v2/owner/image/blobs/sha256:" + "a" * 64, {})
    assert 1 < len(requests) <= 4


def test_preflight_requests_indexes_so_existing_multiarch_tag_cannot_look_absent(
    monkeypatch,
):
    seen = []

    def fetch(url, headers):
        seen.append(headers["Accept"])
        raw = (
            b'{"schemaVersion":2,"mediaType":'
            b'"application/vnd.oci.image.index.v1+json","manifests":[]}'
        )
        return (
            200,
            {"Docker-Content-Digest": "sha256:" + hashlib.sha256(raw).hexdigest()},
            raw,
        )

    monkeypatch.setattr(registry, "_fetch", fetch)
    with pytest.raises(ValueError):
        registry.Registry().manifest("api", "v1.0.0", allow_missing=True)
    assert "application/vnd.oci.image.index.v1+json" in seen[0]
    assert "application/vnd.docker.distribution.manifest.list.v2+json" in seen[0]
