import io
import json
from importlib import import_module
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

import pytest

INDEX = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.index.v1+json",
    "manifests": [],
}


class SampleTransport:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return io.BytesIO(response)


def prepare_transport(monkeypatch, *responses):
    registry = import_module("app.registries.docker_hub")
    transport = SampleTransport(responses)
    monkeypatch.setattr(registry, "build_opener", lambda *handlers: transport)
    return registry, transport


@pytest.mark.parametrize("token_field", ["token", "access_token"])
def test_fetches_index_with_an_anonymous_pull_token(monkeypatch, token_field):
    registry, transport = prepare_transport(
        monkeypatch,
        json.dumps({token_field: "sample-token"}).encode(),
        json.dumps(INDEX).encode(),
    )
    raw = registry.fetch_docker_index("library/alpine", "3.20", timeout_seconds=7)
    assert json.loads(raw) == INDEX
    token_request, token_timeout = transport.requests[0]
    token_url = urlsplit(token_request.full_url)
    assert token_url.scheme == "https"
    assert token_url.netloc == "auth.docker.io"
    assert parse_qs(token_url.query) == {
        "service": ["registry.docker.io"],
        "scope": ["repository:library/alpine:pull"],
    }
    assert token_request.get_header("Authorization") is None
    image_request, image_timeout = transport.requests[1]
    assert (
        image_request.full_url
        == "https://registry-1.docker.io/v2/library/alpine/manifests/3.20"
    )
    assert image_request.get_header("Authorization") == "Bearer sample-token"
    assert "application/vnd.oci.image.index.v1+json" in image_request.get_header(
        "Accept"
    )
    assert token_timeout == image_timeout == 7


@pytest.mark.parametrize(
    "token_document",
    [b"not-json", b"[]", b"{}", b'{"token": 123}', b'{"token": "bad\\nheader"}'],
)
def test_rejects_invalid_token_responses(monkeypatch, token_document):
    registry, transport = prepare_transport(monkeypatch, token_document)
    with pytest.raises(registry.RegistryRequestError) as error:
        registry.fetch_docker_index("library/alpine", "3.20")
    assert error.value.code == "invalid_response"
    assert len(transport.requests) == 1


@pytest.mark.parametrize(
    "status,code",
    [
        (401, "access_denied"),
        (404, "not_found"),
        (429, "rate_limited"),
        (500, "unavailable"),
        (302, "invalid_response"),
        (400, "invalid_response"),
        (408, "unavailable"),
        (503, "unavailable"),
    ],
)
def test_reports_registry_errors_without_exposing_response_content(
    monkeypatch, status, code
):
    http_error = HTTPError(
        "https://registry-1.docker.io", status, "secret", {}, io.BytesIO(b"secret")
    )
    registry, _ = prepare_transport(
        monkeypatch, b'{"token": "sample-token"}', http_error
    )
    with pytest.raises(registry.RegistryRequestError) as error:
        registry.fetch_docker_index("library/alpine", "missing")
    assert error.value.code == code
    assert "secret" not in str(error.value)
    assert "sample-token" not in str(error.value)


@pytest.mark.parametrize(
    "failure", [TimeoutError(), URLError("secret connection details")]
)
def test_handles_connection_failures(monkeypatch, failure):
    registry, _ = prepare_transport(monkeypatch, failure)
    with pytest.raises(registry.RegistryRequestError) as error:
        registry.fetch_docker_index("library/alpine", "3.20")
    assert error.value.code == "unavailable"
    assert "secret" not in str(error.value)


@pytest.mark.parametrize("stage", ["token", "index"])
def test_bounds_response_sizes(monkeypatch, stage):
    responses = (
        [b"x" * (64 * 1024 + 1)]
        if stage == "token"
        else [b'{"token": "sample-token"}', b"x" * 129]
    )
    registry, _ = prepare_transport(monkeypatch, *responses)
    with pytest.raises(registry.RegistryRequestError) as error:
        registry.fetch_docker_index("library/alpine", "3.20", max_response_bytes=128)
    assert error.value.code == "output_limit"


def test_rejects_non_utf8_index(monkeypatch):
    registry, _ = prepare_transport(monkeypatch, b'{"token": "sample-token"}', b"\xff")
    with pytest.raises(registry.RegistryRequestError) as error:
        registry.fetch_docker_index("library/alpine", "3.20")
    assert error.value.code == "invalid_response"


@pytest.mark.parametrize(
    "repository,tag",
    [
        ("../private", "latest"),
        ("library/alpine?x", "latest"),
        ("library/alpine", "../latest"),
        ("library/alpine", "tag?x=1"),
        (None, "latest"),
        ("library/alpine", None),
    ],
)
def test_rejects_unsafe_request_paths_before_network_access(
    monkeypatch, repository, tag
):
    registry, transport = prepare_transport(monkeypatch)
    with pytest.raises(ValueError):
        registry.fetch_docker_index(repository, tag)
    assert transport.requests == []


@pytest.mark.parametrize(
    "options",
    [{"timeout_seconds": 0}, {"timeout_seconds": True}, {"max_response_bytes": 0}],
)
def test_rejects_invalid_request_limits(monkeypatch, options):
    registry, transport = prepare_transport(monkeypatch)
    with pytest.raises(ValueError):
        registry.fetch_docker_index("library/alpine", "3.20", **options)
    assert transport.requests == []


def test_disallows_redirecting_bearer_tokens_to_another_host():
    registry = import_module("app.registries.docker_hub")
    assert (
        registry.NoRedirect().redirect_request(
            None, None, 302, "redirect", {}, "https://example.com"
        )
        is None
    )


@pytest.mark.parametrize(
    "reference,expected",
    [
        (" docker.io/library/alpine:3.20 ", ("library/alpine", "3.20")),
        ("docker.io/alpine:3.20", ("library/alpine", "3.20")),
    ],
)
def test_parses_an_explicit_docker_hub_tag(reference, expected):
    registry = import_module("app.registries.docker_hub")
    assert registry.parse_docker_tag(reference) == expected


@pytest.mark.parametrize(
    "reference",
    [
        "ghcr.io/demo/image:latest",
        "docker.io/library/alpine",
        "docker.io/library/alpine@sha256:" + "a" * 64,
        "https://docker.io/library/alpine:3.20",
        "docker.io/library/alpine:3.20?x=1",
        None,
    ],
)
def test_rejects_unsupported_tag_references(reference):
    registry = import_module("app.registries.docker_hub")
    with pytest.raises(ValueError):
        registry.parse_docker_tag(reference)


@pytest.mark.parametrize("stage", ["token", "index"])
def test_truncated_chunked_response_is_a_safe_registry_failure(monkeypatch, stage):
    from http.client import HTTPResponse

    class SampleSocket:
        def makefile(self, mode):
            return io.BytesIO(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nabc"
            )

    response = HTTPResponse(SampleSocket())
    response.begin()
    registry = import_module("app.registries.docker_hub")

    class TruncatedTransport:
        def __init__(self):
            self.calls = 0

        def open(self, request, timeout):
            self.calls += 1
            if stage == "index" and self.calls == 1:
                return io.BytesIO(b'{"token": "sample-token"}')
            return response

    monkeypatch.setattr(
        registry, "build_opener", lambda *handlers: TruncatedTransport()
    )
    with pytest.raises(registry.RegistryRequestError) as error:
        registry.fetch_docker_index("library/alpine", "3.20")
    assert error.value.code == "unavailable"
    assert "abc" not in str(error.value)
