from __future__ import annotations

from typing import Any

import pytest

from pyevp.adapters import _http
from pyevp.adapters._doh import parse_txt_data
from pyevp.adapters.doh import (
    CLOUDFLARE,
    GOOGLE,
    AsyncDohResolver,
    DnssecError,
    DohError,
    DohResolver,
)

http = _http.http
NAME = "_email-verification.gmail.com"


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        ("iss=accounts.google.com", "iss=accounts.google.com"),  # Google: already joined
        ('"iss=accounts.google.com"', "iss=accounts.google.com"),  # Cloudflare: quoted
        ('"v=DKIM1; p=abc" "def"', "v=DKIM1; p=abcdef"),  # split character-strings
        (r'"say \"hi\" \\ ok"', 'say "hi" \\ ok'),
        (r'"caf\195\169"', "café"),  # \DDD byte escapes
        ('""', ""),
    ],
)
def test_parse_txt_data(data: str, expected: str) -> None:
    assert parse_txt_data(data) == expected


@pytest.mark.parametrize("data", ['"unterminated', '"a" b', '"dangling\\'])
def test_parse_txt_data_malformed(data: str) -> None:
    with pytest.raises(DohError):
        parse_txt_data(data)


def _answer(data: str, type_: int = 16) -> dict[str, Any]:
    return {"name": NAME, "type": type_, "TTL": 3600, "data": data}


RESPONSES: dict[str, Any] = {
    "google": {"Status": 0, "AD": False, "Answer": [_answer("iss=accounts.google.com")]},
    "cloudflare": {"Status": 0, "AD": False, "Answer": [_answer('"iss=accounts.google.com"')]},
    "cname": {
        "Status": 0,
        "AD": True,
        "Answer": [_answer("target.example.", 5), _answer("iss=a.example")],
    },
    "nodata": {"Status": 0, "AD": False},
    "nxdomain": {"Status": 3, "AD": False},
    "servfail": {"Status": 2},
}


def _client(kind: str, seen: list[Any] | None = None, *, is_async: bool = False) -> Any:
    def handle(request: Any) -> Any:
        if seen is not None:
            seen.append(request)
        if kind == "http500":
            return http.Response(500)
        if kind == "redirect" and request.url.host != "elsewhere.example":
            return http.Response(302, headers={"Location": "https://elsewhere.example/"})
        if kind == "redirect":
            return http.Response(200, json=RESPONSES["google"])
        return http.Response(200, json=RESPONSES[kind])

    cls = http.AsyncClient if is_async else http.Client
    # Applications may pass a client that follows redirects; the resolver must not.
    return cls(transport=http.MockTransport(handle), follow_redirects=True)


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("google", ["iss=accounts.google.com"]),
        ("cloudflare", ["iss=accounts.google.com"]),
        ("cname", ["iss=a.example"]),
        ("nodata", []),
        ("nxdomain", []),
    ],
)
def test_resolve(kind: str, expected: list[str]) -> None:
    with DohResolver(client=_client(kind)) as resolver:
        assert resolver.resolve_txt(NAME) == expected


@pytest.mark.parametrize("kind", ["servfail", "http500"])
def test_resolve_errors(kind: str) -> None:
    with DohResolver(client=_client(kind)) as resolver, pytest.raises(DohError):
        resolver.resolve_txt(NAME)


def test_request_shape() -> None:
    seen: list[Any] = []
    with DohResolver(CLOUDFLARE, client=_client("cloudflare", seen)) as resolver:
        resolver.resolve_txt(NAME)
    [request] = seen
    assert str(request.url).startswith(CLOUDFLARE)
    assert request.url.params["name"] == NAME
    assert request.url.params["type"] == "TXT"
    assert request.headers["accept"] == "application/dns-json"


def test_require_dnssec() -> None:
    with DohResolver(client=_client("cname"), require_dnssec=True) as resolver:
        assert resolver.resolve_txt(NAME) == ["iss=a.example"]
    with (
        DohResolver(client=_client("google"), require_dnssec=True) as resolver,
        pytest.raises(DnssecError),
    ):
        resolver.resolve_txt(NAME)


@pytest.mark.anyio
async def test_async_resolve() -> None:
    async with AsyncDohResolver(GOOGLE, client=_client("google", is_async=True)) as resolver:
        assert await resolver.resolve_txt(NAME) == ["iss=accounts.google.com"]


def test_injected_client_does_not_follow_redirects() -> None:
    seen: list[Any] = []
    with DohResolver(client=_client("redirect", seen)) as resolver, pytest.raises(DohError):
        resolver.resolve_txt(NAME)
    assert [r.url.host for r in seen] == ["dns.google"]


@pytest.mark.anyio
async def test_async_injected_client_does_not_follow_redirects() -> None:
    seen: list[Any] = []
    async with AsyncDohResolver(client=_client("redirect", seen, is_async=True)) as resolver:
        with pytest.raises(DohError):
            await resolver.resolve_txt(NAME)
    assert [r.url.host for r in seen] == ["dns.google"]


def test_a_client_passed_in_stays_open() -> None:
    client = http.Client()
    with DohResolver(client=client):
        pass
    assert not client.is_closed
    owned = DohResolver()
    owned.close()
    assert owned._client.is_closed


@pytest.mark.anyio
async def test_an_async_client_passed_in_stays_open() -> None:
    client = http.AsyncClient()
    async with AsyncDohResolver(client=client):
        pass
    assert not client.is_closed
    await client.aclose()
    owned = AsyncDohResolver()
    await owned.aclose()
    assert owned._client.is_closed
