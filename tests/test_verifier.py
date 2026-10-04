from __future__ import annotations

import importlib.util
import sys
from datetime import timedelta
from typing import cast

import anyio
import pytest

from pyevp import (
    AsyncCache,
    AsyncVerifier,
    CacheEntry,
    DiscoveryError,
    ErrorCode,
    EVPError,
    InMemoryCache,
    NullCache,
    PolicyError,
    Profile,
    TokenError,
    Verifier,
)
from pyevp.testing import (
    AsyncInMemoryHttp,
    FakeBrowser,
    FakeIssuer,
    FixedClock,
    InMemoryDns,
    InMemoryHttp,
    make_async_verifier,
    make_verifier,
)

from .conftest import AUDIENCE, EMAIL


def _http(verifier: Verifier) -> InMemoryHttp:
    fetcher = verifier._fetcher
    assert isinstance(fetcher, InMemoryHttp)
    return fetcher


def test_sync_verify(verifier: Verifier, token: str, nonce: str) -> None:
    result = verifier.verify(token, nonce=nonce, email=EMAIL)
    assert result.email == EMAIL
    assert result.issuer == "https://issuer.example"
    assert result.claims["email_verified"] is True


@pytest.mark.anyio
async def test_async_verify(issuer: FakeIssuer, token: str, nonce: str) -> None:
    verifier = make_async_verifier(issuer, audience=AUDIENCE)
    result = await verifier.verify(token, nonce=nonce, email=EMAIL)
    assert result.email == EMAIL


@pytest.mark.anyio
async def test_async_error(issuer: FakeIssuer, token: str) -> None:
    verifier = make_async_verifier(issuer, audience=AUDIENCE)
    with pytest.raises(TokenError) as exc:
        await verifier.verify(token, nonce="nope", email=None)
    assert exc.value.code is ErrorCode.NONCE_MISMATCH


def test_metadata_and_jwks_are_cached(
    issuer: FakeIssuer, browser: FakeBrowser, verifier: Verifier, nonce: str
) -> None:
    for _ in range(3):
        token = browser.present(
            issuer.issue(EMAIL, browser.public_jwk), audience=AUDIENCE, nonce=nonce
        )
        verifier.verify(token, nonce=nonce, email=None)
    assert _http(verifier).requests == [issuer.metadata_url, issuer.jwks_uri]


class _AsyncCache:
    """An AsyncCache that records calls and yields to the loop on each one."""

    def __init__(self, clock: FixedClock) -> None:
        self.inner = InMemoryCache(clock=clock)
        self.calls: list[str] = []

    async def get(self, key: str) -> CacheEntry | None:
        await anyio.sleep(0)
        self.calls.append(f"get {key}")
        return self.inner.get(key)

    async def set(self, key: str, entry: CacheEntry, ttl: timedelta) -> None:
        await anyio.sleep(0)
        self.calls.append(f"set {key}")
        self.inner.set(key, entry, ttl)


@pytest.mark.anyio
async def test_async_cache_is_awaited(
    issuer: FakeIssuer, browser: FakeBrowser, nonce: str, clock: FixedClock
) -> None:
    cache = _AsyncCache(clock)
    typed: AsyncCache = cache  # checked statically by ty
    verifier = make_async_verifier(issuer, audience=AUDIENCE, cache=typed)
    for _ in range(2):
        token = browser.present(
            issuer.issue(EMAIL, browser.public_jwk), audience=AUDIENCE, nonce=nonce
        )
        assert (await verifier.verify(token, nonce=nonce, email=None)).email == EMAIL
    meta, jwks = issuer.metadata_url, issuer.jwks_uri
    assert cache.calls == [
        f"get {meta}",
        f"set {meta}",
        f"get {jwks}",
        f"set {jwks}",
        f"get {meta}",
        f"get {jwks}",
    ]
    fetcher = verifier._fetcher
    assert isinstance(fetcher, AsyncInMemoryHttp)
    assert fetcher.requests == [meta, jwks]


@pytest.mark.anyio
async def test_async_cache_refresh_is_rate_limited(
    issuer: FakeIssuer, browser: FakeBrowser, nonce: str, clock: FixedClock
) -> None:
    verifier = make_async_verifier(issuer, audience=AUDIENCE, cache=_AsyncCache(clock))

    def fresh_token() -> str:
        return browser.present(
            issuer.issue(EMAIL, browser.public_jwk), audience=AUDIENCE, nonce=nonce
        )

    await verifier.verify(fresh_token(), nonce=nonce, email=None)
    issuer.rotate_key()
    with pytest.raises(EVPError) as exc:
        await verifier.verify(fresh_token(), nonce=nonce, email=None)
    assert exc.value.code is ErrorCode.EVT_SIGNATURE_INVALID
    clock.advance(timedelta(minutes=2))
    assert (await verifier.verify(fresh_token(), nonce=nonce, email=None)).email == EMAIL


def test_null_cache_fetches_every_time(issuer: FakeIssuer, token: str, nonce: str) -> None:
    verifier = make_verifier(issuer, audience=AUDIENCE, cache=NullCache())
    verifier.verify(token, nonce=nonce, email=None)
    verifier.verify(token, nonce=nonce, email=None)
    assert len(_http(verifier).requests) == 4


def test_key_rotation_refreshes_jwks_once_interval_passed(
    issuer: FakeIssuer, browser: FakeBrowser, verifier: Verifier, nonce: str, clock: FixedClock
) -> None:
    def fresh_token() -> str:
        return browser.present(
            issuer.issue(EMAIL, browser.public_jwk), audience=AUDIENCE, nonce=nonce
        )

    verifier.verify(fresh_token(), nonce=nonce, email=None)
    issuer.rotate_key()

    # Within min_refresh_interval the cached (stale) key set is reused.
    with pytest.raises(EVPError) as exc:
        verifier.verify(fresh_token(), nonce=nonce, email=None)
    assert exc.value.code is ErrorCode.EVT_SIGNATURE_INVALID

    clock.advance(timedelta(minutes=2))
    assert verifier.verify(fresh_token(), nonce=nonce, email=None).email == EMAIL
    assert _http(verifier).requests.count(issuer.jwks_uri) == 2


def test_failed_refreshes_are_rate_limited(
    issuer: FakeIssuer, browser: FakeBrowser, verifier: Verifier, nonce: str, clock: FixedClock
) -> None:
    def fresh_token() -> str:
        return browser.present(
            issuer.issue(EMAIL, browser.public_jwk), audience=AUDIENCE, nonce=nonce
        )

    verifier.verify(fresh_token(), nonce=nonce, email=None)
    issuer.rotate_key()
    del _http(verifier).documents[issuer.jwks_uri]
    clock.advance(timedelta(minutes=2))

    codes = []
    for _ in range(4):
        with pytest.raises(EVPError) as exc:
            verifier.verify(fresh_token(), nonce=nonce, email=None)
        codes.append(exc.value.code)
    assert codes == [ErrorCode.ISSUER_UNREACHABLE] + [ErrorCode.EVT_SIGNATURE_INVALID] * 3
    assert _http(verifier).requests.count(issuer.jwks_uri) == 2

    clock.advance(timedelta(minutes=2))
    with pytest.raises(EVPError):
        verifier.verify(fresh_token(), nonce=nonce, email=None)
    assert _http(verifier).requests.count(issuer.jwks_uri) == 3


class _GatedHttp(AsyncInMemoryHttp):
    """Holds key set fetches until ``release`` is set."""

    release: anyio.Event | None = None

    async def fetch_json(self, url: str) -> object:
        if self.release is not None and url.endswith("jwks.json"):
            await self.release.wait()
        return await super().fetch_json(url)


@pytest.mark.anyio
async def test_concurrent_refreshes_are_coalesced(
    issuer: FakeIssuer, browser: FakeBrowser, nonce: str, clock: FixedClock
) -> None:
    verifier = make_async_verifier(issuer, audience=AUDIENCE)
    plain = verifier._fetcher
    assert isinstance(plain, AsyncInMemoryHttp)
    http = _GatedHttp(plain.documents)
    verifier = AsyncVerifier(
        audience=AUDIENCE, resolver=verifier._resolver, fetcher=http, clock=clock
    )

    def fresh_token() -> str:
        return browser.present(
            issuer.issue(EMAIL, browser.public_jwk), audience=AUDIENCE, nonce=nonce
        )

    await verifier.verify(fresh_token(), nonce=nonce, email=None)
    issuer.rotate_key()
    clock.advance(timedelta(minutes=2))
    http.release = anyio.Event()

    results: list[ErrorCode | None] = []

    async def verify() -> None:
        try:
            await verifier.verify(fresh_token(), nonce=nonce, email=None)
            results.append(None)
        except EVPError as exc:
            results.append(exc.code)

    async with anyio.create_task_group() as tg:
        for _ in range(10):
            tg.start_soon(verify)
        await anyio.wait_all_tasks_blocked()
        http.release.set()

    assert http.requests.count(issuer.jwks_uri) == 2
    assert results.count(None) == 1
    assert results.count(ErrorCode.EVT_SIGNATURE_INVALID) == 9


def test_gmail_like_issuer(clock: FixedClock, nonce: str) -> None:
    gmail = FakeIssuer.gmail_like(clock=clock, iss_format="host")
    browser = FakeBrowser(alg="EdDSA", clock=clock)
    token = browser.present(
        gmail.issue("bob@gmail.example", browser.public_jwk), audience=AUDIENCE, nonce=nonce
    )
    assert make_verifier(gmail, audience=AUDIENCE).verify(
        token, nonce=nonce, email=None
    ).issuer == ("https://accounts.google.example")
    with pytest.raises(EVPError):
        make_verifier(gmail, audience=AUDIENCE, profile=Profile.draft_hardt_02()).verify(
            token, nonce=nonce, email=None
        )


def test_strict_profile_accepts_conforming_tokens(
    issuer: FakeIssuer, token: str, nonce: str
) -> None:
    verifier = make_verifier(issuer, audience=AUDIENCE, profile=Profile.draft_hardt_02())
    assert verifier.verify(token, nonce=nonce, email=None).email == EMAIL


def test_es256(clock: FixedClock, nonce: str) -> None:
    issuer = FakeIssuer(alg="ES256", clock=clock)
    browser = FakeBrowser(alg="ES256", clock=clock)
    token = browser.present(issuer.issue(EMAIL, browser.public_jwk), audience=AUDIENCE, nonce=nonce)
    assert (
        make_verifier(issuer, audience=AUDIENCE).verify(token, nonce=nonce, email=None).email
        == EMAIL
    )


def test_multiple_issuers(clock: FixedClock, nonce: str) -> None:
    a = FakeIssuer("a.example", email_domains=("a.test",), clock=clock)
    b = FakeIssuer("b.example", email_domains=("b.test",), clock=clock)
    browser = FakeBrowser(clock=clock)
    verifier = make_verifier(a, b, audience=AUDIENCE)
    token = browser.present(b.issue("x@b.test", browser.public_jwk), audience=AUDIENCE, nonce=nonce)
    assert verifier.verify(token, nonce=nonce, email=None).issuer == "https://b.example"
    # a.example cannot vouch for b.test addresses.
    token = browser.present(a.issue("x@b.test", browser.public_jwk), audience=AUDIENCE, nonce=nonce)
    with pytest.raises(DiscoveryError) as exc:
        verifier.verify(token, nonce=nonce, email=None)
    assert exc.value.code is ErrorCode.ISSUER_MISMATCH


def test_transport_failure_is_issuer_unreachable(
    issuer: FakeIssuer, token: str, nonce: str, clock: FixedClock
) -> None:
    verifier = Verifier(
        audience=AUDIENCE,
        resolver=InMemoryDns(issuer.dns_records()),
        fetcher=InMemoryHttp({}),
        clock=clock,
    )
    with pytest.raises(DiscoveryError) as exc:
        verifier.verify(token, nonce=nonce, email=None)
    assert exc.value.code is ErrorCode.ISSUER_UNREACHABLE
    assert exc.value.__cause__ is not None


class _BrokenCache:
    def __init__(self, fail: str) -> None:
        self.fail = fail

    def get(self, key: str) -> CacheEntry | None:
        if self.fail == "get":
            raise ConnectionError("cache down")
        return None

    def set(self, key: str, entry: CacheEntry, ttl: timedelta) -> None:
        if self.fail == "set":
            raise ConnectionError("cache down")


class _AsyncBrokenCache:
    def __init__(self, fail: str) -> None:
        self.sync = _BrokenCache(fail)

    async def get(self, key: str) -> CacheEntry | None:
        return self.sync.get(key)

    async def set(self, key: str, entry: CacheEntry, ttl: timedelta) -> None:
        self.sync.set(key, entry, ttl)


@pytest.mark.parametrize("fail", ["get", "set"])
def test_cache_failures_propagate_unchanged(
    issuer: FakeIssuer, token: str, nonce: str, fail: str
) -> None:
    # The application's own infrastructure failed, not the issuer: no ISSUER_UNREACHABLE.
    verifier = make_verifier(issuer, audience=AUDIENCE, cache=_BrokenCache(fail))
    with pytest.raises(ConnectionError):
        verifier.verify(token, nonce=nonce, email=None)


@pytest.mark.anyio
@pytest.mark.parametrize("fail", ["get", "set"])
async def test_async_cache_failures_propagate_unchanged(
    issuer: FakeIssuer, token: str, nonce: str, fail: str
) -> None:
    for cache in (_BrokenCache(fail), _AsyncBrokenCache(fail)):
        verifier = make_async_verifier(issuer, audience=AUDIENCE, cache=cache)
        with pytest.raises(ConnectionError):
            await verifier.verify(token, nonce=nonce, email=None)


def test_policy_errors_say_nothing_about_authenticity(
    issuer: FakeIssuer, browser: FakeBrowser, nonce: str
) -> None:
    forger = FakeIssuer(clock=issuer.clock)  # same issuer name, another key
    token = browser.present(forger.issue(EMAIL, browser.public_jwk), audience=AUDIENCE, nonce=nonce)
    verifier = make_verifier(issuer, audience=AUDIENCE)
    with pytest.raises(PolicyError):
        verifier.verify(token, nonce=nonce, email="mallory@example.com")
    with pytest.raises(TokenError) as exc:
        verifier.verify(token, nonce=nonce, email=EMAIL)
    assert exc.value.code is ErrorCode.EVT_SIGNATURE_INVALID


def test_audience_override(issuer: FakeIssuer, browser: FakeBrowser, nonce: str) -> None:
    verifier = make_verifier(issuer, audience=AUDIENCE)
    token = browser.present(
        issuer.issue(EMAIL, browser.public_jwk), audience="https://other.example", nonce=nonce
    )
    assert (
        verifier.verify(token, nonce=nonce, audience="https://other.example", email=None).email
        == EMAIL
    )


@pytest.mark.parametrize(
    "audience", ["rp.example", "https://rp.example/", "https://rp.example/login", "ftp://rp"]
)
def test_invalid_audience(issuer: FakeIssuer, audience: str) -> None:
    with pytest.raises(ValueError, match="origin"):
        make_verifier(issuer, audience=audience)


def test_localhost_audience_allowed(issuer: FakeIssuer) -> None:
    assert make_verifier(issuer, audience="http://localhost:8000").audience == (
        "http://localhost:8000"
    )


@pytest.mark.parametrize("cls", [Verifier, AsyncVerifier])
@pytest.mark.parametrize(
    ("missing", "named"),
    [
        (("dns", "pyevp.adapters.dnspython"), "dnspython"),
        (("httpx", "httpx2", "pyevp.adapters._http", "pyevp.adapters.httpx"), "httpx2 or httpx"),
    ],
)
def test_default_names_missing_extras(
    monkeypatch: pytest.MonkeyPatch,
    cls: type[Verifier] | type[AsyncVerifier],
    missing: tuple[str, ...],
    named: str,
) -> None:
    for module in missing:
        monkeypatch.setitem(sys.modules, module, None)
    # Without the dns extra installed, the resolver import would fail first.
    kwargs = {"resolver": InMemoryDns()} if named != "dnspython" else {}
    with pytest.raises(ImportError, match=named) as exc:
        cls.default(audience=AUDIENCE, **kwargs)
    assert "pip install 'pyevp[dns,httpx2]'" in str(exc.value)


def test_default_accepts_port_overrides(issuer: FakeIssuer, token: str, nonce: str) -> None:
    verifier = Verifier.default(
        audience=AUDIENCE,
        resolver=InMemoryDns(issuer.dns_records()),
        fetcher=InMemoryHttp(issuer.http_documents()),
        clock=issuer.clock,
    )
    assert verifier.verify(token, nonce=nonce, email=None).email == EMAIL


class _Port:
    """Stands in for a resolver and a fetcher; counts close calls."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.closed = 0

    def resolve_txt(self, name: str) -> list[str]:
        return []

    def fetch_json(self, url: str) -> object:
        return {}

    def close(self) -> None:
        self.closed += 1


class _AsyncPort:
    def __init__(self, *args: object, **kwargs: object) -> None:
        self.closed = 0

    async def resolve_txt(self, name: str) -> list[str]:
        return []

    async def fetch_json(self, url: str) -> object:
        return {}

    async def aclose(self) -> None:
        self.closed += 1


# Verifier.default() imports the dnspython adapter, which needs the extra.
needs_dnspython = pytest.mark.skipif(
    importlib.util.find_spec("dns") is None, reason="dnspython is not installed"
)


def _fake_default_ports(monkeypatch: pytest.MonkeyPatch, port: type) -> None:
    import pyevp.adapters.dnspython  # noqa: PLC0415
    import pyevp.adapters.httpx  # noqa: PLC0415

    for module, name in [
        (pyevp.adapters.dnspython, "DnsPythonResolver"),
        (pyevp.adapters.dnspython, "AsyncDnsPythonResolver"),
        (pyevp.adapters.httpx, "HttpxFetcher"),
        (pyevp.adapters.httpx, "AsyncHttpxFetcher"),
    ]:
        monkeypatch.setattr(module, name, port)


def _closed(*ports: object) -> list[int]:
    return [cast(_Port | _AsyncPort, p).closed for p in ports]


@needs_dnspython
def test_close_closes_what_default_created(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_default_ports(monkeypatch, _Port)
    with Verifier.default(audience=AUDIENCE) as verifier:
        ports = verifier._resolver, verifier._fetcher
    assert _closed(*ports) == [1, 1]
    verifier.close()
    assert _closed(*ports) == [1, 1]


@needs_dnspython
def test_close_leaves_ports_passed_in_open(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_default_ports(monkeypatch, _Port)
    fetcher = _Port()
    with Verifier.default(audience=AUDIENCE, fetcher=fetcher) as verifier:
        resolver = verifier._resolver
    assert _closed(resolver, fetcher) == [1, 0]
    with Verifier(audience=AUDIENCE, resolver=_Port(), fetcher=fetcher):
        pass
    assert fetcher.closed == 0


@needs_dnspython
@pytest.mark.anyio
async def test_aclose_closes_what_default_created(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_default_ports(monkeypatch, _AsyncPort)
    async with AsyncVerifier.default(audience=AUDIENCE) as verifier:
        ports = verifier._resolver, verifier._fetcher
    await verifier.aclose()
    assert _closed(*ports) == [1, 1]

    resolver = _AsyncPort()
    async with AsyncVerifier.default(audience=AUDIENCE, resolver=resolver) as verifier:
        fetcher = verifier._fetcher
    assert _closed(resolver, fetcher) == [0, 1]
