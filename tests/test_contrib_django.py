from __future__ import annotations

import contextlib
import re
import warnings
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest
from asgiref.sync import sync_to_async
from django.contrib.sessions.backends.base import SessionBase
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.cache import caches
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.db import connections, transaction
from django.http import HttpRequest, HttpResponse
from django.template import Context, Engine
from django.test import RequestFactory, override_settings

from pyevp import (
    AsyncCache,
    AsyncReplayGuard,
    Cache,
    CacheEntry,
    ErrorCode,
    EVPError,
    ReplayGuard,
    TokenError,
    Verifier,
    token_input,
)
from pyevp.contrib.django import (
    AsyncEVPCache,
    AsyncEVPReplayGuard,
    EVPCache,
    EVPReplayGuard,
    aget_nonce,
    averify_request,
    get_nonce,
    verify_request,
)
from pyevp.observability import VerificationEvent
from pyevp.testing import FakeBrowser, FakeIssuer, FixedClock, make_async_verifier, make_verifier

from . import _django
from .conftest import AUDIENCE, EMAIL

_django.configure()

# Models can only be imported once the app registry is ready.
from pyevp.contrib.django.models import UsedToken  # noqa: E402

LONG_URL = "https://issuer.example/" + "k" * 300


@pytest.fixture(scope="module", autouse=True)
def _database() -> Any:
    call_command("migrate", verbosity=0)
    call_command("createcachetable", verbosity=0)
    yield
    connections.close_all()


@pytest.fixture(autouse=True)
def _clean() -> None:
    for alias in ("default", "db"):
        caches[alias].clear()
    UsedToken.objects.all().delete()


def test_satisfies_protocols() -> None:
    cache: Cache = EVPCache()
    async_cache: AsyncCache = AsyncEVPCache()
    guard: ReplayGuard = EVPReplayGuard()
    async_guard: AsyncReplayGuard = AsyncEVPReplayGuard()
    assert isinstance(guard, ReplayGuard)
    assert isinstance(async_guard, AsyncReplayGuard)
    assert cache.get("missing") is None
    assert async_cache is not None


def test_migrations_match_models() -> None:
    call_command("makemigrations", "pyevp", check=True, dry_run=True, verbosity=0)


# --- cache ---------------------------------------------------------------------------


@pytest.mark.parametrize("alias", ["default", "db"])
def test_cache_round_trip(alias: str, clock: FixedClock) -> None:
    cache = EVPCache(alias)
    entry = CacheEntry({"issuer": "https://issuer.example"}, clock())
    cache.set("https://issuer.example/meta", entry, timedelta(minutes=10))
    assert cache.get("https://issuer.example/meta") == entry
    assert cache.get("https://issuer.example/other") is None


def test_cache_keys_have_a_fixed_length(clock: FixedClock) -> None:
    # Memcached rejects keys over 250 bytes; Django warns about them on every backend,
    # which pytest turns into an error here.
    cache = EVPCache()
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        cache.set(LONG_URL, CacheEntry(1, clock()), timedelta(minutes=10))
        assert cache.get(LONG_URL) == CacheEntry(1, clock())
    assert len(cache._key(LONG_URL)) == len("evp:1:") + 64


def test_cache_alias_and_prefix(clock: FixedClock) -> None:
    EVPCache("db", prefix="x:").set("meta", CacheEntry(1, clock()), timedelta(minutes=10))
    assert EVPCache("db", prefix="x:").get("meta") is not None
    assert EVPCache("db").get("meta") is None
    assert EVPCache("default", prefix="x:").get("meta") is None


@pytest.mark.parametrize("value", ["not an entry", (1, 2), (1, 2, 3), None])
def test_cache_ignores_foreign_values(value: object) -> None:
    cache = EVPCache()
    caches["default"].set(cache._key("meta"), value)
    assert cache.get("meta") is None


def test_cache_stores_only_built_in_types(clock: FixedClock) -> None:
    # Pickled PyEVP classes would tie the entries to this version of the library.
    cache = EVPCache()
    cache.set("meta", CacheEntry({"keys": []}, clock()), timedelta(minutes=10))
    stored = caches["default"].get(cache._key("meta"))
    assert stored == ({"keys": []}, clock())
    assert type(stored) is tuple


def test_cache_passes_ttl(monkeypatch: pytest.MonkeyPatch, clock: FixedClock) -> None:
    seen: list[Any] = []
    monkeypatch.setattr(caches["default"], "set", lambda *a, **kw: seen.append(kw["timeout"]))
    EVPCache().set("meta", CacheEntry(1, clock()), timedelta(minutes=10))
    assert seen == [600]


@pytest.mark.anyio
async def test_async_cache_shares_entries(clock: FixedClock) -> None:
    entry = CacheEntry({"issuer": "https://issuer.example"}, clock())
    await AsyncEVPCache("db").set(LONG_URL, entry, timedelta(minutes=10))
    assert await AsyncEVPCache("db").get(LONG_URL) == entry
    assert await AsyncEVPCache("db").get("missing") is None


# --- replay guard ----------------------------------------------------------------------


def test_replay_guard(clock: FixedClock) -> None:
    guard = EVPReplayGuard(clock=clock)
    expires = clock() + timedelta(minutes=5)
    assert guard.mark_used("k", expires) is True
    assert guard.mark_used("k", expires) is False
    assert guard.mark_used("other", expires) is True
    assert UsedToken.objects.count() == 2


def test_records_are_not_evicted_by_volume(clock: FixedClock) -> None:
    # A cache would cull here (Django's default MAX_ENTRIES is 300) and forget "k".
    guard = EVPReplayGuard(clock=clock)
    expires = clock() + timedelta(minutes=5)
    assert guard.mark_used("k", expires) is True
    for i in range(400):
        assert guard.mark_used(f"filler-{i}", expires) is True
    assert guard.mark_used("k", expires) is False


def test_expired_records_are_purged(clock: FixedClock) -> None:
    guard = EVPReplayGuard(clock=clock)
    guard.mark_used("old", clock() + timedelta(minutes=5))
    clock.advance(timedelta(minutes=6))
    guard.mark_used("new", clock() + timedelta(minutes=5))
    assert UsedToken.objects.count() == 1


def test_arbitrary_keys_fit(clock: FixedClock) -> None:
    guard = EVPReplayGuard(clock=clock)
    assert guard.mark_used("x" * 1000, clock() + timedelta(minutes=5)) is True
    assert guard.mark_used("x" * 1000, clock() + timedelta(minutes=5)) is False


def test_without_use_tz(clock: FixedClock) -> None:
    with override_settings(USE_TZ=False):
        guard = EVPReplayGuard(clock=clock)
        expires = clock() + timedelta(minutes=5)
        assert guard.mark_used("k", expires) is True
        assert guard.mark_used("k", expires) is False
        [row] = UsedToken.objects.all()
        assert row.expires_at.tzinfo is None
        assert row.expires_at == expires.replace(tzinfo=None)


def test_database_errors_propagate(monkeypatch: pytest.MonkeyPatch, clock: FixedClock) -> None:
    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("database down")

    monkeypatch.setattr(UsedToken.objects, "using", broken)
    with pytest.raises(RuntimeError):
        EVPReplayGuard(clock=clock).mark_used("k", clock() + timedelta(minutes=5))


def test_refuses_to_run_inside_a_transaction(clock: FixedClock) -> None:
    # A savepoint would be rolled back with the caller's transaction, forgetting the token.
    guard = EVPReplayGuard(clock=clock)
    with pytest.raises(RuntimeError, match="ATOMIC_REQUESTS"), transaction.atomic():
        guard.mark_used("k", clock() + timedelta(minutes=5))
    assert not UsedToken.objects.exists()


def test_outer_rollback_does_not_forget_tokens(issuer: FakeIssuer, token: str, nonce: str) -> None:
    verifier = make_verifier(
        issuer, audience=AUDIENCE, replay_guard=EVPReplayGuard("replay", clock=issuer.clock)
    )
    with transaction.atomic():
        assert verifier.verify(token, nonce=nonce, email=EMAIL).email == EMAIL
        transaction.set_rollback(True)
    with pytest.raises(TokenError) as exc:
        verifier.verify(token, nonce=nonce, email=EMAIL)
    assert exc.value.code is ErrorCode.TOKEN_REPLAYED


@contextlib.contextmanager
def _manual_transaction(using: str = "default") -> Iterator[None]:
    """Autocommit off, as with AUTOCOMMIT=False; rolled back on exit."""
    transaction.set_autocommit(False, using=using)
    try:
        yield
    finally:
        transaction.rollback(using=using)
        transaction.set_autocommit(True, using=using)


def test_refuses_to_run_with_autocommit_off(clock: FixedClock) -> None:
    guard = EVPReplayGuard(clock=clock)
    expires = clock() + timedelta(minutes=5)
    with _manual_transaction():
        UsedToken.objects.create(key="earlier-write", expires_at=expires)
        with pytest.raises(RuntimeError, match="AUTOCOMMIT"):
            guard.mark_used("k", expires)
    assert not UsedToken.objects.exists()


def test_manual_rollback_does_not_reopen_tokens(issuer: FakeIssuer, token: str, nonce: str) -> None:
    verifier = make_verifier(
        issuer, audience=AUDIENCE, replay_guard=EVPReplayGuard(clock=issuer.clock)
    )
    with _manual_transaction():
        UsedToken.objects.create(key="earlier-write", expires_at=issuer.clock())
        with pytest.raises(RuntimeError):
            verifier.verify(token, nonce=nonce, email=EMAIL)
    # Nothing was half-recorded: the token is accepted once, then never again.
    assert verifier.verify(token, nonce=nonce, email=EMAIL).email == EMAIL
    with pytest.raises(TokenError) as exc:
        verifier.verify(token, nonce=nonce, email=EMAIL)
    assert exc.value.code is ErrorCode.TOKEN_REPLAYED


def test_dedicated_alias_survives_manual_rollback(
    issuer: FakeIssuer, token: str, nonce: str
) -> None:
    verifier = make_verifier(
        issuer, audience=AUDIENCE, replay_guard=EVPReplayGuard("replay", clock=issuer.clock)
    )
    with _manual_transaction():
        assert verifier.verify(token, nonce=nonce, email=EMAIL).email == EMAIL
    with pytest.raises(TokenError) as exc:
        verifier.verify(token, nonce=nonce, email=EMAIL)
    assert exc.value.code is ErrorCode.TOKEN_REPLAYED


def test_works_inside_django_test_case_transactions(clock: FixedClock) -> None:
    # django.test.TestCase wraps each test in atomic blocks it marks like this.
    outer = transaction.atomic()
    outer._from_testcase = True
    guard = EVPReplayGuard(clock=clock)
    with outer:
        assert guard.mark_used("k", clock() + timedelta(minutes=5)) is True
        assert guard.mark_used("k", clock() + timedelta(minutes=5)) is False


@pytest.mark.anyio
async def test_async_replay_guard(clock: FixedClock) -> None:
    guard = AsyncEVPReplayGuard(clock=clock)
    expires = clock() + timedelta(minutes=5)
    assert await guard.mark_used("k", expires) is True
    assert await guard.mark_used("k", expires) is False


# --- end to end ------------------------------------------------------------------------


def test_verifier_end_to_end(issuer: FakeIssuer, token: str, nonce: str) -> None:
    verifier = make_verifier(
        issuer,
        audience=AUDIENCE,
        cache=EVPCache("db"),
        replay_guard=EVPReplayGuard(clock=issuer.clock),
    )
    assert verifier.verify(token, nonce=nonce, email=EMAIL).email == EMAIL
    with pytest.raises(TokenError) as exc:
        verifier.verify(token, nonce=nonce, email=EMAIL)
    assert exc.value.code is ErrorCode.TOKEN_REPLAYED


@pytest.mark.anyio
async def test_async_verifier_with_database_cache(
    issuer: FakeIssuer, token: str, nonce: str
) -> None:
    # A synchronous DatabaseCache call on the event loop raises SynchronousOnlyOperation.
    verifier = make_async_verifier(
        issuer,
        audience=AUDIENCE,
        cache=AsyncEVPCache("db"),
        replay_guard=AsyncEVPReplayGuard(clock=issuer.clock),
    )
    assert (await verifier.verify(token, nonce=nonce, email=EMAIL)).email == EMAIL
    with pytest.raises(TokenError) as exc:
        await verifier.verify(token, nonce=nonce, email=EMAIL)
    assert exc.value.code is ErrorCode.TOKEN_REPLAYED


# --- forms: nonce, template tag and verify_request ------------------------------------

_TAGS = Engine(libraries={"pyevp": "pyevp.contrib.django.templatetags.pyevp"})


def _with_session(request: HttpRequest, session: SessionBase | None = None) -> HttpRequest:
    if session is None:
        SessionMiddleware(lambda r: HttpResponse()).process_request(request)
    else:
        request.session = session  # ty: ignore[unresolved-attribute]
    return request


def _render(request: HttpRequest, source: str) -> str:
    return _TAGS.from_string("{% load pyevp %}" + source).render(Context({"request": request}))


def _nonces(html: str) -> list[str]:
    return re.findall(r'nonce="([^"]+)"', html)


def _session(request: HttpRequest) -> SessionBase:
    return request.session  # ty: ignore[unresolved-attribute]


def _stored(request: HttpRequest) -> list[str]:
    """The nonces the request's session holds, oldest first."""
    return [nonce for nonce, _ in _session(request).get("evp_nonce", [])]


def _page() -> tuple[HttpRequest, str]:
    """Render a page with a token input and return its request and nonce."""
    page = _with_session(RequestFactory().get("/"))
    (nonce,) = _nonces(_render(page, "{% evp_token_input %}"))
    return page, nonce


def _submit(page: HttpRequest, **data: str) -> HttpRequest:
    return _with_session(RequestFactory().post("/", data), _session(page))


def _present(issuer: FakeIssuer, browser: FakeBrowser, nonce: str, email: str = EMAIL) -> str:
    return browser.present(issuer.issue(email, browser.public_jwk), audience=AUDIENCE, nonce=nonce)


def test_tag_renders_the_token_input() -> None:
    page = _with_session(RequestFactory().get("/"))
    html = _render(page, '{% evp_token_input %}{% evp_token_input field="token" %}')
    first, second = _nonces(html)
    # One nonce per page: forms rendered in the same request share it.
    assert [first] == [second] == _stored(page)
    assert html == token_input(first) + token_input(first, field="token")


def test_tag_needs_the_request() -> None:
    with pytest.raises(ImproperlyConfigured):
        _TAGS.from_string("{% load pyevp %}{% evp_token_input %}").render(Context({}))


def test_each_request_gets_a_new_nonce() -> None:
    page, nonce = _page()
    again = _with_session(RequestFactory().get("/"), _session(page))
    assert get_nonce(again) != nonce
    # The first page's nonce stays usable, for a form left open in another tab.
    assert _stored(page) == [nonce, get_nonce(again)]


def test_verify_request(issuer: FakeIssuer, browser: FakeBrowser) -> None:
    verifier = make_verifier(issuer, audience=AUDIENCE, replay_guard=EVPReplayGuard())
    page, nonce = _page()
    token = _present(issuer, browser, nonce)
    request = _submit(page, evt=token)
    result = verify_request(request, verifier, email=EMAIL)
    assert result is not None
    assert result.email == EMAIL
    assert _stored(request) == []
    # A form rendered after verification gets a nonce that the session knows.
    renewed = get_nonce(request)
    assert _stored(request) == [renewed]

    with pytest.raises(TokenError) as exc:
        verify_request(_submit(page, evt=token), verifier, email=EMAIL)
    assert exc.value.code is ErrorCode.NONCE_MISMATCH


def test_verify_request_keeps_the_nonce_without_a_token(verifier: Verifier) -> None:
    page, nonce = _page()
    assert verify_request(_submit(page, email=EMAIL), verifier, email=EMAIL) is None
    assert verify_request(_submit(page, evt=""), verifier, email=EMAIL) is None
    assert _stored(page) == [nonce]


def test_verify_request_from_two_tabs(issuer: FakeIssuer, browser: FakeBrowser) -> None:
    verifier = make_verifier(issuer, audience=AUDIENCE)
    page, first = _page()
    second = get_nonce(_with_session(RequestFactory().get("/"), _session(page)))
    for nonce in (second, first):
        token = _present(issuer, browser, nonce)
        assert verify_request(_submit(page, evt=token), verifier, email=EMAIL) is not None


def test_verify_request_without_a_session_nonce(issuer: FakeIssuer, browser: FakeBrowser) -> None:
    events: list[VerificationEvent] = []
    verifier = make_verifier(issuer, audience=AUDIENCE, observer=events.append)
    page, nonce = _page()
    del _session(page)["evp_nonce"]  # the session expired
    with pytest.raises(TokenError) as exc:
        verify_request(_submit(page, evt=_present(issuer, browser, nonce)), verifier, email=EMAIL)
    assert exc.value.code is ErrorCode.NONCE_MISMATCH
    assert [e.code for e in events] == [ErrorCode.NONCE_MISMATCH]


def test_verify_request_raises_on_rejection(issuer: FakeIssuer, browser: FakeBrowser) -> None:
    verifier = make_verifier(issuer, audience=AUDIENCE)
    page, nonce = _page()
    token = _present(issuer, browser, nonce, email="mallory@example.com")
    with pytest.raises(EVPError) as exc:
        verify_request(_submit(page, evt=token), verifier, email=EMAIL)
    assert exc.value.code is ErrorCode.EMAIL_MISMATCH


def test_verify_request_custom_field_and_audience(issuer: FakeIssuer, browser: FakeBrowser) -> None:
    verifier = make_verifier(issuer, audience="https://other.example")
    page, nonce = _page()
    request = _submit(page, token=_present(issuer, browser, nonce))
    result = verify_request(request, verifier, email=EMAIL, field="token", audience=AUDIENCE)
    assert result is not None


@pytest.mark.anyio
async def test_async_verify_request(issuer: FakeIssuer, browser: FakeBrowser) -> None:
    verifier = make_async_verifier(
        issuer, audience=AUDIENCE, replay_guard=AsyncEVPReplayGuard(clock=issuer.clock)
    )
    page = await sync_to_async(_with_session)(RequestFactory().get("/"))
    nonce = await aget_nonce(page)
    # The tag reuses the nonce without touching the session from async code.
    assert _nonces(_render(page, "{% evp_token_input %}")) == [nonce]

    empty = _submit(page, email=EMAIL)
    assert await averify_request(empty, verifier, email=EMAIL) is None

    token = _present(issuer, browser, nonce)
    result = await averify_request(_submit(page, evt=token), verifier, email=EMAIL)
    assert result is not None
    assert result.email == EMAIL
    with pytest.raises(TokenError) as exc:
        await averify_request(_submit(page, evt=token), verifier, email=EMAIL)
    assert exc.value.code is ErrorCode.NONCE_MISMATCH
