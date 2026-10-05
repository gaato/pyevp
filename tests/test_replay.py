from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

import pytest

from pyevp import (
    DEFAULT_PROFILE,
    AsyncReplayGuard,
    AsyncVerifier,
    ErrorCode,
    EVPError,
    InMemoryReplayGuard,
    ReplayGuard,
    Verifier,
)
from pyevp._jose import b64url_decode, b64url_encode
from pyevp.core import replay_key
from pyevp.testing import (
    AsyncInMemoryDns,
    AsyncInMemoryHttp,
    FakeBrowser,
    FakeIssuer,
    FixedClock,
    InMemoryDns,
    InMemoryHttp,
    make_async_verifier,
    make_verifier,
)
from pyevp.token import parse_token

from .conftest import AUDIENCE, EMAIL

# Order of the P-256 group.
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _malleate_es256(token: str) -> str:
    """Replace the KB-JWT signature (r, s) by (r, n - s), which is equally valid."""
    head, _, signature = token.rpartition(".")
    raw = b64url_decode(signature)
    r, s = raw[:32], int.from_bytes(raw[32:])
    return f"{head}.{b64url_encode(r + (_P256_N - s).to_bytes(32))}"


class AsyncGuard:
    def __init__(self, clock: FixedClock) -> None:
        self.inner = InMemoryReplayGuard(clock=clock)

    async def mark_used(self, key: str, expires_at: datetime) -> bool:
        return self.inner.mark_used(key, expires_at)


class BrokenGuard:
    def mark_used(self, key: str, expires_at: datetime) -> bool:
        raise ConnectionError("store down")


def test_replay_rejected(issuer: FakeIssuer, token: str, nonce: str, clock: FixedClock) -> None:
    verifier = make_verifier(
        issuer, audience=AUDIENCE, replay_guard=InMemoryReplayGuard(clock=clock)
    )
    assert verifier.verify(token, nonce=nonce, email=None).email == EMAIL
    with pytest.raises(EVPError) as exc:
        verifier.verify(token, nonce=nonce, email=None)
    assert exc.value.code is ErrorCode.TOKEN_REPLAYED


def test_malleated_signature_is_still_a_replay(
    issuer: FakeIssuer, nonce: str, clock: FixedClock
) -> None:
    browser = FakeBrowser(alg="ES256", clock=clock)
    token = browser.present(issuer.issue(EMAIL, browser.public_jwk), audience=AUDIENCE, nonce=nonce)
    twin = _malleate_es256(token)
    assert twin != token
    assert (
        make_verifier(issuer, audience=AUDIENCE).verify(twin, nonce=nonce, email=None).email
        == EMAIL
    )
    verifier = make_verifier(
        issuer, audience=AUDIENCE, replay_guard=InMemoryReplayGuard(clock=clock)
    )
    assert verifier.verify(token, nonce=nonce, email=None).email == EMAIL
    with pytest.raises(EVPError) as exc:
        verifier.verify(twin, nonce=nonce, email=None)
    assert exc.value.code is ErrorCode.TOKEN_REPLAYED


def test_replay_key_identifies_the_presentation(
    issuer: FakeIssuer, browser: FakeBrowser, token: str
) -> None:
    head, _, signature = token.rpartition(".")
    assert replay_key(parse_token(token)) == replay_key(parse_token(f"{head}.{signature[::-1]}"))
    evt = token.partition("~")[0]
    again = browser.present(evt, audience=AUDIENCE, nonce="another")
    assert replay_key(parse_token(token)) != replay_key(parse_token(again))


def test_replay_key_accepts_the_raw_token(token: str) -> None:
    assert replay_key(token) == replay_key(parse_token(token))


def test_without_guard_replay_is_not_detected(verifier: Verifier, token: str, nonce: str) -> None:
    verifier.verify(token, nonce=nonce, email=None)
    verifier.verify(token, nonce=nonce, email=None)


def test_rejected_tokens_are_not_remembered(
    issuer: FakeIssuer, token: str, nonce: str, clock: FixedClock
) -> None:
    guard = InMemoryReplayGuard(clock=clock)
    verifier = make_verifier(issuer, audience=AUDIENCE, replay_guard=guard)
    with pytest.raises(EVPError):
        verifier.verify(token, nonce="wrong", email=None)
    assert verifier.verify(token, nonce=nonce, email=None).email == EMAIL


@pytest.mark.anyio
@pytest.mark.parametrize("guard_factory", [lambda c: InMemoryReplayGuard(clock=c), AsyncGuard])
async def test_async_replay(
    issuer: FakeIssuer,
    token: str,
    nonce: str,
    clock: FixedClock,
    guard_factory: Callable[[FixedClock], ReplayGuard | AsyncReplayGuard],
) -> None:
    verifier = make_async_verifier(issuer, audience=AUDIENCE, replay_guard=guard_factory(clock))
    await verifier.verify(token, nonce=nonce, email=None)
    with pytest.raises(EVPError) as exc:
        await verifier.verify(token, nonce=nonce, email=None)
    assert exc.value.code is ErrorCode.TOKEN_REPLAYED


def test_guard_failures_propagate_unchanged(issuer: FakeIssuer, token: str, nonce: str) -> None:
    verifier = make_verifier(issuer, audience=AUDIENCE, replay_guard=BrokenGuard())
    with pytest.raises(ConnectionError):
        verifier.verify(token, nonce=nonce, email=None)


def test_expiry_matches_token_lifetime(
    issuer: FakeIssuer, browser: FakeBrowser, nonce: str, clock: FixedClock
) -> None:
    seen: list[datetime] = []

    class Recorder:
        def mark_used(self, key: str, expires_at: datetime) -> bool:
            seen.append(expires_at)
            return True

    verifier = make_verifier(issuer, audience=AUDIENCE, replay_guard=Recorder())
    token = browser.present(issuer.issue(EMAIL, browser.public_jwk), audience=AUDIENCE, nonce=nonce)
    verifier.verify(token, nonce=nonce, email=None)
    profile = verifier.profile
    assert seen == [clock() + profile.max_token_age + profile.clock_skew]


def test_in_memory_guard_forgets_expired_keys(clock: FixedClock) -> None:
    guard = InMemoryReplayGuard(clock=clock)
    assert guard.mark_used("k", clock() + timedelta(minutes=1))
    assert not guard.mark_used("k", clock() + timedelta(minutes=1))
    clock.advance(timedelta(minutes=2))
    assert guard.mark_used("k", clock() + timedelta(minutes=1))


def test_token_expires_when_its_record_does(
    issuer: FakeIssuer, token: str, nonce: str, clock: FixedClock
) -> None:
    verifier = make_verifier(
        issuer, audience=AUDIENCE, replay_guard=InMemoryReplayGuard(clock=clock)
    )
    verifier.verify(token, nonce=nonce, email=None)
    lifetime = verifier.profile.max_token_age + verifier.profile.clock_skew

    clock.advance(lifetime - timedelta(microseconds=1))
    with pytest.raises(EVPError) as exc:
        verifier.verify(token, nonce=nonce, email=None)
    assert exc.value.code is ErrorCode.TOKEN_REPLAYED

    clock.advance(timedelta(microseconds=1))  # the guard has now forgotten the token
    with pytest.raises(EVPError) as exc:
        verifier.verify(token, nonce=nonce, email=None)
    assert exc.value.code is ErrorCode.TOKEN_EXPIRED


# The replay record lives until the token would fail the freshness checks.
_LIFETIME = DEFAULT_PROFILE.max_token_age + DEFAULT_PROFILE.clock_skew


class SlowDns(InMemoryDns):
    """Lets time pass during the lookup, after freshness has been checked."""

    def __init__(self, records: dict[str, list[str]], clock: FixedClock) -> None:
        super().__init__(records)
        self.clock = clock

    def resolve_txt(self, name: str) -> list[str]:
        self.clock.advance(timedelta(seconds=2))
        return super().resolve_txt(name)


class AsyncSlowDns(AsyncInMemoryDns):
    def __init__(self, records: dict[str, list[str]], clock: FixedClock) -> None:
        super().__init__(records)
        self.clock = clock

    async def resolve_txt(self, name: str) -> list[str]:
        self.clock.advance(timedelta(seconds=2))
        return await super().resolve_txt(name)


def test_token_expiring_during_verification_is_rejected(
    issuer: FakeIssuer, token: str, nonce: str, clock: FixedClock
) -> None:
    verifier = Verifier(
        audience=AUDIENCE,
        resolver=SlowDns(issuer.dns_records(), clock),
        fetcher=InMemoryHttp(issuer.http_documents()),
        clock=clock,
        replay_guard=InMemoryReplayGuard(clock=clock),
    )
    start = clock()
    assert verifier.verify(token, nonce=nonce, email=None).email == EMAIL
    clock.now = start + _LIFETIME - timedelta(seconds=1)
    with pytest.raises(EVPError) as exc:
        verifier.verify(token, nonce=nonce, email=None)
    assert exc.value.code is ErrorCode.TOKEN_EXPIRED


@pytest.mark.anyio
async def test_token_expiring_during_async_verification_is_rejected(
    issuer: FakeIssuer, token: str, nonce: str, clock: FixedClock
) -> None:
    verifier = AsyncVerifier(
        audience=AUDIENCE,
        resolver=AsyncSlowDns(issuer.dns_records(), clock),
        fetcher=AsyncInMemoryHttp(issuer.http_documents()),
        clock=clock,
        replay_guard=AsyncGuard(clock),
    )
    start = clock()
    assert (await verifier.verify(token, nonce=nonce, email=None)).email == EMAIL
    clock.now = start + _LIFETIME - timedelta(seconds=1)
    with pytest.raises(EVPError) as exc:
        await verifier.verify(token, nonce=nonce, email=None)
    assert exc.value.code is ErrorCode.TOKEN_EXPIRED


class _Wordy:
    def mark_used(self, key: str, expires_at: datetime) -> bool:
        return "already-used"  # ty: ignore[invalid-return-type]


class _AsyncWordy:
    async def mark_used(self, key: str, expires_at: datetime) -> bool:
        return "already-used"  # ty: ignore[invalid-return-type]


def test_a_guard_answering_anything_but_a_bool_is_refused(
    issuer: FakeIssuer, token: str, nonce: str
) -> None:
    verifier = make_verifier(issuer, audience=AUDIENCE, replay_guard=_Wordy())
    with pytest.raises(TypeError, match="MarkUsed must return a bool"):
        verifier.verify(token, nonce=nonce, email=None)


@pytest.mark.anyio
async def test_an_async_guard_answering_anything_but_a_bool_is_refused(
    issuer: FakeIssuer, token: str, nonce: str
) -> None:
    verifier = make_async_verifier(issuer, audience=AUDIENCE, replay_guard=_AsyncWordy())
    with pytest.raises(TypeError, match="MarkUsed must return a bool"):
        await verifier.verify(token, nonce=nonce, email=None)
