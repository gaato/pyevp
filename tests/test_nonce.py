from __future__ import annotations

from datetime import timedelta
from typing import Any

import anyio
import pytest

from pyevp import (
    AsyncVerifier,
    ErrorCode,
    PolicyError,
    SessionNonces,
    TokenError,
    VerificationEvent,
    Verifier,
    token_input,
)
from pyevp.testing import FakeBrowser, FakeIssuer, FixedClock, make_async_verifier, make_verifier

from .conftest import AUDIENCE, EMAIL

# --- SessionNonces ---


def test_issue_is_shared_by_the_forms_of_a_page(clock: FixedClock) -> None:
    session: dict[str, Any] = {}
    nonces = SessionNonces(session, clock=clock)
    nonce = nonces.issue()
    assert nonces.issue() == nonce
    assert session == {"evp_nonce": [[nonce, clock().timestamp()]]}


def test_every_tab_can_take_its_nonce(clock: FixedClock) -> None:
    session: dict[str, Any] = {}
    first = SessionNonces(session, clock=clock).issue()
    second = SessionNonces(session, clock=clock).issue()
    assert first != second
    nonces = SessionNonces(session, clock=clock)
    assert nonces.take(first)
    assert not nonces.take(first)
    assert nonces.take(second)
    assert session["evp_nonce"] == []


def test_take_refuses_what_was_not_issued(clock: FixedClock) -> None:
    session: dict[str, Any] = {}
    SessionNonces(session, clock=clock).issue()
    before = list(session["evp_nonce"])
    assert not SessionNonces(session, clock=clock).take("guessed")
    assert session["evp_nonce"] == before


def test_after_a_take_the_page_gets_a_new_nonce(clock: FixedClock) -> None:
    nonces = SessionNonces({}, clock=clock)
    nonce = nonces.issue()
    assert nonces.take(nonce)
    assert nonces.issue() != nonce


def test_nonces_expire(clock: FixedClock) -> None:
    session: dict[str, Any] = {}
    nonce = SessionNonces(session, clock=clock).issue()
    clock.advance(timedelta(minutes=10, seconds=1))
    assert not SessionNonces(session, clock=clock).take(nonce)
    assert session["evp_nonce"] == []


def test_the_oldest_nonces_give_way(clock: FixedClock) -> None:
    session: dict[str, Any] = {}
    issued = [SessionNonces(session, limit=3, clock=clock).issue() for _ in range(4)]
    nonces = SessionNonces(session, limit=3, clock=clock)
    assert not nonces.take(issued[0])
    assert all(nonces.take(n) for n in issued[1:])


@pytest.mark.parametrize(
    "stored",
    [None, "nonce", {"a": 1}, [["n"]], [[1, 2]], [["", 2]], [["n", "t"]], [["n", True]]],
)
def test_malformed_session_values_are_ignored(clock: FixedClock, stored: object) -> None:
    session: dict[str, Any] = {"evp_nonce": stored}
    nonces = SessionNonces(session, clock=clock)
    assert not nonces.take("n")
    nonce = nonces.issue()
    assert session["evp_nonce"] == [[nonce, clock().timestamp()]]


def test_any_session_with_get_and_item_assignment(clock: FixedClock) -> None:
    class Session:  # like Django's SessionBase, which is not a Mapping
        def __init__(self) -> None:
            self.data: dict[str, Any] = {}

        def get(self, key: str, default: Any = None) -> Any:
            return self.data.get(key, default)

        def __setitem__(self, key: str, value: Any) -> None:
            self.data[key] = value

    session = Session()
    nonce = SessionNonces(session, key="other", clock=clock).issue()
    assert SessionNonces(session, key="other", clock=clock).take(nonce)


def test_limit_must_be_positive() -> None:
    with pytest.raises(ValueError, match="limit"):
        SessionNonces({}, limit=0)


def test_token_input() -> None:
    html = token_input('a"<b>', field="x'&y")
    assert html == (
        '<input type="hidden" name="x&#x27;&amp;y" autocomplete="email-verification-token"'
        ' nonce="a&quot;&lt;b&gt;">'
    )
    markup: Any = html  # what Jinja and Django look for
    assert markup.__html__() == html
    assert 'name="evt"' in token_input("n")


# --- verify_submission ---


class Untouchable:
    def issue(self) -> str:
        raise AssertionError("issue() called")

    def take(self, nonce: str) -> bool:
        raise AssertionError("take() called")


def _token(issuer: FakeIssuer, browser: FakeBrowser, nonce: str, email: str = EMAIL) -> str:
    return browser.present(issuer.issue(email, browser.public_jwk), audience=AUDIENCE, nonce=nonce)


@pytest.mark.parametrize("token", [None, ""])
def test_no_token_leaves_the_nonces_alone(verifier: Verifier, token: str | None) -> None:
    assert verifier.verify_submission(token, nonces=Untouchable(), email=EMAIL) is None


def test_a_submission_takes_its_nonce(
    verifier: Verifier, issuer: FakeIssuer, browser: FakeBrowser, clock: FixedClock
) -> None:
    session: dict[str, Any] = {}
    nonce = SessionNonces(session, clock=clock).issue()
    other_tab = SessionNonces(session, clock=clock).issue()
    token = _token(issuer, browser, nonce)
    nonces = SessionNonces(session, clock=clock)
    result = verifier.verify_submission(token, nonces=nonces, email=EMAIL)
    assert result is not None
    assert result.email == EMAIL
    assert [n for n, _ in session["evp_nonce"]] == [other_tab]
    with pytest.raises(TokenError) as info:
        verifier.verify_submission(token, nonces=nonces, email=EMAIL)
    assert info.value.code == ErrorCode.NONCE_MISMATCH


def test_a_failed_submission_uses_up_its_nonce(
    verifier: Verifier, issuer: FakeIssuer, browser: FakeBrowser, clock: FixedClock
) -> None:
    session: dict[str, Any] = {}
    nonce = SessionNonces(session, clock=clock).issue()
    token = _token(issuer, browser, nonce)
    with pytest.raises(PolicyError):
        verifier.verify_submission(
            token, nonces=SessionNonces(session, clock=clock), email="bob@example.com"
        )
    assert session["evp_nonce"] == []


def test_an_unknown_nonce_is_one_nonce_mismatch(
    issuer: FakeIssuer, browser: FakeBrowser, clock: FixedClock
) -> None:
    events: list[VerificationEvent] = []
    verifier = make_verifier(issuer, audience=AUDIENCE, observer=events.append)
    # Even an expired token reports the nonce, which is checked first.
    token = _token(issuer, browser, "never-issued")
    clock.advance(timedelta(hours=1))
    with pytest.raises(TokenError) as info:
        verifier.verify_submission(token, nonces=SessionNonces({}, clock=clock), email=EMAIL)
    assert info.value.code == ErrorCode.NONCE_MISMATCH
    assert [(e.ok, e.code, e.email_domain) for e in events] == [
        (False, ErrorCode.NONCE_MISMATCH, "example.com")
    ]


def test_an_empty_nonce_is_never_taken(
    issuer: FakeIssuer, browser: FakeBrowser, clock: FixedClock
) -> None:
    events: list[VerificationEvent] = []
    verifier = make_verifier(issuer, audience=AUDIENCE, observer=events.append)
    token = _token(issuer, browser, "")
    with pytest.raises(TokenError) as info:
        verifier.verify_submission(token, nonces=Untouchable(), email=EMAIL)
    assert info.value.code == ErrorCode.NONCE_MISMATCH
    # Nor does the low-level call accept it when told to expect an empty nonce.
    with pytest.raises(TokenError) as info:
        verifier.verify(token, nonce="", email=EMAIL)
    assert info.value.code == ErrorCode.NONCE_MISMATCH
    assert [e.code for e in events] == [ErrorCode.NONCE_MISMATCH] * 2


def test_store_failures_propagate_and_are_reported(
    issuer: FakeIssuer, browser: FakeBrowser, clock: FixedClock
) -> None:
    class Broken:
        def issue(self) -> str:
            return "n"

        def take(self, nonce: str) -> bool:
            raise ConnectionError("session store down")

    class AsyncBroken:
        async def issue(self) -> str:
            return "n"

        async def take(self, nonce: str) -> bool:
            raise ConnectionError("session store down")

    events: list[VerificationEvent] = []
    token = _token(issuer, browser, "n")
    verifier = make_verifier(issuer, audience=AUDIENCE, observer=events.append)
    with pytest.raises(ConnectionError):
        verifier.verify_submission(token, nonces=Broken(), email=EMAIL)
    averifier = make_async_verifier(issuer, audience=AUDIENCE, observer=events.append)

    async def main() -> None:
        with pytest.raises(ConnectionError):
            await averifier.verify_submission(token, nonces=AsyncBroken(), email=EMAIL)

    anyio.run(main)
    assert [(e.ok, e.code) for e in events] == [(False, None)] * 2


@pytest.mark.parametrize("token", ["garbage", "  ", "a.b.c~"])
def test_an_unreadable_token_leaves_the_nonces_alone(verifier: Verifier, token: str) -> None:
    with pytest.raises(TokenError) as info:
        verifier.verify_submission(token, nonces=Untouchable(), email=EMAIL)
    assert info.value.code == ErrorCode.MALFORMED_TOKEN


def test_audience_override(issuer: FakeIssuer, browser: FakeBrowser, clock: FixedClock) -> None:
    verifier = make_verifier(issuer, audience=AUDIENCE)
    nonces = SessionNonces({}, clock=clock)
    evt = issuer.issue(EMAIL, browser.public_jwk)
    token = browser.present(evt, audience="https://other.example", nonce=nonces.issue())
    result = verifier.verify_submission(
        token, nonces=nonces, email=EMAIL, audience="https://other.example"
    )
    assert result is not None


def test_async_submission_with_sync_and_async_stores(
    issuer: FakeIssuer, browser: FakeBrowser, clock: FixedClock
) -> None:
    class AsyncNonces:
        def __init__(self, inner: SessionNonces) -> None:
            self.inner = inner

        async def issue(self) -> str:
            return self.inner.issue()

        async def take(self, nonce: str) -> bool:
            return self.inner.take(nonce)

    verifier: AsyncVerifier = make_async_verifier(issuer, audience=AUDIENCE)

    async def main() -> None:
        assert await verifier.verify_submission("", nonces=Untouchable(), email=EMAIL) is None
        sync = SessionNonces({}, clock=clock)
        token = _token(issuer, browser, sync.issue())
        assert await verifier.verify_submission(token, nonces=sync, email=EMAIL) is not None
        store = AsyncNonces(SessionNonces({}, clock=clock))
        token = _token(issuer, browser, await store.issue())
        assert await verifier.verify_submission(token, nonces=store, email=EMAIL) is not None
        with pytest.raises(TokenError) as info:
            await verifier.verify_submission(token, nonces=store, email=EMAIL)
        assert info.value.code == ErrorCode.NONCE_MISMATCH

    anyio.run(main)
