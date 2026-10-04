from __future__ import annotations

import importlib.util
from collections.abc import Coroutine, Iterator
from typing import Any

import pytest

from pyevp import Verifier, generate_nonce
from pyevp.testing import FakeBrowser, FakeIssuer, FixedClock, make_verifier

AUDIENCE = "https://rp.example"
EMAIL = "alice@example.com"

# Tests for optional adapters are skipped when the extras are not installed.
# Each requirement is a group of alternatives, any of which will do.
_REQUIRES: dict[str, tuple[tuple[str, ...], ...]] = {
    "test_adapters.py": (("httpx", "httpx2"),),
    "test_dnspython.py": (("dns",),),
    "test_doh.py": (("httpx", "httpx2"),),
    "test_cli.py": (("typer",),),
    "test_contrib_django.py": (("django",),),
    "test_contrib_django_issuer.py": (("django",),),
    "test_network.py": (("httpx", "httpx2"), ("dns",)),
}
collect_ignore = [
    name
    for name, groups in _REQUIRES.items()
    if not all(any(importlib.util.find_spec(m) for m in group) for group in groups)
]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock()


@pytest.fixture
def issuer(clock: FixedClock) -> FakeIssuer:
    return FakeIssuer(clock=clock)


@pytest.fixture
def browser(clock: FixedClock) -> FakeBrowser:
    return FakeBrowser(clock=clock)


@pytest.fixture
def nonce() -> str:
    return generate_nonce()


@pytest.fixture
def verifier(issuer: FakeIssuer) -> Verifier:
    return make_verifier(issuer, audience=AUDIENCE)


@pytest.fixture
def token(issuer: FakeIssuer, browser: FakeBrowser, nonce: str) -> str:
    return browser.present(issuer.issue(EMAIL, browser.public_jwk), audience=AUDIENCE, nonce=nonce)


@pytest.fixture
def leash() -> Iterator[list[Coroutine[Any, Any, Any]]]:
    """Coroutines a test hands to synchronous code; closed afterwards if nobody awaited them."""
    made: list[Coroutine[Any, Any, Any]] = []
    yield made
    for coroutine in made:
        coroutine.close()
