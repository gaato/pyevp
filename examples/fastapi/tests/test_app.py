"""The FastAPI example, tested against fakes: also shows how applications can test."""

from __future__ import annotations

import re
from collections.abc import Iterator

import app as example
import pytest
from app import app, get_verifier
from fastapi.testclient import TestClient

from pyevp import InMemoryReplayGuard
from pyevp.testing import FakeBrowser, FakeIssuer, make_async_verifier

ORIGIN = "http://testserver"


@pytest.fixture
def issuer() -> FakeIssuer:
    return FakeIssuer()


@pytest.fixture
def client(issuer: FakeIssuer, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setattr(example, "ORIGIN", ORIGIN)
    verifier = make_async_verifier(
        issuer, audience=ORIGIN, replay_guard=InMemoryReplayGuard(clock=issuer.clock)
    )
    app.dependency_overrides[get_verifier] = lambda: verifier
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


def _nonce(client: TestClient) -> str:
    match = re.search(r'nonce="([^"]+)"', client.get("/").text)
    assert match
    return match.group(1)


def test_signup_with_token(client: TestClient, issuer: FakeIssuer) -> None:
    browser = FakeBrowser(clock=issuer.clock)
    nonce = _nonce(client)
    evt = browser.present(
        issuer.issue("alice@example.com", browser.public_jwk), audience=ORIGIN, nonce=nonce
    )
    response = client.post("/signup", data={"email": "alice@example.com", "evt": evt})
    assert response.json() == {
        "email": "alice@example.com",
        "verified": True,
        "issuer": "https://issuer.example",
    }
    # The nonce is single-use.
    response = client.post("/signup", data={"email": "alice@example.com", "evt": evt})
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "nonce_mismatch"


def test_signup_with_bad_token(client: TestClient, issuer: FakeIssuer) -> None:
    browser = FakeBrowser(clock=issuer.clock)
    _nonce(client)
    evt = browser.present(
        issuer.issue("alice@example.com", browser.public_jwk), audience=ORIGIN, nonce="stolen"
    )
    response = client.post("/signup", data={"email": "alice@example.com", "evt": evt})
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "nonce_mismatch"


def test_signup_without_token_keeps_the_nonce(client: TestClient, issuer: FakeIssuer) -> None:
    nonce = _nonce(client)
    response = client.post("/signup", data={"email": "alice@example.com"})
    assert response.json() == {"email": "alice@example.com", "verified": False}
    browser = FakeBrowser(clock=issuer.clock)
    evt = browser.present(
        issuer.issue("alice@example.com", browser.public_jwk), audience=ORIGIN, nonce=nonce
    )
    response = client.post("/signup", data={"email": "alice@example.com", "evt": evt})
    assert response.json()["verified"] is True


def test_forms_in_two_tabs(client: TestClient, issuer: FakeIssuer) -> None:
    browser = FakeBrowser(clock=issuer.clock)
    nonces = [_nonce(client), _nonce(client)]
    for nonce in reversed(nonces):
        evt = browser.present(
            issuer.issue("alice@example.com", browser.public_jwk), audience=ORIGIN, nonce=nonce
        )
        response = client.post("/signup", data={"email": "alice@example.com", "evt": evt})
        assert response.json()["verified"] is True


def test_replay_with_old_session_cookie(client: TestClient, issuer: FakeIssuer) -> None:
    browser = FakeBrowser(clock=issuer.clock)
    nonce = _nonce(client)
    captured = dict(client.cookies)
    evt = browser.present(
        issuer.issue("alice@example.com", browser.public_jwk), audience=ORIGIN, nonce=nonce
    )
    form = {"email": "alice@example.com", "evt": evt}
    assert client.post("/signup", data=form).json()["verified"] is True

    # The session cookie is client-side: restoring it brings the nonce back.
    client.cookies.clear()
    client.cookies.update(captured)
    response = client.post("/signup", data=form)
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "token_replayed"
