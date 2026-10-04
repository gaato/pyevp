"""The Flask example, tested against fakes: also shows how applications can test."""

from __future__ import annotations

import re

import pytest
from app import create_app
from flask.testing import FlaskClient

from pyevp import InMemoryReplayGuard
from pyevp.testing import FakeBrowser, FakeIssuer, make_verifier

ORIGIN = "http://localhost"


@pytest.fixture
def issuer() -> FakeIssuer:
    return FakeIssuer()


@pytest.fixture
def client(issuer: FakeIssuer) -> FlaskClient:
    verifier = make_verifier(
        issuer, audience=ORIGIN, replay_guard=InMemoryReplayGuard(clock=issuer.clock)
    )
    return create_app(verifier).test_client()


def _nonce(client: FlaskClient) -> str:
    match = re.search(r'nonce="([^"]+)"', client.get("/").text)
    assert match
    return match.group(1)


def test_signup_with_token(client: FlaskClient, issuer: FakeIssuer) -> None:
    browser = FakeBrowser(clock=issuer.clock)
    nonce = _nonce(client)
    evt = browser.present(
        issuer.issue("alice@example.com", browser.public_jwk), audience=ORIGIN, nonce=nonce
    )
    response = client.post("/signup", data={"email": "alice@example.com", "evt": evt})
    assert response.json == {
        "email": "alice@example.com",
        "verified": True,
        "issuer": "https://issuer.example",
    }
    # The nonce is single-use.
    response = client.post("/signup", data={"email": "alice@example.com", "evt": evt})
    assert response.status_code == 400
    assert response.json == {"error": {"code": "nonce_mismatch"}}


def test_signup_with_bad_token(client: FlaskClient, issuer: FakeIssuer) -> None:
    browser = FakeBrowser(clock=issuer.clock)
    _nonce(client)
    evt = browser.present(
        issuer.issue("alice@example.com", browser.public_jwk), audience=ORIGIN, nonce="stolen"
    )
    response = client.post("/signup", data={"email": "alice@example.com", "evt": evt})
    assert response.status_code == 400
    assert response.json == {"error": {"code": "nonce_mismatch"}}


def test_signup_without_token_keeps_the_nonce(client: FlaskClient, issuer: FakeIssuer) -> None:
    nonce = _nonce(client)
    response = client.post("/signup", data={"email": "alice@example.com"})
    assert response.json == {"email": "alice@example.com", "verified": False}
    browser = FakeBrowser(clock=issuer.clock)
    evt = browser.present(
        issuer.issue("alice@example.com", browser.public_jwk), audience=ORIGIN, nonce=nonce
    )
    response = client.post("/signup", data={"email": "alice@example.com", "evt": evt})
    assert response.json is not None
    assert response.json["verified"] is True


def test_forms_in_two_tabs(client: FlaskClient, issuer: FakeIssuer) -> None:
    browser = FakeBrowser(clock=issuer.clock)
    nonces = [_nonce(client), _nonce(client)]
    for nonce in reversed(nonces):
        evt = browser.present(
            issuer.issue("alice@example.com", browser.public_jwk), audience=ORIGIN, nonce=nonce
        )
        response = client.post("/signup", data={"email": "alice@example.com", "evt": evt})
        assert response.json is not None
        assert response.json["verified"] is True


def test_replay_with_old_session_cookie(client: FlaskClient, issuer: FakeIssuer) -> None:
    browser = FakeBrowser(clock=issuer.clock)
    nonce = _nonce(client)
    captured = client.get_cookie("session")
    assert captured
    evt = browser.present(
        issuer.issue("alice@example.com", browser.public_jwk), audience=ORIGIN, nonce=nonce
    )
    form = {"email": "alice@example.com", "evt": evt}
    assert client.post("/signup", data=form).json == {
        "email": "alice@example.com",
        "verified": True,
        "issuer": "https://issuer.example",
    }

    # The session cookie is client-side: restoring it brings the nonce back.
    client.set_cookie("session", captured.value)
    response = client.post("/signup", data=form)
    assert response.status_code == 400
    assert response.json == {"error": {"code": "token_replayed"}}
