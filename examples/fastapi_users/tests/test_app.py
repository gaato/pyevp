from __future__ import annotations

import re
import uuid
from collections.abc import Iterator
from typing import Literal

import app as example
import pytest
from app import app, get_verifier
from fastapi.testclient import TestClient

from pyevp import InMemoryReplayGuard
from pyevp.testing import FakeBrowser, FakeIssuer, make_async_verifier

ORIGIN = "http://testserver"
PASSWORD = "correct horse battery staple"


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


def _email() -> str:
    return f"user-{uuid.uuid4().hex[:8]}@example.com"


def _register(
    client: TestClient, issuer: FakeIssuer, email: str, token: Literal["valid", "stolen", "none"]
) -> dict:
    match = re.search(r'nonce="([^"]+)"', client.get("/register").text)
    assert match
    evt = ""
    if token != "none":
        browser = FakeBrowser(clock=issuer.clock)
        nonce = match.group(1) if token == "valid" else "nonce-of-another-session"
        evt = browser.present(issuer.issue(email, browser.public_jwk), audience=ORIGIN, nonce=nonce)
    response = client.post("/register", data={"email": email, "password": PASSWORD, "evt": evt})
    assert response.status_code == 200, response.text
    return response.json()


def _login(client: TestClient, email: str) -> None:
    response = client.post("/auth/login", data={"username": email, "password": PASSWORD})
    assert response.status_code == 204, response.text


def test_valid_token_registers_verified_user(client: TestClient, issuer: FakeIssuer) -> None:
    email = _email()
    user = _register(client, issuer, email, "valid")
    assert user["is_verified"] is True
    assert user["is_superuser"] is False
    _login(client, email)
    assert client.get("/me").json()["email"] == email


def test_invalid_token_registers_unverified_user(client: TestClient, issuer: FakeIssuer) -> None:
    email = _email()
    assert _register(client, issuer, email, "stolen")["is_verified"] is False
    _login(client, email)
    assert client.get("/me").status_code == 403


def test_no_token_registers_unverified_user(client: TestClient, issuer: FakeIssuer) -> None:
    email = _email()
    assert _register(client, issuer, email, "none")["is_verified"] is False


def test_without_a_token_the_nonce_stays(client: TestClient, issuer: FakeIssuer) -> None:
    match = re.search(r'nonce="([^"]+)"', client.get("/register").text)
    assert match
    first, second = _email(), _email()
    data = {"email": first, "password": PASSWORD, "evt": ""}
    assert client.post("/register", data=data).json()["is_verified"] is False
    browser = FakeBrowser(clock=issuer.clock)
    evt = browser.present(
        issuer.issue(second, browser.public_jwk), audience=ORIGIN, nonce=match.group(1)
    )
    data = {"email": second, "password": PASSWORD, "evt": evt}
    assert client.post("/register", data=data).json()["is_verified"] is True


def test_invalid_email_is_rejected(client: TestClient) -> None:
    response = client.post("/register", data={"email": "not-an-email", "password": PASSWORD})
    assert response.status_code == 422
