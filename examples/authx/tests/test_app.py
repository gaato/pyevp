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
EMAIL = "alice@example.com"


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


def _token(client: TestClient, issuer: FakeIssuer, *, nonce: str | None = None) -> str:
    match = re.search(r'nonce="([^"]+)"', client.get("/login").text)
    assert match
    browser = FakeBrowser(clock=issuer.clock)
    return browser.present(
        issuer.issue(EMAIL, browser.public_jwk), audience=ORIGIN, nonce=nonce or match.group(1)
    )


def test_login(client: TestClient, issuer: FakeIssuer) -> None:
    response = client.post("/login", data={"email": EMAIL, "evt": _token(client, issuer)})
    assert response.status_code == 200, response.text
    assert response.json() == {"email": EMAIL}
    assert client.get("/me").json() == {"email": EMAIL}


def test_not_logged_in(client: TestClient) -> None:
    assert client.get("/me").status_code == 401


def test_without_a_token_the_nonce_stays(client: TestClient, issuer: FakeIssuer) -> None:
    evt = _token(client, issuer)
    response = client.post("/login", data={"email": EMAIL})
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "evp_unavailable"
    assert client.post("/login", data={"email": EMAIL, "evt": evt}).status_code == 200


def test_bad_token(client: TestClient, issuer: FakeIssuer) -> None:
    evt = _token(client, issuer, nonce="nonce-of-another-session")
    response = client.post("/login", data={"email": EMAIL, "evt": evt})
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "nonce_mismatch"


def test_replay_with_old_session_cookie(client: TestClient, issuer: FakeIssuer) -> None:
    evt = _token(client, issuer)
    captured = dict(client.cookies)
    assert client.post("/login", data={"email": EMAIL, "evt": evt}).status_code == 200

    # An attacker restores the pre-login session cookie, which still holds the nonce.
    client.cookies.clear()
    client.cookies.update(captured)
    response = client.post("/login", data={"email": EMAIL, "evt": evt})
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "token_replayed"
