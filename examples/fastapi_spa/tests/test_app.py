"""The single-page app API, tested against fakes."""

from __future__ import annotations

from collections.abc import Iterator

import app as example
import pytest
from app import OUTBOX, USERS, User, app, check_reset_token, get_verifier
from fastapi.testclient import TestClient

from pyevp import InMemoryReplayGuard
from pyevp.testing import FakeBrowser, FakeIssuer, make_async_verifier

ALICE = "alice@example.com"


@pytest.fixture
def issuer() -> Iterator[FakeIssuer]:
    # Also authoritative for faß.example, a different domain from fass.example.
    issuer = FakeIssuer(email_domains=("example.com", "xn--fa-hia.example"))
    verifier = make_async_verifier(
        issuer, audience=example.ORIGIN, replay_guard=InMemoryReplayGuard(clock=issuer.clock)
    )
    app.dependency_overrides[get_verifier] = lambda: verifier
    USERS.clear()
    USERS[ALICE] = User(ALICE)
    OUTBOX.clear()
    yield issuer
    app.dependency_overrides.clear()


@pytest.fixture
def client(issuer: FakeIssuer) -> Iterator[TestClient]:
    with TestClient(app) as client:
        yield client


def _token(client: TestClient, issuer: FakeIssuer, email: str = ALICE) -> str:
    nonce = client.get("/api/evp/nonce").json()["nonce"]
    browser = FakeBrowser(clock=issuer.clock)
    return browser.present(
        issuer.issue(email, browser.public_jwk), audience=example.ORIGIN, nonce=nonce
    )


def _recover(client: TestClient, email: str, evt: str = "") -> dict[str, str]:
    response = client.post("/api/password-recovery", json={"email": email, "evt": evt})
    assert response.status_code == 200
    return response.json()


def test_nonce_cookie(client: TestClient) -> None:
    cookie = client.get("/api/evp/nonce").headers["set-cookie"]
    assert cookie.startswith("evp_nonce=")
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert "Path=/;" in cookie or cookie.endswith("Path=/")
    assert "Secure" not in cookie


def test_nonce_cookie_over_https(monkeypatch: pytest.MonkeyPatch, issuer: FakeIssuer) -> None:
    monkeypatch.setattr(example, "ORIGIN", "https://app.example")
    with TestClient(app, base_url="https://api.example") as client:
        cookie = client.get("/api/evp/nonce").headers["set-cookie"]
    assert cookie.startswith("__Host-evp_nonce=")
    assert "Secure" in cookie
    assert "Domain" not in cookie


def test_cors_allows_credentials_from_the_frontend(client: TestClient) -> None:
    response = client.options(
        "/api/password-recovery",
        headers={"Origin": example.ORIGIN, "Access-Control-Request-Method": "POST"},
    )
    assert response.headers["access-control-allow-origin"] == example.ORIGIN
    assert response.headers["access-control-allow-credentials"] == "true"


def test_token_hands_over_the_reset_token(client: TestClient, issuer: FakeIssuer) -> None:
    reply = _recover(client, ALICE, _token(client, issuer))
    assert check_reset_token(reply["reset_token"]) == ALICE
    assert OUTBOX == []
    assert "evp_nonce" not in client.cookies

    response = client.post(
        "/api/reset-password", json={"token": reply["reset_token"], "new_password": "new one"}
    )
    assert response.status_code == 200
    assert USERS[ALICE].password_hash


def test_without_a_token_the_email_is_sent(client: TestClient) -> None:
    client.get("/api/evp/nonce")
    assert _recover(client, ALICE) == {"message": example.GENERIC_REPLY}
    assert [address for address, _ in OUTBOX] == [ALICE]
    # Nothing used the nonce, so it stays for the next submission.
    assert "evp_nonce" in client.cookies


def test_a_token_from_an_older_form_keeps_the_cookie(
    client: TestClient, issuer: FakeIssuer
) -> None:
    old = _token(client, issuer)
    current = _token(client, issuer)
    assert _recover(client, ALICE, old) == {"message": example.GENERIC_REPLY}
    assert "evp_nonce" in client.cookies
    assert "reset_token" in _recover(client, ALICE, current)


def test_cookie_nonce_is_taken_once_per_request() -> None:
    request = example.Request(
        {"type": "http", "headers": [(b"cookie", b"evp_nonce=n")], "method": "POST"}
    )
    nonces = example.CookieNonces(request, example.Response())
    assert nonces.take("n")
    assert not nonces.take("n")


def test_replayed_token_is_refused(client: TestClient, issuer: FakeIssuer) -> None:
    token = _token(client, issuer)
    cookie = next(c for c in client.cookies.jar if c.name == "evp_nonce")
    assert "reset_token" in _recover(client, ALICE, token)
    # Resending the captured token with the old cookie does not work.
    client.cookies.jar.set_cookie(cookie)
    assert _recover(client, ALICE, token) == {"message": example.GENERIC_REPLY}
    assert len(OUTBOX) == 1


def test_token_for_another_address_sends_the_email(client: TestClient, issuer: FakeIssuer) -> None:
    reply = _recover(client, ALICE, _token(client, issuer, "mallory@example.com"))
    assert reply == {"message": example.GENERIC_REPLY}
    assert len(OUTBOX) == 1


def test_token_for_a_case_folded_domain_sends_the_email(
    client: TestClient, issuer: FakeIssuer
) -> None:
    # "faß".casefold() is "fass", but the two are different DNS names and owners.
    victim = "a@fass.example"
    USERS[victim] = User(victim)
    reply = _recover(client, victim, _token(client, issuer, "a@faß.example"))
    assert reply == {"message": example.GENERIC_REPLY}
    assert [address for address, _ in OUTBOX] == [victim]


def test_inactive_user_gets_nothing(client: TestClient, issuer: FakeIssuer) -> None:
    USERS[ALICE].active = False
    assert _recover(client, ALICE, _token(client, issuer)) == {"message": example.GENERIC_REPLY}
    assert OUTBOX == []


def test_reply_does_not_reveal_registration(client: TestClient, issuer: FakeIssuer) -> None:
    def attempt(email: str) -> tuple[int, str, str | None]:
        client.get("/api/evp/nonce")
        response = client.post(
            "/api/password-recovery", json={"email": email, "evt": "not a token"}
        )
        return response.status_code, response.text, response.headers.get("set-cookie")

    assert attempt(ALICE) == attempt("nobody@example.com")


@pytest.mark.parametrize("token", ["x.y", "x.é", "é"])
def test_bad_reset_token(client: TestClient, token: str) -> None:
    response = client.post("/api/reset-password", json={"token": token, "new_password": "p"})
    assert response.status_code == 400
