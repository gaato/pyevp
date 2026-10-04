from __future__ import annotations

import json
from collections.abc import Iterator
from types import ModuleType
from typing import Any

import pytest
from django.core import checks
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.db import connections
from django.http import HttpRequest
from django.test import Client, override_settings

from pyevp import Verifier
from pyevp.contrib.django import EVPReplayGuard
from pyevp.contrib.django.issuer import (
    AccountsView,
    IssuerSite,
    check_session_cookie,
)
from pyevp.issuer import Issuer, SigningKey
from pyevp.testing import FakeBrowser, FixedClock, InMemoryDns, InMemoryHttp

from . import _django

_django.configure()

# Models can only be imported once the app registry is ready.
from django.contrib.auth.models import User  # noqa: E402

from pyevp.contrib.django.models import UsedToken  # noqa: E402

ORIGIN = "https://issuer.example"
ISSUANCE = ORIGIN + "/email-verification/issuance"
JWKS = ORIGIN + "/email-verification/jwks"
RP = "https://rp.example"
EMAIL = "alice@example.com"


@pytest.fixture(scope="module", autouse=True)
def _database() -> Any:
    call_command("migrate", verbosity=0)
    yield
    connections.close_all()


@pytest.fixture(autouse=True)
def _clean() -> None:
    User.objects.all().delete()
    UsedToken.objects.all().delete()


class EmailSite(IssuerSite):
    """The tests create each user with an address they own."""

    def user_emails(self, request: HttpRequest) -> list[str]:
        user = getattr(request, "user", None)
        return [user.email] if user is not None and user.is_authenticated and user.email else []


def _make_issuer(clock: FixedClock, **kwargs: Any) -> Issuer:
    return Issuer(
        issuer=ORIGIN,
        issuance_endpoint=ISSUANCE,
        jwks_uri=JWKS,
        signer=SigningKey.generate(kid="2026-10"),
        email_domains=["example.com"],
        clock=clock,
        **kwargs,
    )


@pytest.fixture
def issuer(clock: FixedClock) -> Issuer:
    return _make_issuer(clock)


def _mount(*patterns: Any) -> Any:
    urlconf = ModuleType("evp_urls")
    urlconf.urlpatterns = list(patterns)  # ty: ignore[unresolved-attribute]
    return override_settings(ROOT_URLCONF=urlconf)


@pytest.fixture
def site(issuer: Issuer) -> Iterator[IssuerSite]:
    site = EmailSite(issuer, login_url="/accounts/login/")
    with _mount(*site.urls):
        yield site


@pytest.fixture
def client() -> Client:
    return Client(secure=True, HTTP_HOST="issuer.example")


def _login(client: Client, email: str = EMAIL) -> None:
    client.force_login(User.objects.create_user(email.split("@", maxsplit=1)[0], email=email))


def _issue(client: Client, browser: FakeBrowser, email: str = EMAIL) -> Any:
    request = browser.issuance_request(email, endpoint=ISSUANCE)
    headers = dict(request["headers"])
    content_type = headers.pop("Content-Type")
    return client.post(
        "/email-verification/issuance",
        request["body"],
        content_type=content_type,
        headers=headers,
    )


@pytest.mark.usefixtures("site")
def test_documents(client: Client, issuer: Issuer) -> None:
    assert client.get("/.well-known/email-verification").json() == issuer.metadata_document()
    assert client.get("/email-verification/jwks").json() == issuer.jwks_document()
    assert client.get("/.well-known/web-identity").json() == {
        "accounts_endpoint": ORIGIN + "/fedcm/accounts",
        "login_url": ORIGIN + "/accounts/login/",
    }
    for url in ("/.well-known/email-verification", "/email-verification/jwks"):
        assert client.get(url)["Cache-Control"] == "public, max-age=300"


@pytest.mark.usefixtures("site")
def test_signed_in_user_gets_a_verifiable_token(
    client: Client, issuer: Issuer, clock: FixedClock
) -> None:
    _login(client)
    browser = FakeBrowser(clock=clock)
    response = _issue(client, browser)
    assert response.status_code == 200, response.content
    assert response["Cache-Control"] == "no-store"
    evt = response.json()["issuance_token"]

    verifier = Verifier(
        audience=RP,
        resolver=InMemoryDns({k: [v] for k, v in issuer.dns_txt_records().items()}),
        fetcher=InMemoryHttp(
            {
                ORIGIN + "/.well-known/email-verification": issuer.metadata_document(),
                JWKS: issuer.jwks_document(),
            }
        ),
        clock=clock,
    )
    token = browser.present(evt, audience=RP, nonce="n")
    assert verifier.verify(token, nonce="n", email=EMAIL).email == EMAIL


@pytest.mark.usefixtures("site")
def test_addresses_compare_case_insensitively(client: Client, clock: FixedClock) -> None:
    _login(client, "Alice@Example.com")
    response = _issue(client, FakeBrowser(clock=clock), "alice@example.com")
    assert response.status_code == 200


@pytest.mark.usefixtures("site")
def test_failures_look_the_same(client: Client, clock: FixedClock) -> None:
    browser = FakeBrowser(clock=clock)
    anonymous = _issue(client, browser)
    _login(client)
    other_user = _issue(client, browser, "bob@example.com")
    other_domain = _issue(client, browser, "alice@other.example")
    assert anonymous.status_code == other_user.status_code == other_domain.status_code == 401
    assert anonymous.content == other_user.content == other_domain.content


@pytest.mark.usefixtures("site")
def test_issuance_is_csrf_exempt(clock: FixedClock) -> None:
    client = Client(enforce_csrf_checks=True, secure=True, HTTP_HOST="issuer.example")
    _login(client)
    assert _issue(client, FakeBrowser(clock=clock)).status_code == 200


@pytest.mark.usefixtures("site")
def test_invalid_requests(client: Client) -> None:
    unsigned = client.post(
        "/email-verification/issuance",
        b'{"email": "alice@example.com"}',
        content_type="application/json",
        headers={"Sec-Fetch-Dest": "email-verification"},
    )
    assert unsigned.status_code == 400
    assert unsigned.json()["error"] == "invalid_signature"
    assert unsigned["Signature-Error"] == "error=invalid_signature"

    for method in (client.get, client.put, client.delete):
        response = method("/email-verification/issuance")
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"
        assert response["Cache-Control"] == "no-store"

    large = client.post(
        "/email-verification/issuance", b"x" * (16 * 1024 + 1), content_type="application/json"
    )
    assert large.status_code == 400
    assert large.json()["error"] == "invalid_request"


def test_replay_guard_under_atomic_requests(
    client: Client, clock: FixedClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    issuer = _make_issuer(clock, replay_guard=EVPReplayGuard(clock=clock))
    for alias in ("default", "replay"):
        monkeypatch.setitem(connections.settings[alias], "ATOMIC_REQUESTS", True)
    _login(client)
    request = FakeBrowser(clock=clock).issuance_request(EMAIL, endpoint=ISSUANCE)
    headers = dict(request["headers"])
    content_type = headers.pop("Content-Type")
    with _mount(*EmailSite(issuer).urls):
        responses = [
            client.post(
                "/email-verification/issuance",
                request["body"],
                content_type=content_type,
                headers=headers,
            )
            for _ in range(2)
        ]
    assert [r.status_code for r in responses] == [200, 400]
    assert UsedToken.objects.count() == 1


@pytest.mark.usefixtures("site")
def test_accounts_endpoint(client: Client) -> None:
    fedcm = {"Sec-Fetch-Dest": "webidentity"}
    assert client.get("/fedcm/accounts", headers=fedcm).status_code == 401
    _login(client)
    assert client.get("/fedcm/accounts").status_code == 400
    response = client.get("/fedcm/accounts", headers=fedcm)
    assert response.json() == {"accounts": [{"id": EMAIL, "email": EMAIL, "name": EMAIL}]}
    assert response["Cache-Control"] == "no-store"


def test_hooks_choose_issuer_and_addresses(client: Client, clock: FixedClock) -> None:
    issuers = {"issuer.example": _make_issuer(clock)}

    class BrandSite(EmailSite):
        def get_issuer(self, request: HttpRequest) -> Issuer:
            return issuers[request.get_host()]

        def user_emails(self, request: HttpRequest) -> list[str]:
            return [*super().user_emails(request), "alias@example.com"]

    site = BrandSite()
    with _mount(*site.urls):
        doc = client.get("/.well-known/email-verification").json()
        assert doc == issuers["issuer.example"].metadata_document()
        _login(client)
        assert _issue(client, FakeBrowser(clock=clock), "alias@example.com").status_code == 200


def test_lookalike_addresses_are_ignored(client: Client, clock: FixedClock) -> None:
    # U+212A KELVIN SIGN lowercases to an ASCII "k".
    class LookalikeSite(EmailSite):
        def user_emails(self, request: HttpRequest) -> list[str]:
            return ["\u212aate@example.com"]

    site = LookalikeSite(_make_issuer(clock))
    with _mount(*site.urls):
        _login(client)
        fedcm = client.get("/fedcm/accounts", headers={"Sec-Fetch-Dest": "webidentity"})
        assert fedcm.status_code == 401
        assert _issue(client, FakeBrowser(clock=clock), "kate@example.com").status_code == 401


def test_views_mount_on_their_own(client: Client, issuer: Issuer) -> None:
    from django.urls import path  # noqa: PLC0415

    site = EmailSite(issuer)
    with _mount(path("custom/accounts", AccountsView.as_view(site=site))):
        _login(client)
        response = client.get("/custom/accounts", headers={"Sec-Fetch-Dest": "webidentity"})
        assert response.json()["accounts"][0]["email"] == EMAIL


def test_paths_must_match_the_issuer(clock: FixedClock) -> None:
    issuer = Issuer(
        issuer=ORIGIN,
        issuance_endpoint=ORIGIN + "/evp/issue",
        jwks_uri=JWKS,
        signer=SigningKey.generate(kid="k"),
        email_domains=["example.com"],
        clock=clock,
    )
    with pytest.raises(ImproperlyConfigured, match="/evp/issue"):
        EmailSite(issuer)

    class Site(EmailSite):
        issuance_path = "evp/issue"

    assert Site(issuer).issuer is issuer


def test_async_replay_guard_is_refused(clock: FixedClock) -> None:
    class AsyncGuard:
        async def mark_used(self, key: str, expires_at: object) -> bool:
            return True

    with pytest.raises(ImproperlyConfigured, match="synchronous replay guard"):
        EmailSite(_make_issuer(clock, replay_guard=AsyncGuard()))


def test_user_emails_must_be_overridden(issuer: Issuer) -> None:
    with pytest.raises(ImproperlyConfigured, match="user_emails"):
        IssuerSite(issuer)


def test_site_without_issuer(client: Client) -> None:
    with _mount(*EmailSite().urls), pytest.raises(ImproperlyConfigured):
        client.get("/.well-known/email-verification")


@pytest.mark.usefixtures("site")
def test_login_status_middleware(client: Client) -> None:
    page = {"Sec-Fetch-Dest": "document"}
    # Any page will do; the metadata view stands in for one.
    assert client.get("/.well-known/web-identity", headers=page)["Set-Login"] == "logged-out"
    _login(client)
    assert client.get("/.well-known/web-identity", headers=page)["Set-Login"] == "logged-in"
    assert "Set-Login" not in client.get("/.well-known/web-identity")


def test_session_cookie_checks(issuer: Issuer) -> None:
    site = EmailSite(issuer)
    assert check_session_cookie() == []
    with override_settings(SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=False):
        ids = [m.id for m in check_session_cookie()]
        assert ids == ["pyevp.W001", "pyevp.W002"]
        security = [checks.Tags.security]
        deploy = checks.run_checks(tags=security, include_deployment_checks=True)
        assert {m.id for m in deploy} >= set(ids)
        assert not {m.id for m in checks.run_checks(tags=security)} & set(ids)
    with override_settings(DATA_UPLOAD_MAX_MEMORY_SIZE=1024):
        assert [m.id for m in check_session_cookie()] == ["pyevp.W003"]
    with override_settings(DATA_UPLOAD_MAX_MEMORY_SIZE=None):
        assert check_session_cookie() == []
    del site


def test_issuance_response_is_json(client: Client, clock: FixedClock, site: IssuerSite) -> None:
    _login(client)
    response = _issue(client, FakeBrowser(clock=clock))
    assert response["Content-Type"] == "application/json"
    assert set(json.loads(response.content)) == {"issuance_token"}
    assert site.user_emails(response.wsgi_request) == [EMAIL]
