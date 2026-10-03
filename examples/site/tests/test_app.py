"""Host routing and the mock provider, driven by a fake browser."""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import os
import re
from collections.abc import AsyncIterator, Iterator
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx2
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from joserfc.jwk import OKPKey
from pygments.styles import get_style_by_name
from pygments.util import ClassNotFound
from starlette.applications import Starlette
from starlette.routing import Host, Route
from verification_trace import (
    ERROR_STEPS,
    RecordingClock,
    RecordingFetcher,
    RecordingResolver,
    TrackingCache,
)

from pyevp import AsyncVerifier, ErrorCode, EVPError, InMemoryReplayGuard, VerifiedEmail, Verifier
from pyevp.adapters import httpx as httpx_adapter
from pyevp.cache import InMemoryCache
from pyevp.issuer import Issuer, SigningKey
from pyevp.profile import DEFAULT_PROFILE
from pyevp.testing import (
    AsyncInMemoryDns,
    AsyncInMemoryHttp,
    FakeBrowser,
    FakeIssuer,
    FixedClock,
    InMemoryDns,
    InMemoryHttp,
)

# Importing the deployment entry point must be explicit about development mode.
# The patch ends before any test; factories are tested independently of the environment.
with patch.dict(os.environ, {"EVP_DEV": "1", "EVP_SIGNING_JWK": "", "SESSION_SECRET": ""}):
    import app as site

SITE = "https://pyevp.dev"
MAIL = "https://mail.pyevp.dev"
RP = SITE
LEGACY = "https://demo.pyevp.dev"
SITE_COOKIE = "pyevp_site_session"
EMAIL = "demo@pyevp.dev"
COOKIE = "pyevp_mail_session"


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock()


@pytest.fixture
def signer() -> SigningKey:
    return SigningKey.generate(kid="test")


@pytest.fixture
def stylesheet(tmp_path: Path) -> Path:
    path = tmp_path / "site.css"
    path.write_text("/* test stylesheet */", encoding="utf-8")
    return path


@pytest.fixture
def application(signer: SigningKey, clock: FixedClock, stylesheet: Path) -> Starlette:
    return site.create_app(
        signer=signer,
        session_secret="test-session-secret",
        clock=clock,
        stylesheet_path=stylesheet,
        build_sha="test-sha",
    )


@pytest.fixture
def issuer(application: Starlette) -> Issuer:
    return application.state.issuer


@pytest.fixture
def client(application: Starlette) -> Iterator[TestClient]:
    with TestClient(application, base_url=MAIL) as client:
        yield client


def _issue(client: TestClient, browser: FakeBrowser, email: str = EMAIL) -> httpx2.Response:
    request = browser.issuance_request(email, endpoint=MAIL + site.ISSUANCE_PATH)
    return client.post(site.ISSUANCE_PATH, headers=request["headers"], content=request["body"])


class PageText(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def _page_text(page: str) -> str:
    parser = PageText()
    parser.feed(page)
    return "".join(parser.parts)


@pytest.mark.parametrize(
    "host", ["pyevp.dev", "mail.pyevp.dev", "demo.pyevp.dev", "unknown.example", "127.0.0.1"]
)
def test_healthz_on_any_host(client: TestClient, host: str) -> None:
    response = client.get("/healthz", headers={"Host": host})
    assert response.status_code == 200
    assert response.text == "ok"


@pytest.mark.parametrize("path", ["/", "/login", "/me", "/.well-known/web-identity"])
def test_unknown_host(client: TestClient, path: str) -> None:
    assert client.get(path, headers={"Host": "unknown.example"}).status_code == 404


def test_routing_order_and_disabled_docs(application: Starlette, client: TestClient) -> None:
    routes = application.routes
    assert isinstance(routes[0], Route)
    assert routes[0].path == "/healthz"
    for route, host in zip(routes[1:3], ["pyevp.dev", "mail.pyevp.dev"], strict=True):
        assert isinstance(route, Host)
        assert route.host == host
        assert isinstance(route.app, FastAPI)
        assert route.app.docs_url is None
        assert route.app.redoc_url is None
        assert route.app.openapi_url is None
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert client.get(path, headers={"Host": host}).status_code == 404


def test_web_identity(client: TestClient) -> None:
    response = client.get(SITE + "/.well-known/web-identity")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {
        "accounts_endpoint": MAIL + site.ACCOUNTS_PATH,
        "login_url": MAIL + site.LOGIN_PATH,
    }
    assert client.get("/.well-known/web-identity").status_code == 404


def test_metadata_and_jwks(client: TestClient, issuer: Issuer) -> None:
    response = client.get("/.well-known/email-verification")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.json() == issuer.metadata_document()
    assert response.json()["issuer"] == MAIL
    assert response.json()["issuance_endpoint"] == MAIL + site.ISSUANCE_PATH
    response = client.get(site.JWKS_PATH)
    assert response.headers["content-type"] == "application/json"
    assert response.json() == issuer.jwks_document()
    assert "d" not in response.json()["keys"][0]


def test_accounts(client: TestClient) -> None:
    for headers in ({}, {"Sec-Fetch-Dest": "document"}):
        response = client.get(site.ACCOUNTS_PATH, headers=headers)
        assert response.status_code == 400
        assert response.headers["cache-control"] == "no-store"
    fedcm = {"Sec-Fetch-Dest": "webidentity", "Origin": RP}
    response = client.get(site.ACCOUNTS_PATH, headers=fedcm)
    assert response.status_code == 401
    assert response.json() == {"accounts": []}
    assert response.headers["cache-control"] == "no-store"
    client.post("/login")
    response = client.get(site.ACCOUNTS_PATH, headers=fedcm)
    assert response.status_code == 200
    assert response.json() == {"accounts": [{"id": EMAIL, "email": EMAIL, "name": EMAIL}]}
    assert response.headers["cache-control"] == "no-store"
    assert not any(name.startswith("access-control-") for name in response.headers)


@pytest.mark.parametrize("path", ["/", "/login"])
def test_provider_page(client: TestClient, path: str) -> None:
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert f"Sign in as {EMAIL}" in response.text
    assert "not a mailbox" in response.text
    assert "proves nothing" in response.text
    assert 'action="/login"' in response.text
    assert 'href="https://pyevp.dev/demo"' in response.text
    assert 'href="https://pyevp.dev"' in response.text
    assert "/* test stylesheet */" in response.text
    assert "<input" not in response.text
    client.post("/login")
    response = client.get(path)
    assert "Sign out" in response.text
    assert 'action="/logout"' in response.text
    assert "setStatus(" not in response.text


def test_login_logout_and_me(client: TestClient) -> None:
    response = client.get("/me")
    assert response.json() == {"email": None, "issued": 0, "build_sha": "test-sha"}
    assert response.headers["cache-control"] == "no-store"
    login = client.post("/login", headers={"Sec-Fetch-Site": "same-origin"})
    assert login.status_code == 200
    assert login.headers["cache-control"] == "no-store"
    assert login.headers["set-login"] == "logged-in"
    assert 'navigator.login.setStatus("logged-in")' in login.text
    assert COOKIE in client.cookies
    assert client.get("/me").json() == {"email": EMAIL, "issued": 0, "build_sha": "test-sha"}
    logout = client.post("/logout")
    assert logout.status_code == 200
    assert logout.headers["cache-control"] == "no-store"
    assert logout.headers["set-login"] == "logged-out"
    assert 'navigator.login.setStatus("logged-out")' in logout.text
    assert COOKIE not in client.cookies
    assert client.get("/me").json() == {"email": None, "issued": 0, "build_sha": "test-sha"}


@pytest.mark.parametrize("path", ["/login", "/logout"])
@pytest.mark.parametrize("fetch_site", ["cross-site", "same-site", "none", ""])
def test_csrf_rejected(client: TestClient, path: str, fetch_site: str) -> None:
    client.post("/login")
    before = client.get("/me").json()
    response = client.post(path, headers={"Sec-Fetch-Site": fetch_site})
    assert response.status_code == 403
    assert response.json() == {"error": "forbidden"}
    assert "set-login" not in response.headers
    assert client.get("/me").json() == before


def test_csrf_cannot_create_a_session(client: TestClient) -> None:
    response = client.post("/login", headers={"Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 403
    assert COOKIE not in client.cookies


def test_cookie_attributes_and_host_isolation(client: TestClient) -> None:
    response = client.post("/login")
    cookie = SimpleCookie(response.headers["set-cookie"])[COOKIE]
    assert cookie["path"] == "/"
    assert cookie["max-age"] == "3600"
    assert cookie["samesite"].lower() == "none"
    assert cookie["secure"]
    assert cookie["httponly"]
    assert not cookie["domain"]
    landing = client.get(SITE + "/demo")
    assert SITE_COOKIE in landing.headers["set-cookie"]
    # TestClient's stdlib cookie jar sends host-only cookies to subdomains.
    # Check the stored scope and independent session state instead.
    stored = next(cookie for cookie in client.cookies.jar if cookie.name == SITE_COOKIE)
    assert stored.domain == "pyevp.dev"
    assert not stored.domain_specified
    assert client.get("/me").json() == {"email": EMAIL, "issued": 0, "build_sha": "test-sha"}
    assert COOKIE not in landing.request.headers.get("cookie", "")
    assert COOKIE in client.get("/me").request.headers["cookie"]
    response = client.post("/logout")
    cleared = SimpleCookie(response.headers["set-cookie"])[COOKIE]
    assert cleared.value == "null"
    assert cleared["expires"]
    assert cleared["secure"]
    assert cleared["httponly"]
    assert cleared["samesite"].lower() == "none"
    assert not cleared["domain"]


@pytest.mark.parametrize("email", [EMAIL, "DeMo@PyEvP.DeV"])
def test_full_issuance(
    client: TestClient,
    issuer: Issuer,
    clock: FixedClock,
    email: str,
) -> None:
    client.post("/login")
    browser = FakeBrowser(clock=clock)
    response = _issue(client, browser, email)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    verifier = Verifier(
        audience=RP,
        resolver=InMemoryDns({k: [v] for k, v in issuer.dns_txt_records().items()}),
        fetcher=InMemoryHttp(
            {
                MAIL + "/.well-known/email-verification": client.get(
                    "/.well-known/email-verification"
                ).json(),
                issuer.jwks_uri: client.get(site.JWKS_PATH).json(),
            }
        ),
        clock=clock,
    )
    token = browser.present(response.json()["issuance_token"], audience=RP, nonce="n")
    assert verifier.verify(token, nonce="n", email=email).email == email
    response = client.get("/me")
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {"email": EMAIL, "issued": 1, "build_sha": "test-sha"}
    assert _issue(client, FakeBrowser(clock=clock)).status_code == 200
    assert client.get("/me").json()["issued"] == 2
    assert _issue(client, browser, "other@pyevp.dev").status_code == 401
    assert client.get("/me").json()["issued"] == 2
    client.post("/login")
    assert client.get("/me").json()["issued"] == 0
    client.post("/logout")
    assert client.get("/me").json()["issued"] == 0


def test_issuance_failures_look_the_same(client: TestClient, clock: FixedClock) -> None:
    browser = FakeBrowser(clock=clock)
    signed_out = _issue(client, browser)
    assert client.get("/me").json()["issued"] == 0
    client.post("/login")
    wrong_user = _issue(client, browser, "someone@pyevp.dev")
    wrong_domain = _issue(client, browser, "someone@other.example")
    assert signed_out.status_code == wrong_user.status_code == wrong_domain.status_code == 401
    assert signed_out.content == wrong_user.content == wrong_domain.content
    assert signed_out.json()["error"] == "authentication_required"
    assert signed_out.headers["cache-control"] == "no-store"
    assert client.get("/me").json()["issued"] == 0
    client.post("/logout")
    assert _issue(client, browser).status_code == 401


def test_unsigned_and_oversized_requests(client: TestClient) -> None:
    response = client.post(
        site.ISSUANCE_PATH,
        headers={"Content-Type": "application/json", "Sec-Fetch-Dest": "email-verification"},
        content=b'{"email":"private-request-detail@pyevp.dev"}',
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_signature"
    assert response.headers["signature-error"] == "error=invalid_signature"
    assert "private-request-detail" not in response.text
    response = client.post(site.ISSUANCE_PATH, content=b"private-request-detail" * site.MAX_BODY)
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    assert response.headers["cache-control"] == "no-store"
    assert "private-request-detail" not in response.text


@pytest.mark.parametrize("missing", ["key", "secret"])
def test_factory_requires_production_credentials(
    signer: SigningKey,
    missing: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An ambient development environment cannot change the explicit factory settings.
    monkeypatch.setenv("EVP_DEV", "1")
    with pytest.raises(
        RuntimeError, match="EVP_SIGNING_JWK" if missing == "key" else "SESSION_SECRET"
    ):
        site.create_app(signer=None if missing == "key" else signer, session_secret=None)


def test_missing_stylesheet_refuses_startup(signer: SigningKey, tmp_path: Path) -> None:
    app = site.create_app(
        signer=signer, session_secret="test", stylesheet_path=tmp_path / "absent.css"
    )
    with pytest.raises(RuntimeError, match=r"static/site\.css"), TestClient(app):
        pass


def test_dev_ephemeral_keys_and_missing_css(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    app = site.create_app(dev=True, stylesheet_path=tmp_path / "absent.css")
    other = site.create_app(dev=True)
    assert app.state.issuer.signer.kid == "dev"
    assert app.state.issuer.jwks_document() != other.state.issuer.jwks_document()
    with TestClient(app, base_url=SITE) as client:
        assert client.get("/").status_code == 200
    assert "Missing static/site.css" in caplog.text


def test_environment_settings(monkeypatch: pytest.MonkeyPatch, stylesheet: Path) -> None:
    for variable in ("EVP_SIGNING_JWK", "SESSION_SECRET", "EVP_DEV"):
        monkeypatch.delenv(variable, raising=False)
    with pytest.raises(RuntimeError, match="EVP_SIGNING_JWK"):
        site._from_environment()
    key = OKPKey.generate_key("Ed25519", private=True).as_dict(private=True)
    key["kid"] = "environment-test"
    monkeypatch.setenv("EVP_SIGNING_JWK", json.dumps(key))
    with pytest.raises(RuntimeError, match="SESSION_SECRET"):
        site._from_environment()
    monkeypatch.setenv("SESSION_SECRET", "environment-secret")
    monkeypatch.setenv("EVP_SITE_HOST", "site.example")
    monkeypatch.setenv("EVP_MAIL_HOST", "mail.example")
    monkeypatch.setenv("EVP_EMAIL_DOMAIN", "email.example")
    monkeypatch.setenv("EVP_LEGACY_DEMO_HOST", "old.example")
    monkeypatch.setenv("BUILD_SHA", "environment-sha")
    custom_examples = stylesheet.parent / "examples"
    for _, _, path in site.EXAMPLES:
        example = custom_examples / path
        example.parent.mkdir(parents=True, exist_ok=True)
        example.write_text("# landing:start\n# selected EVP_EXAMPLES_DIR\n# landing:end\n")
    monkeypatch.setenv("EVP_EXAMPLES_DIR", str(custom_examples))
    monkeypatch.setattr(site, "STYLESHEET", stylesheet)
    with TestClient(site._from_environment(), base_url="https://mail.example") as client:
        assert client.post("/login").headers["set-login"] == "logged-in"
        assert client.get("/me").json() == {
            "email": "demo@email.example",
            "issued": 0,
            "build_sha": "environment-sha",
        }
        identity = client.get("https://site.example/.well-known/web-identity").json()
        assert identity["accounts_endpoint"] == "https://mail.example/fedcm/accounts"
        landing = client.get("https://site.example/").text
        assert 'href="/demo"' in landing
        demo = client.get("https://site.example/demo").text
        assert 'href="https://mail.example/"' in demo
        assert "https://accounts.google.com, https://mail.example" in demo
        assert 'href="https://site.example/demo"' in client.get("/").text
        redirect = client.get("https://old.example/any/path", follow_redirects=False)
        assert redirect.status_code == 301
        assert redirect.headers["location"] == "https://site.example/demo"
        assert "# selected EVP_EXAMPLES_DIR" in _page_text(landing)
        assert client.get(site.JWKS_PATH).json()["keys"][0]["kid"] == "environment-test"


def test_real_markers_and_landing(client: TestClient) -> None:
    response = client.get(SITE + "/")
    assert response.status_code == 200
    text = _page_text(response.text)
    assert 'pip install "pyevp[all]"' in text
    for url in (
        "/demo",
        "https://docs.pyevp.dev/",
        "https://docs.pyevp.dev/ja/latest/",
        "https://github.com/gaato/pyevp",
        "https://pypi.org/project/pyevp/",
        "https://github.com/gaato/pyevp/blob/main/LICENSE",
        "https://docs.pyevp.dev/en/latest/compatibility.html",
    ):
        assert f'href="{url}"' in response.text
    for ident, label, path in site.EXAMPLES:
        source = site.EXAMPLES_DIR / path
        lines = source.read_text().splitlines()
        assert sum(line.strip() == "# landing:start" for line in lines) == 1
        assert sum(line.strip() == "# landing:end" for line in lines) == 1
        code = site.extract_example(source)
        assert 10 <= len(code.splitlines()) <= 30
        # Each tab shows the verification call and the fallback.
        assert "verify" in code
        assert "except EVPError" in code
        assert code in text
        assert f'<section id="example-{ident}"' in response.text
        assert f">{label}</h3>" in response.text
    assert "# landing:start" not in response.text
    assert "/* test stylesheet */" in response.text
    assert "@media (prefers-color-scheme: dark)" in response.text
    assert 'role="tabpanel"' not in response.text  # No-JS sections stay visible.
    assert "ArrowRight" in response.text
    assert "ArrowLeft" in response.text


@pytest.mark.parametrize(
    "source",
    [
        "pass\n",
        "# landing:start\npass\n",
        "# landing:end\npass\n",
        "# landing:start\n# landing:start\npass\n# landing:end\n",
        "# landing:start\npass\n# landing:end\n# landing:end\n",
        "# landing:end\npass\n# landing:start\n",
    ],
)
def test_invalid_markers_raise(tmp_path: Path, source: str) -> None:
    path = tmp_path / "app.py"
    path.write_text(source)
    with pytest.raises(ValueError, match="exactly one ordered landing marker pair"):
        site.extract_example(path)


def test_marker_dedent(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    path.write_text("outside\n    # landing:start\n    if True:\n        pass\n    # landing:end\n")
    assert site.extract_example(path) == "if True:\n    pass\n"


def test_missing_example_refuses_startup(tmp_path: Path, stylesheet: Path) -> None:
    app = site.create_app(dev=True, examples_dir=tmp_path, stylesheet_path=stylesheet)
    with pytest.raises(FileNotFoundError), TestClient(app):
        pass


def test_expensive_landing_parts_are_computed_once(
    application: Starlette, stylesheet: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with TestClient(application, base_url=SITE) as client:
        before = client.get("/").text
        stylesheet.write_text("/* changed after startup */")

        def recomputed(*args: object, **kwargs: object) -> None:
            pytest.fail("expensive landing content recomputed after startup")

        monkeypatch.setattr(site, "extract_example", recomputed)
        monkeypatch.setattr(site, "highlight", recomputed)
        monkeypatch.setattr(site, "_formatter", recomputed)
        monkeypatch.setattr(site.Template, "render", recomputed)
        after = client.get("/").text
        assert before == after


def test_formatter_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    def without_plugin(name: str) -> type:
        if name.startswith("a11y-"):
            raise ClassNotFound(name)
        return get_style_by_name(name)

    monkeypatch.setattr(site, "get_style_by_name", without_plugin)
    assert site._formatter("a11y-light", "default").style == get_style_by_name("default")
    assert site._formatter("a11y-dark", "native").style == get_style_by_name("native")


def test_security_headers(client: TestClient) -> None:
    for url in (SITE + "/", MAIL + "/", MAIL + "/healthz"):
        response = client.get(url)
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert "content-security-policy" not in response.headers


@pytest.fixture
def rp_issuer() -> FakeIssuer:
    return FakeIssuer.gmail_like()


@pytest.fixture
def stranger() -> FakeIssuer:
    """An issuer the demo does not allow, for a domain an attacker controls."""
    return FakeIssuer(host="evil.example", email_domains=("evil.example",))


@contextlib.asynccontextmanager
async def _opened(http: AsyncInMemoryHttp) -> AsyncIterator[AsyncInMemoryHttp]:
    """Stand in for ``AsyncHttpxFetcher()``, which the app opens with ``async with``."""
    yield http


@pytest.fixture
def rp_http(rp_issuer: FakeIssuer, stranger: FakeIssuer) -> AsyncInMemoryHttp:
    return AsyncInMemoryHttp(rp_issuer.http_documents() | stranger.http_documents())


@pytest.fixture
def rp_client(
    rp_issuer: FakeIssuer,
    stranger: FakeIssuer,
    rp_http: AsyncInMemoryHttp,
    application: Starlette,
) -> Iterator[TestClient]:
    dns = AsyncInMemoryDns(rp_issuer.dns_records() | stranger.dns_records())
    verifier = AsyncVerifier(
        audience=SITE,
        resolver=site.AllowedIssuers(RecordingResolver(dns), [rp_issuer.issuer]),
        fetcher=RecordingFetcher(rp_http),
        cache=TrackingCache(InMemoryCache(clock=rp_issuer.clock)),
        clock=RecordingClock(rp_issuer.clock),
        replay_guard=InMemoryReplayGuard(clock=rp_issuer.clock),
    )
    application.state.site.dependency_overrides[site.get_verifier] = lambda: verifier
    with TestClient(application, base_url=SITE) as rp_client:
        yield rp_client
    application.state.site.dependency_overrides.clear()


def _nonce(rp_client: TestClient) -> str:
    match = re.search(r'nonce="([^"]+)"', rp_client.get("/demo").text)
    assert match
    return match.group(1)


def _present(rp_issuer: FakeIssuer, email: str, nonce: str) -> str:
    browser = FakeBrowser(clock=rp_issuer.clock)
    return browser.present(rp_issuer.issue(email, browser.public_jwk), audience=SITE, nonce=nonce)


def test_verified(rp_client: TestClient, rp_issuer: FakeIssuer) -> None:
    evt = _present(rp_issuer, "alice@gmail.example", _nonce(rp_client))
    response = rp_client.post("/verify", data={"email": "alice@gmail.example", "evt": evt})
    assert response.status_code == 200
    assert "Verified" in response.text
    assert "alice@gmail.example" in response.text
    assert rp_issuer.issuer in response.text


def test_no_token(rp_client: TestClient) -> None:
    _nonce(rp_client)
    response = rp_client.post("/verify", data={"email": "alice@gmail.example"})
    assert response.status_code == 200
    assert "No token received" in response.text
    assert "chrome://flags/#email-verification-protocol" in response.text


def test_failure_shows_code(rp_client: TestClient, rp_issuer: FakeIssuer) -> None:
    _nonce(rp_client)
    evt = _present(rp_issuer, "alice@gmail.example", "stolen")
    response = rp_client.post("/verify", data={"email": "alice@gmail.example", "evt": evt})
    assert response.status_code == 400
    assert "nonce_mismatch" in response.text


def test_replay(rp_client: TestClient, rp_issuer: FakeIssuer) -> None:
    nonce = _nonce(rp_client)
    captured = dict(rp_client.cookies)
    form = {
        "email": "alice@gmail.example",
        "evt": _present(rp_issuer, "alice@gmail.example", nonce),
    }
    assert rp_client.post("/verify", data=form).status_code == 200
    rp_client.cookies.clear()
    rp_client.cookies.update(captured)
    response = rp_client.post("/verify", data=form)
    assert response.status_code == 400
    assert "token_replayed" in response.text


def test_unlisted_issuer_is_never_fetched(
    rp_client: TestClient, stranger: FakeIssuer, rp_http: AsyncInMemoryHttp
) -> None:
    evt = _present(stranger, "mallory@evil.example", _nonce(rp_client))
    response = rp_client.post("/verify", data={"email": "mallory@evil.example", "evt": evt})
    assert response.status_code == 400
    assert "issuer_discovery_failed" in response.text
    assert not any("evil.example" in url for url in rp_http.requests)


def test_output_is_escaped(rp_client: TestClient) -> None:
    _nonce(rp_client)
    evt = "<script>alert(1)</script>"
    response = rp_client.post("/verify", data={"email": "a@gmail.example", "evt": evt})
    assert response.status_code == 400
    assert "<script>alert(1)" not in response.text


def test_healthz_and_headers(rp_client: TestClient) -> None:
    response = rp_client.get("/healthz")
    assert response.text == "ok"
    assert response.headers["x-frame-options"] == "DENY"
    assert "content-security-policy" not in response.headers


def test_nonce_and_site_cookie(application: Starlette) -> None:
    with TestClient(application, base_url=SITE) as client:
        response = client.get("/demo")
        cookie = SimpleCookie(response.headers["set-cookie"])[SITE_COOKIE]
        assert cookie["path"] == "/"
        assert cookie["samesite"].lower() == "lax"
        assert cookie["secure"]
        assert cookie["httponly"]
        assert not cookie["domain"]
        nonce = re.search(r'nonce="([^"]+)"', response.text)
        assert nonce
        session = json.loads(base64.b64decode(cookie.value.split(".")[0]))
        assert session == {site.SESSION_NONCE: nonce.group(1)}
        assert _nonce(client) != nonce.group(1)
        assert response.headers["cache-control"] == "no-store"
        assert 'autocomplete="email-verification-token"' in response.text
        assert 'autocomplete="email"' in response.text
        assert 'action="/verify"' in response.text
        assert '<section id="demo"' in response.text
        assert 'href="https://mail.pyevp.dev/"' in response.text
        assert "demo@pyevp.dev" in response.text
        assert "This page is not a secure context." in response.text
        assert "window.isSecureContext" in response.text
        assert "You are signed in" not in response.text
        stored = next(cookie for cookie in client.cookies.jar if cookie.name == SITE_COOKIE)
        assert stored.domain == "pyevp.dev"
        assert not stored.domain_specified
        assert client.get(MAIL + "/me").json()["email"] is None


@pytest.mark.parametrize(
    ("host", "mail_host", "accepted"),
    [
        ("mail.pyevp.dev", "mail.pyevp.dev", True),
        ("pyevp.dev", "mail.pyevp.dev", False),
        ("mail.example", "mail.example", True),
        ("mail.pyevp.dev", "mail.example", False),
    ],
)
def test_default_allowlist(
    *,
    host: str,
    mail_host: str,
    accepted: bool,
    signer: SigningKey,
    stylesheet: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    provider = FakeIssuer(host=host, email_domains=("pyevp.dev",))
    http = AsyncInMemoryHttp(provider.http_documents())
    monkeypatch.setattr(
        site, "AsyncDnsPythonResolver", lambda: AsyncInMemoryDns(provider.dns_records())
    )
    monkeypatch.setattr(httpx_adapter, "AsyncHttpxFetcher", lambda: _opened(http))
    application = site.create_app(
        signer=signer,
        session_secret="test-session-secret",
        mail_host=mail_host,
        clock=provider.clock,
        stylesheet_path=stylesheet,
    )
    with (
        caplog.at_level(logging.INFO, logger="pyevp"),
        TestClient(application, base_url=SITE) as client,
    ):
        nonce = _nonce(client)
        captured = dict(client.cookies)
        evt = _present(provider, EMAIL, nonce)
        form = {"email": EMAIL, "evt": evt}
        response = client.post("/verify", data=form)
        assert response.headers["cache-control"] == "no-store"
        assert '<section id="demo"' in response.text
        assert 'href="/demo"' in response.text
        if accepted:
            assert response.status_code == 200
            assert "Verified" in response.text
            assert f"<dd>{EMAIL}</dd>" in response.text
            assert f"<dd>{provider.issuer}</dd>" in response.text
            assert "EVP verification succeeded" in caplog.text
            client.cookies.clear()
            client.cookies.update(captured)
            replay = client.post("/verify", data=form)
            assert replay.status_code == 400
            assert "token_replayed" in replay.text
        else:
            assert response.status_code == 400
            assert "issuer_discovery_failed" in response.text
            assert (
                list(_statuses(response.text).values())
                == ["passed", "passed", "failed"] + ["not run"] * 3
            )
            assert "_email-verification.pyevp.dev" in response.text
            assert not http.requests
            assert "EVP verification failed" in caplog.text
        assert EMAIL not in caplog.text
        assert evt not in caplog.text


@pytest.mark.parametrize(
    ("allowed", "host", "accepted"),
    [
        ("https://custom.example", "custom.example", True),
        ("https://custom.example", "mail.pyevp.dev", False),
        ("", "mail.pyevp.dev", False),
    ],
)
def test_environment_allowlist_override(
    *,
    allowed: str,
    host: str,
    accepted: bool,
    stylesheet: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("EVP_DEV", "1")
    monkeypatch.delenv("EVP_SIGNING_JWK", raising=False)
    monkeypatch.delenv("SESSION_SECRET", raising=False)
    monkeypatch.setenv("EVP_ALLOWED_ISSUERS", allowed)
    monkeypatch.setattr(site, "STYLESHEET", stylesheet)
    provider = FakeIssuer(
        host=host, email_domains=("pyevp.dev",), clock=FixedClock(site.system_clock())
    )
    http = AsyncInMemoryHttp(provider.http_documents())
    monkeypatch.setattr(
        site, "AsyncDnsPythonResolver", lambda: AsyncInMemoryDns(provider.dns_records())
    )
    monkeypatch.setattr(httpx_adapter, "AsyncHttpxFetcher", lambda: _opened(http))
    with TestClient(site._from_environment(), base_url=SITE) as client:
        nonce = _nonce(client)
        response = client.post(
            "/verify", data={"email": EMAIL, "evt": _present(provider, EMAIL, nonce)}
        )
        if accepted:
            assert response.status_code == 200
            assert "Verified" in response.text
        else:
            assert response.status_code == 400
            assert "issuer_discovery_failed" in response.text
            assert not http.requests
        assert f"Accepted issuers: {allowed}." in response.text


@pytest.mark.parametrize(
    "method", ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"]
)
@pytest.mark.parametrize("path", ["/", "/verify", "/arbitrary/nested/path?query=value"])
def test_legacy_host_redirect(client: TestClient, method: str, path: str) -> None:
    response = client.request(method, LEGACY + path, follow_redirects=False)
    assert response.status_code == 301
    assert response.headers["location"] == SITE + "/demo"
    assert "set-cookie" not in response.headers


@pytest.mark.parametrize("outcome", ["verified", "no-token", "failed"])
def test_nonce_is_consumed(rp_client: TestClient, rp_issuer: FakeIssuer, outcome: str) -> None:
    nonce = _nonce(rp_client)
    evt = _present(rp_issuer, "alice@gmail.example", "wrong" if outcome == "failed" else nonce)
    response = rp_client.post(
        "/verify",
        data={"email": "alice@gmail.example", "evt": "" if outcome == "no-token" else evt},
    )
    assert response.status_code == (400 if outcome == "failed" else 200)
    again = rp_client.post("/verify", data={"email": "alice@gmail.example", "evt": evt})
    assert again.status_code == 400
    assert "Session expired" in again.text


@pytest.mark.parametrize("success", [True, False])
def test_result_values_are_escaped(
    application: Starlette, clock: FixedClock, success: bool
) -> None:
    payload = '<script>alert("x")</script>'
    verifier = AsyncMock(spec=AsyncVerifier)
    verifier.profile = DEFAULT_PROFILE
    verifier.audience = SITE
    if success:
        verifier.verify.return_value = VerifiedEmail(
            email=payload,
            issuer=payload,
            issued_at=clock.now,
            expires_at=None,
            is_private_email=False,
            claims={},
        )
    else:
        verifier.verify.side_effect = EVPError(ErrorCode.MALFORMED_TOKEN, payload)
    application.state.site.dependency_overrides[site.get_verifier] = lambda: verifier
    with TestClient(application, base_url=SITE) as client:
        _nonce(client)
        response = client.post("/verify", data={"email": EMAIL, "evt": "token"})
        assert response.status_code == (200 if success else 400)
        assert payload not in response.text
        assert "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;" in response.text


def _statuses(page: str) -> dict[str, str]:
    return dict(
        re.findall(r'id="trace-([^" ]+)" class="trace-step [^"]*" data-status="([^"]+)"', page)
    )


def test_error_mapping_is_exhaustive() -> None:
    assert set(ERROR_STEPS) == set(ErrorCode)
    assert all(ERROR_STEPS.values())


def test_landing_has_no_session_or_nonce(application: Starlette) -> None:
    with TestClient(application, base_url=SITE) as client:
        before = client.get("/")
        assert "set-cookie" not in before.headers
        assert SITE_COOKIE not in client.cookies
        assert "nonce=" not in before.text
        assert 'id="verify-form"' not in before.text
        _nonce(client)
        after = client.get("/")
        assert "set-cookie" not in after.headers
        assert after.text == before.text
        assert _nonce(client)


def test_demo_flow_and_submit_script(rp_client: TestClient) -> None:
    page = rp_client.get("/demo").text
    for hook in (
        "demo-browser",
        "demo-provider",
        "demo-verify",
        "verify-form",
        "evt",
        "verify-button",
        "token-status",
        "browser-hint",
        "demo-result",
    ):
        assert f'id="{hook}"' in page
    assert page.index("Use Chrome with EVP") < page.index("Sign in at an email provider")
    assert page.index("demo email provider") < page.index("Alternatively, use a Gmail")
    # Chrome starts EVP only on user input or autofill, so the field must start empty.
    assert 'placeholder="demo@pyevp.dev"' in page
    assert 'value="demo@pyevp.dev"' not in page
    assert 'role="status" aria-live="polite"' in page
    for script in (
        'addEventListener("submit"',
        "event.preventDefault()",
        "token.value",
        "form.requestSubmit(submitter)",
        "8000",
        "400",
        '"aria-busy"',
        "navigator.userAgentData?.brands",
        "navigator.userAgent",
        ">= 150",
        "Waiting for your email provider…",
        "Token received, verifying…",
    ):
        assert script in page
    assert "form.submit(" not in page
    assert ".disabled" not in page
    assert "setInterval" not in page
    assert "/me" not in page
    assert "You are signed in" not in page


def test_success_trace_and_claims(rp_client: TestClient, rp_issuer: FakeIssuer) -> None:
    nonce = _nonce(rp_client)
    evt = _present(rp_issuer, "alice@gmail.example", nonce)
    page = rp_client.post("/verify", data={"email": "alice@gmail.example", "evt": evt}).text
    assert list(_statuses(page).values()) == ["passed"] * 6
    assert "_email-verification.gmail.example" in page
    assert rp_issuer.metadata_url in page
    assert rp_issuer.jwks_uri in page
    assert "Elapsed:" in page
    assert " ms" in page
    assert '<details id="decoded-claims"' in page
    text = _page_text(page)
    assert "EVT payload claims — decoded for display" in text
    assert "KB-JWT payload claims — decoded for display" in text
    assert '"email": "alice@gmail.example"' in text
    assert f'"nonce": "{nonce}"' in text
    assert '"aud": "https://pyevp.dev"' in text
    assert '"sd_hash":' in text
    assert evt not in page
    assert all(part.rsplit(".", 1)[-1] not in page for part in evt.split("~"))


def test_binding_trace_has_no_io(rp_client: TestClient, rp_issuer: FakeIssuer) -> None:
    _nonce(rp_client)
    evt = _present(rp_issuer, "alice@gmail.example", "wrong")
    page = rp_client.post("/verify", data={"email": "alice@gmail.example", "evt": evt}).text
    assert list(_statuses(page).values()) == ["passed", "failed"] + ["not run"] * 4
    assert 'class="trace-io ' not in page


def test_metadata_failure(
    rp_client: TestClient, rp_issuer: FakeIssuer, rp_http: AsyncInMemoryHttp
) -> None:
    rp_http.documents[rp_issuer.metadata_url] = {"issuer": rp_issuer.issuer}
    evt = _present(rp_issuer, "alice@gmail.example", _nonce(rp_client))
    response = rp_client.post("/verify", data={"email": "alice@gmail.example", "evt": evt})
    assert response.status_code == 400
    assert "metadata_invalid" in response.text
    assert list(_statuses(response.text).values()) == ["passed"] * 3 + [
        "failed",
        "not run",
        "not run",
    ]
    assert rp_issuer.metadata_url in response.text
    assert rp_issuer.jwks_uri not in rp_http.requests


def test_jwks_failure(
    rp_client: TestClient, rp_issuer: FakeIssuer, rp_http: AsyncInMemoryHttp
) -> None:
    rp_http.documents[rp_issuer.jwks_uri] = {"keys": []}
    evt = _present(rp_issuer, "alice@gmail.example", _nonce(rp_client))
    response = rp_client.post("/verify", data={"email": "alice@gmail.example", "evt": evt})
    assert response.status_code == 400
    assert list(_statuses(response.text).values()) == ["passed"] * 4 + ["failed", "not run"]


def test_cached_fetches_and_request_isolation(
    rp_client: TestClient, rp_issuer: FakeIssuer, rp_http: AsyncInMemoryHttp
) -> None:
    for attempt in range(2):
        evt = _present(rp_issuer, "alice@gmail.example", _nonce(rp_client))
        page = rp_client.post("/verify", data={"email": "alice@gmail.example", "evt": evt}).text
        assert list(_statuses(page).values()) == ["passed"] * 6
        assert page.count('class="trace-io ') == (3 if attempt == 0 else 1)
    assert rp_http.requests == [rp_issuer.metadata_url, rp_issuer.jwks_uri]
    _nonce(rp_client)
    failed = rp_client.post(
        "/verify",
        data={
            "email": "alice@gmail.example",
            "evt": _present(rp_issuer, "alice@gmail.example", "wrong"),
        },
    ).text
    assert 'class="trace-io ' not in failed


@pytest.mark.parametrize("claims", [{"email_verified": False}, {"email": "other@gmail.example"}])
def test_early_claims_failure_does_not_invent_network_checks(
    rp_client: TestClient,
    rp_issuer: FakeIssuer,
    claims: dict[str, object],
) -> None:
    browser = FakeBrowser(clock=rp_issuer.clock)
    evt = browser.present(
        rp_issuer.issue("alice@gmail.example", browser.public_jwk, claims=claims),
        audience=SITE,
        nonce=_nonce(rp_client),
    )
    page = rp_client.post("/verify", data={"email": "alice@gmail.example", "evt": evt}).text
    statuses = _statuses(page)
    assert statuses["claims"] == "failed"
    assert statuses["dns"] == statuses["metadata"] == statuses["jwks"] == "not run"
    assert statuses["binding"] == ("not run" if "email_verified" in claims else "passed")
    assert 'class="trace-io ' not in page


def test_decoded_claims_are_escaped(rp_client: TestClient, rp_issuer: FakeIssuer) -> None:
    payload = '<script>alert("claims")</script>'
    browser = FakeBrowser(clock=rp_issuer.clock)
    evt = browser.present(
        rp_issuer.issue("alice@gmail.example", browser.public_jwk, claims={"display": payload}),
        audience=SITE,
        nonce=_nonce(rp_client),
    )
    response = rp_client.post("/verify", data={"email": "alice@gmail.example", "evt": evt})
    assert response.status_code == 200
    assert payload not in response.text
    assert "&lt;script&gt;" in response.text
    assert json.dumps(payload)[1:-1] in _page_text(response.text)


def test_lookup_targets_are_escaped(
    rp_client: TestClient,
    rp_issuer: FakeIssuer,
    rp_http: AsyncInMemoryHttp,
) -> None:
    target = rp_issuer.issuer + '/<script>alert("io")</script>'
    rp_http.documents[rp_issuer.metadata_url] = {**rp_issuer.metadata, "jwks_uri": target}
    evt = _present(rp_issuer, "alice@gmail.example", _nonce(rp_client))
    response = rp_client.post("/verify", data={"email": "alice@gmail.example", "evt": evt})
    assert response.status_code == 400
    assert "issuer_unreachable" in response.text
    assert target not in response.text
    assert "&lt;script&gt;alert(&#34;io&#34;)&lt;/script&gt;" in response.text
    assert list(_statuses(response.text).values()) == ["passed"] * 4 + ["failed", "not run"]


@pytest.mark.parametrize("stage", ["metadata", "jwks"])
def test_cached_invalid_document_keeps_its_failure_stage(
    rp_client: TestClient,
    rp_issuer: FakeIssuer,
    rp_http: AsyncInMemoryHttp,
    stage: str,
) -> None:
    url = rp_issuer.metadata_url if stage == "metadata" else rp_issuer.jwks_uri
    rp_http.documents[url] = {"issuer": rp_issuer.issuer} if stage == "metadata" else {"keys": []}
    for attempt in range(2):
        evt = _present(rp_issuer, "alice@gmail.example", _nonce(rp_client))
        response = rp_client.post("/verify", data={"email": "alice@gmail.example", "evt": evt})
        assert response.status_code == 400
        assert _statuses(response.text)[stage] == "failed"
        if attempt == 1:
            assert response.text.count('class="trace-io ') == 1
    assert rp_http.requests.count(url) == 1


def _head_meta(page: str) -> dict[str, str]:
    head = page.split("</head>", 1)[0]
    found = dict(re.findall(r'<meta (?:name|property)="([^"]+)" content="([^"]*)"', head))
    title = re.search(r"<title>([^<]*)</title>", head)
    canonical = re.search(r'<link rel="canonical" href="([^"]*)"', head)
    assert title
    assert canonical
    return found | {"title": title.group(1), "canonical": canonical.group(1)}


def test_seo_metadata(rp_client: TestClient) -> None:
    pages = {
        "landing": rp_client.get("/").text,
        "demo": rp_client.get("/demo").text,
        "result": rp_client.post("/verify", data={"email": EMAIL}).text,
        "provider": rp_client.get(MAIL + "/").text,
    }
    canonical = {
        "landing": SITE + "/",
        "demo": SITE + "/demo",
        "result": SITE + "/demo",
        "provider": MAIL + "/",
    }
    seen = set()
    for name, page in pages.items():
        assert page.startswith('<!doctype html>\n<html lang="en">')
        meta = _head_meta(page)
        assert meta["canonical"] == canonical[name]
        assert meta["og:url"] == canonical[name]
        assert meta["og:title"] == meta["title"]
        assert meta["og:description"] == meta["description"]
        assert len(meta["description"]) >= 50
        assert meta["og:type"] == "website"
        assert meta["og:site_name"] == "PyEVP"
        assert meta["twitter:card"] == "summary"
        seen.add((meta["title"], meta["description"]))
    assert len(seen) == 3  # The result page shares the demo page's metadata.
    assert _head_meta(pages["provider"])["robots"] == "noindex"
    assert "robots" not in _head_meta(pages["landing"])
    assert "robots" not in _head_meta(pages["demo"])


def test_site_robots_and_sitemap(rp_client: TestClient) -> None:
    robots = rp_client.get("/robots.txt")
    assert robots.status_code == 200
    assert robots.headers["content-type"].startswith("text/plain")
    assert robots.text.splitlines() == [
        "User-agent: *",
        "Allow: /",
        "",
        "Sitemap: https://pyevp.dev/sitemap.xml",
    ]
    assert "x-robots-tag" not in robots.headers
    sitemap = rp_client.get("/sitemap.xml")
    assert sitemap.status_code == 200
    assert sitemap.headers["content-type"].startswith("application/xml")
    assert sitemap.text.startswith('<?xml version="1.0" encoding="UTF-8"?>')
    assert 'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"' in sitemap.text
    assert re.findall(r"<loc>([^<]+)</loc>", sitemap.text) == [SITE + "/", SITE + "/demo"]
    assert "set-cookie" not in robots.headers
    assert "set-cookie" not in sitemap.headers
    for path in ("/", "/demo", "/.well-known/web-identity"):
        assert "x-robots-tag" not in rp_client.get(path).headers


def test_robots_and_sitemap_follow_site_host(signer: SigningKey, stylesheet: Path) -> None:
    app = site.create_app(
        signer=signer, session_secret="test", site_host="site.example", stylesheet_path=stylesheet
    )
    with TestClient(app, base_url="https://site.example") as client:
        assert "Sitemap: https://site.example/sitemap.xml" in client.get("/robots.txt").text
        assert "<loc>https://site.example/demo</loc>" in client.get("/sitemap.xml").text


def test_mail_host_is_not_indexed(client: TestClient) -> None:
    robots = client.get("/robots.txt")
    assert robots.status_code == 200
    assert robots.text.splitlines() == ["User-agent: *", "Disallow: /"]
    responses = [
        robots,
        client.get("/"),
        client.get("/login"),
        client.get("/me"),
        client.get("/healthz"),
        client.get("/no-such-page"),
        client.get(site.JWKS_PATH),
        client.get("/.well-known/email-verification"),
        client.post("/login"),
        client.post("/logout"),
        client.post("/login", headers={"Sec-Fetch-Site": "cross-site"}),
        client.get("https://mail.pyevp.dev:8443/"),
    ]
    for response in responses:
        assert response.headers["x-robots-tag"] == "noindex"
    assert responses[5].status_code == 404
    assert responses[10].status_code == 403
    assert "x-robots-tag" not in client.get(LEGACY + "/", follow_redirects=False).headers


def _origin_trial(page: str) -> list[str]:
    return re.findall(r'<meta http-equiv="origin-trial" content="([^"]*)">', page)


@pytest.mark.parametrize("token", [None, ""])
def test_no_origin_trial_by_default(
    signer: SigningKey, stylesheet: Path, token: str | None
) -> None:
    app = site.create_app(
        signer=signer, session_secret="test", stylesheet_path=stylesheet, origin_trial_token=token
    )
    with TestClient(app, base_url=SITE) as client:
        demo = client.get("/demo").text
        assert not _origin_trial(demo)
        assert "origin trial" not in demo
        assert "set it to Enabled" in _page_text(demo)
        assert "chrome://flags/#email-verification-protocol" in demo
        assert not _origin_trial(client.post("/verify", data={"email": EMAIL}).text)


def test_origin_trial_token(signer: SigningKey, stylesheet: Path) -> None:
    token = "A+b/c=" + '"<x>'
    app = site.create_app(
        signer=signer, session_secret="test", stylesheet_path=stylesheet, origin_trial_token=token
    )
    escaped = "A+b/c=&#34;&lt;x&gt;"
    with TestClient(app, base_url=SITE) as client:
        demo = client.get("/demo").text
        assert _origin_trial(demo) == [escaped]
        assert demo.index("origin-trial") < demo.index("</head>")
        text = _page_text(demo)
        assert "Chrome 150 or later, on desktop or Android, works as is" in text
        assert "chrome://flags/#email-verification-protocol" not in text
        assert "set it to Enabled" not in text
        _nonce(client)
        for data in ({"email": EMAIL}, {"email": EMAIL, "evt": "garbage"}):
            assert _origin_trial(client.post("/verify", data=data).text) == [escaped]
        assert not _origin_trial(client.get("/").text)
        assert not _origin_trial(client.get(MAIL + "/").text)


def test_origin_trial_environment(monkeypatch: pytest.MonkeyPatch, stylesheet: Path) -> None:
    monkeypatch.setenv("EVP_DEV", "1")
    monkeypatch.delenv("EVP_SIGNING_JWK", raising=False)
    monkeypatch.delenv("SESSION_SECRET", raising=False)
    monkeypatch.setattr(site, "STYLESHEET", stylesheet)
    monkeypatch.setenv("EVP_ORIGIN_TRIAL_TOKEN", "environment-token")
    with TestClient(site._from_environment(), base_url=SITE) as client:
        assert _origin_trial(client.get("/demo").text) == ["environment-token"]
    monkeypatch.delenv("EVP_ORIGIN_TRIAL_TOKEN")
    with TestClient(site._from_environment(), base_url=SITE) as client:
        assert not _origin_trial(client.get("/demo").text)


def test_landing_tabs_upgrade_markup(client: TestClient) -> None:
    page = client.get(SITE + "/").text
    assert '<div id="example-tabs" class="tabs tabs-border mt-4" hidden></div>' in page
    for script in ('"tablist"', '"tab"', '"tabpanel"', '"aria-selected"', '"aria-controls"'):
        assert script in page
    for key in ('"Home"', '"End"', "tabIndex"):
        assert key in page
    assert 'type="radio"' not in page
    assert page.count('class="example ') == len(site.EXAMPLES)
