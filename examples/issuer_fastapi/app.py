"""Minimal FastAPI issuer for your own email domains.

This is a sketch of the moving parts, not a mail service: users are a dict and
log in with a password.  Configure it with environment variables::

    pyevp issuer keygen --kid 2026-10 --out signing-key.json
    export EVP_ISSUER=https://issuer.example
    export EVP_PUBLIC_URL=https://issuer.example     # where this app is reachable
    export EVP_EMAIL_DOMAINS=example.com
    export EVP_SIGNING_KEY=signing-key.json
    export SESSION_SECRET=...
    uv run uvicorn app:app --port 8000               # behind an HTTPS proxy

and publish ``_email-verification.example.com TXT "iss=issuer.example"``.
Check the result with ``pyevp discover example.com``.

Chrome also needs a FedCM well-known on the issuer's registrable domain (for
``issuer.example`` that is ``https://issuer.example/.well-known/web-identity``;
for ``accounts.example.com`` it is ``https://example.com/...``).  This app serves
it when the issuer's host is its own registrable domain; otherwise serve
``web_identity_response(...)`` there yourself.  See ``pyevp.issuer.fedcm``.
"""

from __future__ import annotations

import hmac
import html
import json
import os
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, Response
from starlette.middleware.sessions import SessionMiddleware

from pyevp.issuer import (
    MAX_REQUEST_BODY,
    Issuer,
    IssuerResponse,
    SigningKey,
    login_status_headers,
    web_identity_response,
)

ISSUANCE_PATH = "/email-verification/issuance"
JWKS_PATH = "/email-verification/jwks"
ACCOUNTS_PATH = "/fedcm/accounts"
LOGIN_PATH = "/login"
SESSION_USER = "user"
# The issuer answers every method itself; HEAD and OPTIONS are left to the framework.
ISSUANCE_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]


def create_app(issuer: Issuer, users: dict[str, str], *, session_secret: str) -> FastAPI:
    """``users`` maps each email address to its (demo) password."""
    app = FastAPI()
    endpoint = urlsplit(issuer.issuance_endpoint)
    origin = f"{endpoint.scheme}://{endpoint.netloc}"
    # Chrome sends the issuer's cookies with its FedCM accounts request and the issuance
    # request, both cross-site from the relying party: the cookie needs SameSite=None.
    # Browsers then send it with cross-site form posts too, so the endpoints that change
    # the session check where the request comes from (see _same_origin).
    app.add_middleware(
        SessionMiddleware, secret_key=session_secret, same_site="none", https_only=True
    )

    def user_emails(request: Request) -> list[str]:
        """The addresses of the user signed in to this issuer, if any."""
        user = request.session.get(SESSION_USER)
        return [user] if user else []

    @app.get("/.well-known/email-verification")
    async def metadata() -> Response:
        return _response(issuer.metadata_response())

    @app.get(JWKS_PATH)
    async def jwks() -> Response:
        return _response(issuer.jwks_response())

    @app.get("/.well-known/web-identity")
    async def web_identity() -> Response:
        base = issuer.issuer
        return _response(
            web_identity_response(
                accounts_endpoint=base + ACCOUNTS_PATH, login_url=base + LOGIN_PATH
            )
        )

    @app.get(ACCOUNTS_PATH)
    async def accounts(request: Request) -> Response:
        # Chrome checks that the user is signed in with the typed address before issuing.
        result = issuer.accounts_response(
            headers=request.headers.items(), user_emails=user_emails(request)
        )
        return _response(result)

    @app.api_route(ISSUANCE_PATH, methods=ISSUANCE_METHODS)
    async def issuance(request: Request) -> Response:
        # Put per-IP rate limiting in front of this endpoint (proxy or middleware).
        result = await issuer.aissuance_response(
            method=request.method,
            # Starlette keeps repeated header lines apart, as the issuer expects.
            headers=request.headers.items(),
            # Only a POST can succeed; do not wait for the body of anything else.
            body=await _read_body(request) if request.method == "POST" else b"",
            user_emails=user_emails(request),
        )
        return _response(result)

    @app.get(LOGIN_PATH, response_class=HTMLResponse)
    async def login_form() -> str:
        return """<!doctype html>
<form method="post" action="/login">
  <input type="email" name="email" autocomplete="username" required>
  <input type="password" name="password" autocomplete="current-password" required>
  <button>Log in</button>
</form>"""

    @app.post(LOGIN_PATH)
    async def login(
        request: Request, email: Annotated[str, Form()], password: Annotated[str, Form()]
    ) -> Response:
        if not _same_origin(request, origin):
            return HTMLResponse("<p>Cross-site request refused</p>", status_code=403)
        expected = users.get(email, "")
        if not hmac.compare_digest(expected.encode(), password.encode()) or not expected:
            return HTMLResponse(f"<p>Wrong password for {html.escape(email)}</p>", status_code=401)
        request.session[SESSION_USER] = email
        # Login Status API: Chrome skips issuers it knows the user is signed out of.  The
        # header is sent on a page response; whether Chrome honours it on a redirect was
        # not confirmed in testing.
        return HTMLResponse(
            f"<p>Logged in as {html.escape(email)}</p>",
            headers=login_status_headers(signed_in=True),
        )

    @app.post("/logout")
    async def logout(request: Request) -> Response:
        if not _same_origin(request, origin):
            return HTMLResponse("<p>Cross-site request refused</p>", status_code=403)
        request.session.clear()
        return HTMLResponse("<p>Logged out</p>", headers=login_status_headers(signed_in=False))

    return app


def _same_origin(request: Request, origin: str) -> bool:
    """Whether a browser sent ``request`` from this app's own pages.

    Otherwise another site could log visitors in to an account of its choosing (login
    CSRF), so their next EVT asserts that address.  Browsers send ``Sec-Fetch-Site``;
    older ones only ``Origin``.  A request with neither is refused.
    """
    site = request.headers.get("sec-fetch-site")
    if site is not None:
        return site == "same-origin"
    return request.headers.get("origin") == origin


async def _read_body(request: Request) -> bytes:
    """The body, but no more of it than the issuer accepts.

    The issuer refuses larger requests, from ``Content-Length`` when there is one, so
    there is no point reading more.
    """
    length = request.headers.get("content-length", "")
    if len(length) > 9 or (
        length.isascii() and length.isdigit() and int(length) > MAX_REQUEST_BODY
    ):
        return b""
    body = b""
    async for chunk in request.stream():
        body += chunk[: MAX_REQUEST_BODY + 1 - len(body)]
        if len(body) > MAX_REQUEST_BODY:
            break
    return body


def _response(result: IssuerResponse) -> Response:
    return Response(result.body, status_code=result.status, headers=result.headers)


def _from_environment() -> FastAPI:
    public_url = os.environ["EVP_PUBLIC_URL"].rstrip("/")
    with open(os.environ["EVP_SIGNING_KEY"]) as file:
        signer = SigningKey.from_jwk(json.load(file))
    issuer = Issuer(
        issuer=os.environ["EVP_ISSUER"],
        issuance_endpoint=public_url + ISSUANCE_PATH,
        jwks_uri=public_url + JWKS_PATH,
        signer=signer,
        email_domains=os.environ["EVP_EMAIL_DOMAINS"].split(","),
    )
    users = json.loads(os.environ.get("EVP_DEMO_USERS", "{}"))
    return create_app(issuer, users, session_secret=os.environ["SESSION_SECRET"])


app = _from_environment() if "EVP_ISSUER" in os.environ else FastAPI()
