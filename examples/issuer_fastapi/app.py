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
``web_identity_document(...)`` there yourself.  See ``pyevp.issuer.fedcm``.
"""

from __future__ import annotations

import hmac
import html
import json
import os
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.middleware.sessions import SessionMiddleware

from pyevp.issuer import (
    FEDCM_FETCH_DEST,
    IssuanceError,
    IssuanceErrorCode,
    IssuanceResponse,
    Issuer,
    SigningKey,
    accounts_document,
    web_identity_document,
)

ISSUANCE_PATH = "/email-verification/issuance"
JWKS_PATH = "/email-verification/jwks"
ACCOUNTS_PATH = "/fedcm/accounts"
LOGIN_PATH = "/login"
MAX_BODY = 16 * 1024
SESSION_USER = "user"


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

    @app.get("/.well-known/email-verification")
    async def metadata() -> JSONResponse:
        return JSONResponse(issuer.metadata_document())

    @app.get(JWKS_PATH)
    async def jwks() -> JSONResponse:
        return JSONResponse(issuer.jwks_document())

    @app.get("/.well-known/web-identity")
    async def web_identity() -> JSONResponse:
        base = issuer.issuer
        return JSONResponse(
            web_identity_document(
                accounts_endpoint=base + ACCOUNTS_PATH, login_url=base + LOGIN_PATH
            )
        )

    @app.get(ACCOUNTS_PATH)
    async def accounts(request: Request) -> JSONResponse:
        # Chrome checks that the user is signed in with the typed address before issuing.
        if request.headers.get("sec-fetch-dest") != FEDCM_FETCH_DEST:
            return JSONResponse({"error": "not a FedCM request"}, status_code=400)
        user = request.session.get(SESSION_USER)
        if user is None:
            return JSONResponse({"accounts": []}, status_code=401)
        return JSONResponse(accounts_document([user]))

    @app.post(ISSUANCE_PATH)
    async def issuance(request: Request) -> Response:
        # Put per-IP rate limiting in front of this endpoint (proxy or middleware).
        body = await request.body()
        # Raw pairs keep repeated header lines apart.
        headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in request.headers.raw]
        try:
            if len(body) > MAX_BODY:
                raise IssuanceError(IssuanceErrorCode.INVALID_REQUEST, "body too large")
            parsed = await issuer.aparse_request(method=request.method, headers=headers, body=body)
            # One check for every way this can fail, so responses do not reveal accounts.
            if request.session.get(SESSION_USER) != parsed.email:
                raise IssuanceError.authentication_required()
            result = issuer.success_response(issuer.issue(parsed))
        except IssuanceError as exc:
            result = exc.to_response()
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
            f"<p>Logged in as {html.escape(email)}</p>", headers={"Set-Login": "logged-in"}
        )

    @app.post("/logout")
    async def logout(request: Request) -> Response:
        if not _same_origin(request, origin):
            return HTMLResponse("<p>Cross-site request refused</p>", status_code=403)
        request.session.clear()
        return HTMLResponse("<p>Logged out</p>", headers={"Set-Login": "logged-out"})

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


def _response(result: IssuanceResponse) -> Response:
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
