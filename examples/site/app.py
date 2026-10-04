"""pyevp.dev landing page, relying party and mock provider in one ASGI app.

The issuer allowlist matters for a public deployment: discovery fetches HTTPS URLs
chosen by whoever controls the email domain in the token, before any issuer
signature is checked. The verifier's ``allowed_issuers`` refuses other issuers
before any lookup, so the demo only ever contacts issuers listed here.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import textwrap
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from time import perf_counter
from typing import Annotated, TypedDict

from fastapi import Depends, FastAPI, Form, Request
from jinja2 import Environment, FileSystemLoader, Template, select_autoescape
from markupsafe import Markup
from pygments import highlight
from pygments.formatters.html import HtmlFormatter
from pygments.lexers.python import PythonLexer
from pygments.styles import get_style_by_name
from pygments.util import ClassNotFound
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from starlette.routing import Host, Route
from starlette.types import Receive, Scope, Send
from verification_trace import (
    CURRENT_TRACE,
    RecordingClock,
    RecordingFetcher,
    RecordingResolver,
    Trace,
    TrackingCache,
)

from pyevp import (
    AsyncVerifier,
    Clock,
    EVPError,
    InMemoryReplayGuard,
    LoggingObserver,
    SessionNonces,
)
from pyevp.adapters import httpx as httpx_adapter
from pyevp.adapters.dnspython import AsyncDnsPythonResolver
from pyevp.cache import InMemoryCache
from pyevp.issuer import (
    MAX_REQUEST_BODY,
    Issuer,
    IssuerResponse,
    SigningKey,
    login_status_headers,
    web_identity_response,
)
from pyevp.ports import system_clock
from pyevp.token import parse_token

ISSUANCE_PATH = "/email-verification/issuance"
JWKS_PATH = "/email-verification/jwks"
ACCOUNTS_PATH = "/fedcm/accounts"
LOGIN_PATH = "/login"
# The issuer answers every method itself; HEAD and OPTIONS are left to the framework.
ISSUANCE_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]
SESSION_USER = "email"
HERE = Path(__file__).resolve().parent
EXAMPLES_DIR = HERE.parent
STYLESHEET = HERE / "static" / "site.css"
EXAMPLES = (
    ("fastapi", "FastAPI", "fastapi/app.py"),
    ("flask", "Flask", "flask/app.py"),
    ("django", "Django", "django/views.py"),
)
NO_STORE = {"Cache-Control": "no-store"}


class TraceDisplay(TypedDict):
    trace_steps: list[dict[str, object]]
    decoded: dict[str, str] | None
    elapsed_ms: float


def get_verifier(request: Request) -> AsyncVerifier:
    return request.app.state.verifier


class _TracedNonces(SessionNonces):
    """Remembers the nonce a submission took, for the trace to show what it expected."""

    taken = ""

    def take(self, nonce: str) -> bool:
        if not super().take(nonce):
            return False
        self.taken = nonce
        return True


def extract_example(path: Path) -> str:
    """Require one ordered marker pair, then remove markers and indentation."""
    lines = path.read_text(encoding="utf-8").splitlines()
    starts = [i for i, line in enumerate(lines) if line.strip() == "# landing:start"]
    ends = [i for i, line in enumerate(lines) if line.strip() == "# landing:end"]
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise ValueError(f"{path} must contain exactly one ordered landing marker pair")
    return textwrap.dedent("\n".join(lines[starts[0] + 1 : ends[0]])) + "\n"


def _formatter(style: str, fallback: str) -> HtmlFormatter:
    try:
        selected = get_style_by_name(style)
    except ClassNotFound:
        selected = get_style_by_name(fallback)
    return HtmlFormatter(style=selected, cssclass="highlight")


def _render_pages(
    *,
    examples_dir: Path,
    stylesheet_path: Path,
    dev: bool,
    mail_host: str,
    allowed_issuers: Iterable[str],
    site_host: str,
    email: str,
) -> tuple[Template, dict[str, object], dict[str, str]]:
    try:
        stylesheet = stylesheet_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        if not dev:
            raise RuntimeError("static/site.css is required unless EVP_DEV=1") from None
        logging.getLogger(__name__).warning("Missing static/site.css; using an empty stylesheet")
        stylesheet = ""
    light = _formatter("a11y-light", "default")
    dark = _formatter("a11y-dark", "native")
    pygments_css = (
        light.get_style_defs(".highlight")
        + "\n@media (prefers-color-scheme: dark) {\n"
        + dark.get_style_defs(".highlight")
        + "\n}"
    )
    templates = Environment(
        loader=FileSystemLoader(HERE / "templates"), autoescape=select_autoescape(["html"])
    )
    context = {
        "stylesheet": Markup(stylesheet),
        "pygments_css": Markup(pygments_css),
        "provider_url": f"https://{mail_host}/",
        "allowed_issuers": ", ".join(sorted(allowed_issuers)),
        "site_url": f"https://{site_host}",
        "email": email,
    }
    examples = [
        {
            "id": ident,
            "label": label,
            "code": Markup(highlight(extract_example(examples_dir / path), PythonLexer(), light)),
        }
        for ident, label, path in EXAMPLES
    ]
    context["examples"] = examples
    pages = {}
    mail = templates.get_template("mail.html")
    for name, signed_in, status in (
        ("signed-out", False, None),
        ("signed-in", True, None),
        ("logged-in", True, "logged-in"),
        ("logged-out", False, "logged-out"),
    ):
        pages[name] = mail.render(signed_in=signed_in, login_status=status, **context)
    pages["landing"] = templates.get_template("landing.html").render(**context)
    return templates.get_template("demo.html"), context, pages


async def _security_headers(request: Request, call_next: RequestResponseEndpoint) -> Response:
    response = await call_next(request)
    # No header-delivered CSP: browsers hide nonce attributes, including EVP's.
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


class SiteSessionMiddleware(SessionMiddleware):
    """Only the interactive demo routes use the relying-party session."""

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"] not in {"/demo", "/verify"}:
            await self.app(scope, receive, send)
        else:
            await super().__call__(scope, receive, send)


def _site_app(
    issuer: Issuer, *, session_secret: str, site_host: str, origin_trial_token: str | None
) -> FastAPI:
    site = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    site.add_middleware(
        SiteSessionMiddleware,
        secret_key=session_secret,
        session_cookie="pyevp_site_session",
        same_site="lax",
        https_only=True,
    )

    def demo_response(*, status_code: int = 200, **context: object) -> HTMLResponse:
        return HTMLResponse(
            site.state.demo_template.render(
                **site.state.page_context, origin_trial_token=origin_trial_token, **context
            ),
            status_code=status_code,
            headers=NO_STORE,
        )

    @site.get("/")
    async def landing() -> HTMLResponse:
        return HTMLResponse(site.state.landing_page)

    @site.get("/demo")
    async def demo(request: Request) -> HTMLResponse:
        return demo_response(nonce=SessionNonces(request.session).issue())

    @site.post("/verify")
    async def verify(
        request: Request,
        verifier: Annotated[AsyncVerifier, Depends(get_verifier)],
        email: Annotated[str, Form()],
        evt: Annotated[str, Form()] = "",
    ) -> HTMLResponse:
        if not evt:
            # The form's nonce stays in the session for another try.
            return demo_response(result_kind="no-token")
        nonces = _TracedNonces(request.session)
        trace = Trace()
        started = perf_counter()
        now = site.state.clock()
        parsed = None
        # The verifier supplies the authoritative error below.
        with suppress(EVPError):
            parsed = parse_token(evt, allow_disclosures=verifier.profile.allow_disclosures)
        decoded = (
            {
                "EVT": json.dumps(parsed.evt.claims, indent=2),
                "KB-JWT": json.dumps(parsed.kb.claims, indent=2),
            }
            if parsed is not None
            else None
        )
        error = None
        marker = CURRENT_TRACE.set(trace)
        try:
            # The token's nonce is used up, whether or not it verifies.
            result = await verifier.verify_submission(evt, nonces=nonces, email=email)
        except EVPError as exc:
            error = exc
        finally:
            CURRENT_TRACE.reset(marker)
        display: TraceDisplay = {
            "trace_steps": trace.steps(
                error,
                parsed=parsed,
                now=trace.checked_at or now,
                profile=verifier.profile,
                audience=verifier.audience,
                nonce=nonces.taken,
                email=email,
            ),
            "decoded": decoded,
            "elapsed_ms": (perf_counter() - started) * 1000,
        }
        if error is not None:
            return demo_response(
                result_kind="failed",
                code=error.code,
                detail=error.args[0],
                status_code=400,
                **display,
            )
        assert result is not None  # evt is not empty
        rows = {
            "Email": result.email,
            "Issuer": result.issuer,
            "Issued at": result.issued_at.isoformat(),
            "Expires at": result.expires_at.isoformat() if result.expires_at else "-",
            "Private relay address": "yes" if result.is_private_email else "no",
        }
        return demo_response(result_kind="verified", rows=rows, **display)

    @site.get("/robots.txt")
    async def robots() -> PlainTextResponse:
        return PlainTextResponse(
            f"User-agent: *\nAllow: /\n\nSitemap: https://{site_host}/sitemap.xml\n"
        )

    @site.get("/sitemap.xml")
    async def sitemap() -> Response:
        urls = "".join(
            f"  <url><loc>https://{site_host}{path}</loc></url>\n" for path in ("/", "/demo")
        )
        return Response(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
            f"{urls}</urlset>\n",
            media_type="application/xml",
        )

    @site.get("/.well-known/web-identity")
    async def web_identity() -> Response:
        return _response(
            web_identity_response(
                accounts_endpoint=issuer.issuer + ACCOUNTS_PATH,
                login_url=issuer.issuer + LOGIN_PATH,
            )
        )

    return site


def _user_emails(request: Request) -> list[str]:
    email = request.session.get(SESSION_USER)
    return [email] if email else []


async def _read_body(request: Request) -> bytes:
    """The body, but no more of it than the issuer accepts."""
    length = request.headers.get("content-length", "")
    if len(length) > 9 or (
        length.isascii() and length.isdigit() and int(length) > MAX_REQUEST_BODY
    ):
        return b""  # refused from Content-Length
    body = b""
    async for chunk in request.stream():
        body += chunk[: MAX_REQUEST_BODY + 1 - len(body)]
        if len(body) > MAX_REQUEST_BODY:
            break
    return body


def _response(result: IssuerResponse) -> Response:
    return Response(result.body, status_code=result.status, headers=result.headers)


async def _issuance(request: Request, issuer: Issuer) -> Response:
    result = await issuer.aissuance_response(
        method=request.method,
        headers=request.headers.items(),
        body=await _read_body(request) if request.method == "POST" else b"",
        user_emails=_user_emails(request),
    )
    if result.status == 200:
        request.session["issued"] = request.session.get("issued", 0) + 1
    return _response(result)


def _mail_app(
    issuer: Issuer,
    pages: dict[str, str],
    *,
    email: str,
    session_secret: str,
    build_sha: str,
) -> FastAPI:
    mail = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    mail.add_middleware(
        SessionMiddleware,
        secret_key=session_secret,
        session_cookie="pyevp_mail_session",
        same_site="none",
        https_only=True,
        max_age=3600,
    )

    @mail.get("/")
    @mail.get(LOGIN_PATH)
    async def provider(request: Request) -> HTMLResponse:
        name = "signed-in" if request.session.get(SESSION_USER) else "signed-out"
        return HTMLResponse(pages[name], headers=NO_STORE)

    @mail.post(LOGIN_PATH)
    async def login(request: Request) -> Response:
        if request.headers.get("sec-fetch-site", "same-origin") != "same-origin":
            return JSONResponse({"error": "forbidden"}, status_code=403, headers=NO_STORE)
        request.session.clear()
        request.session.update({SESSION_USER: email, "issued": 0})
        headers = {**NO_STORE, **login_status_headers(signed_in=True)}
        return HTMLResponse(pages["logged-in"], headers=headers)

    @mail.post("/logout")
    async def logout(request: Request) -> Response:
        if request.headers.get("sec-fetch-site", "same-origin") != "same-origin":
            return JSONResponse({"error": "forbidden"}, status_code=403, headers=NO_STORE)
        request.session.clear()
        headers = {**NO_STORE, **login_status_headers(signed_in=False)}
        return HTMLResponse(pages["logged-out"], headers=headers)

    @mail.get("/robots.txt")
    async def robots() -> PlainTextResponse:
        return PlainTextResponse("User-agent: *\nDisallow: /\n")

    @mail.get("/me")
    async def me(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "email": request.session.get(SESSION_USER),
                "issued": request.session.get("issued", 0),
                "build_sha": build_sha,
            },
            headers=NO_STORE,
        )

    @mail.get("/.well-known/email-verification")
    async def metadata() -> Response:
        return _response(issuer.metadata_response())

    @mail.get(JWKS_PATH)
    async def jwks() -> Response:
        return _response(issuer.jwks_response())

    @mail.get(ACCOUNTS_PATH)
    async def accounts(request: Request) -> Response:
        result = issuer.accounts_response(
            headers=request.headers.items(), user_emails=_user_emails(request)
        )
        return _response(result)

    @mail.api_route(ISSUANCE_PATH, methods=ISSUANCE_METHODS)
    async def issuance(request: Request) -> Response:
        return await _issuance(request, issuer)

    return mail


def create_app(
    *,
    signer: SigningKey | None = None,
    session_secret: str | None = None,
    site_host: str = "pyevp.dev",
    mail_host: str = "mail.pyevp.dev",
    email_domain: str = "pyevp.dev",
    legacy_demo_host: str = "demo.pyevp.dev",
    allowed_issuers: Iterable[str] | None = None,
    build_sha: str = "unknown",
    examples_dir: Path = EXAMPLES_DIR,
    stylesheet_path: Path = STYLESHEET,
    dev: bool = False,
    clock: Clock = system_clock,
    origin_trial_token: str | None = None,
) -> Starlette:
    """Explicit settings; only ``_from_environment`` reads environment variables."""
    if signer is None:
        if not dev:
            raise RuntimeError("EVP_SIGNING_JWK is required unless EVP_DEV=1")
        signer = SigningKey.generate(kid="dev")
    if not session_secret:
        if not dev:
            raise RuntimeError("SESSION_SECRET is required unless EVP_DEV=1")
        session_secret = secrets.token_urlsafe(32)
    base = f"https://{mail_host}"
    issuer = Issuer(
        issuer=base,
        issuance_endpoint=base + ISSUANCE_PATH,
        jwks_uri=base + JWKS_PATH,
        signer=signer,
        email_domains=[email_domain],
        clock=clock,
    )
    email = f"demo@{email_domain}"
    pages: dict[str, str] = {}
    allowed = (
        tuple(allowed_issuers)
        if allowed_issuers is not None
        else ("https://accounts.google.com", base)
    )
    site = _site_app(
        issuer,
        session_secret=session_secret,
        site_host=site_host,
        origin_trial_token=origin_trial_token or None,
    )

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        logging.basicConfig(level=logging.INFO)
        # The verifier closes only what it creates; this fetcher is ours to close.
        async with httpx_adapter.AsyncHttpxFetcher() as fetcher:
            # One process only: the replay guard lives in memory.
            verifier = site.state.verifier = AsyncVerifier.default(
                audience=f"https://{site_host}",
                resolver=RecordingResolver(AsyncDnsPythonResolver()),
                fetcher=RecordingFetcher(fetcher),
                allowed_issuers=allowed,
                cache=TrackingCache(InMemoryCache(clock=clock)),
                replay_guard=InMemoryReplayGuard(clock=clock),
                observer=LoggingObserver(),
                clock=RecordingClock(clock),
            )
            template, context, mail_pages = _render_pages(
                examples_dir=examples_dir,
                stylesheet_path=stylesheet_path,
                dev=dev,
                mail_host=mail_host,
                allowed_issuers=verifier.allowed_issuers or (),
                site_host=site_host,
                email=email,
            )
            site.state.demo_template = template
            site.state.page_context = context
            site.state.landing_page = mail_pages.pop("landing")
            site.state.clock = clock
            pages.update(mail_pages)
            yield

    async def noindex_mail_host(request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        # The same host matching as starlette.routing.Host.
        if request.headers.get("host", "").split(":")[0] == mail_host:
            response.headers["X-Robots-Tag"] = "noindex"
        return response

    async def healthz(request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    async def legacy_redirect(scope: Scope, receive: Receive, send: Send) -> None:
        await RedirectResponse(f"https://{site_host}/demo", status_code=301)(scope, receive, send)

    app = Starlette(
        routes=[
            Route("/healthz", healthz),
            Host(site_host, site),
            Host(
                mail_host,
                _mail_app(
                    issuer, pages, email=email, session_secret=session_secret, build_sha=build_sha
                ),
            ),
            Host(legacy_demo_host, legacy_redirect),
        ],
        lifespan=lifespan,
        middleware=[
            Middleware(BaseHTTPMiddleware, dispatch=_security_headers),
            Middleware(BaseHTTPMiddleware, dispatch=noindex_mail_host),
        ],
    )
    app.state.issuer = issuer
    app.state.site = site
    return app


def _from_environment() -> Starlette:
    jwk = os.environ.get("EVP_SIGNING_JWK")
    return create_app(
        signer=SigningKey.from_jwk(json.loads(jwk)) if jwk else None,
        session_secret=os.environ.get("SESSION_SECRET"),
        site_host=os.environ.get("EVP_SITE_HOST", "pyevp.dev"),
        mail_host=os.environ.get("EVP_MAIL_HOST", "mail.pyevp.dev"),
        email_domain=os.environ.get("EVP_EMAIL_DOMAIN", "pyevp.dev"),
        legacy_demo_host=os.environ.get("EVP_LEGACY_DEMO_HOST", "demo.pyevp.dev"),
        allowed_issuers=(
            os.environ["EVP_ALLOWED_ISSUERS"].split()
            if "EVP_ALLOWED_ISSUERS" in os.environ
            else None
        ),
        build_sha=os.environ.get("BUILD_SHA", "unknown"),
        examples_dir=Path(os.environ.get("EVP_EXAMPLES_DIR", EXAMPLES_DIR)),
        stylesheet_path=STYLESHEET,
        dev=os.environ.get("EVP_DEV") == "1",
        origin_trial_token=os.environ.get("EVP_ORIGIN_TRIAL_TOKEN") or None,
    )


app = _from_environment()
