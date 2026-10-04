"""Passwordless login: an EVP token proves the address, AuthX issues the session.

There is no password and no email round-trip: the browser's verified address
*is* the login.  That makes replay protection essential, so the verifier gets a
replay guard (use a shared store such as Redis with several workers).

Run from this directory::

    uv run uvicorn app:app --port 8000
"""

from __future__ import annotations

import os
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Annotated

from authx import AuthX, AuthXConfig, TokenPayload
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

from pyevp import AsyncVerifier, EVPError, InMemoryReplayGuard, SessionNonces, token_input

ORIGIN = os.environ.get("EVP_ORIGIN", "http://localhost:8000")
# A random development secret: sessions and logins do not survive restarts.
SECRET = os.environ.get("SECRET") or secrets.token_urlsafe(32)

auth = AuthX(
    config=AuthXConfig(
        JWT_SECRET_KEY=SECRET,
        JWT_TOKEN_LOCATION=["cookies"],
        JWT_COOKIE_SECURE=ORIGIN.startswith("https://"),
        JWT_ACCESS_TOKEN_EXPIRES=timedelta(hours=1),
    )
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    verifier = AsyncVerifier.default(audience=ORIGIN, replay_guard=InMemoryReplayGuard())
    async with verifier:  # closes its HTTP client on shutdown
        app.state.verifier = verifier
        yield


app = FastAPI(lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=SECRET)
auth.handle_errors(app)


def get_verifier(request: Request) -> AsyncVerifier:
    return request.app.state.verifier


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request) -> str:
    nonce = SessionNonces(request.session).issue()
    return f"""<!doctype html>
<form method="post" action="/login">
  <input type="email" name="email" autocomplete="email" required>
  {token_input(nonce)}
  <button>Sign in</button>
</form>"""


@app.post("/login")
async def login(
    request: Request,
    verifier: Annotated[AsyncVerifier, Depends(get_verifier)],
    email: Annotated[str, Form()],
    evt: Annotated[str, Form()] = "",
) -> RedirectResponse:
    try:
        result = await verifier.verify_submission(
            evt, nonces=SessionNonces(request.session), email=email
        )
    except EVPError as exc:
        raise HTTPException(400, {"code": exc.code}) from exc
    if result is None:
        # A real app would offer another sign-in method here (magic link, passkey, ...).
        raise HTTPException(400, {"code": "evp_unavailable"})

    response = RedirectResponse("/me", status_code=303)
    auth.set_access_cookies(auth.create_access_token(uid=result.email), response)
    return response


@app.get("/me")
async def me(payload: Annotated[TokenPayload, Depends(auth.access_token_required)]) -> dict:
    return {"email": payload.sub}
