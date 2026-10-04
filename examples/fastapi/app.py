"""Minimal FastAPI relying party.

Run from this directory::

    uv run uvicorn app:app --port 8000

then open http://localhost:8000 in a browser that supports the Email
Verification Protocol.  Tests swap the verifier for one wired to fakes via
``app.dependency_overrides`` (see ``tests/test_app.py``).
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from starlette.middleware.sessions import SessionMiddleware

from pyevp import AsyncVerifier, EVPError, InMemoryReplayGuard, SessionNonces, token_input

ORIGIN = os.environ.get("EVP_ORIGIN", "http://localhost:8000")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # SessionMiddleware keeps the session in a signed cookie, so taking the nonce
    # out of it does not stop an attacker from resending a captured token with the
    # old cookie.  The replay guard does.  Use a shared store (e.g. Redis) when
    # running more than one worker.
    verifier = AsyncVerifier.default(audience=ORIGIN, replay_guard=InMemoryReplayGuard())
    async with verifier:  # closes its HTTP client on shutdown
        app.state.verifier = verifier
        yield


app = FastAPI(lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=os.environ.get("SESSION_SECRET", "dev-only"))


def get_verifier(request: Request) -> AsyncVerifier:
    return request.app.state.verifier


@app.get("/", response_class=HTMLResponse)
async def form(request: Request) -> str:
    nonce = SessionNonces(request.session).issue()
    return f"""<!doctype html>
<form method="post" action="/signup">
  <input type="email" name="email" autocomplete="email" required>
  {token_input(nonce)}
  <button>Sign up</button>
</form>"""


@app.post("/signup")
async def signup(
    request: Request,
    verifier: Annotated[AsyncVerifier, Depends(get_verifier)],
    email: Annotated[str, Form()],
    evt: Annotated[str, Form()] = "",
) -> dict[str, object]:
    # landing:start
    try:
        # Takes the token's nonce from the session, whether or not it verifies.
        result = await verifier.verify_submission(
            evt, nonces=SessionNonces(request.session), email=email
        )
    except EVPError as exc:
        raise HTTPException(status_code=400, detail={"code": exc.code}) from exc
    if result is None:
        # No token: fall back to sending a confirmation email, as before EVP.
        return {"email": email, "verified": False}
    return {"email": result.email, "verified": True, "issuer": result.issuer}
    # landing:end
