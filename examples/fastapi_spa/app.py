"""FastAPI JSON API for a single-page app, without server sessions.

The frontend runs on its own origin (``EVP_ORIGIN``) and calls this API with
credentials.  There is no session to hold the nonce, so ``GET /api/evp/nonce``
puts it in an HttpOnly cookie.  Password recovery skips the email when the
browser presents a token for the address (see the "Password recovery" guide).

Run from this directory::

    uv run uvicorn app:app --port 8000

Users live in memory and emails go to ``OUTBOX``, to keep the example short.
Tests swap the verifier via ``app.dependency_overrides`` (see ``tests/test_app.py``).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Response,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from pyevp import AsyncVerifier, EVPError, InMemoryReplayGuard, generate_nonce, nonces_equal

logger = logging.getLogger(__name__)

# The origin of the frontend, where the form is.  It is the audience of the
# tokens, not this API's own origin.
ORIGIN = os.environ.get("EVP_ORIGIN", "http://localhost:5173")
RESET_SECRET = os.environ.get("RESET_SECRET", "dev-only").encode()
NONCE_MAX_AGE = 600
RESET_MAX_AGE = 900
GENERIC_REPLY = "If that address is registered, we sent a password recovery link"


@dataclass
class User:
    email: str
    active: bool = True
    password_hash: bytes = b""


USERS: dict[str, User] = {}
OUTBOX: list[tuple[str, str]] = []  # (address, reset token)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # The nonce cookie is client-side state: a captured token could be sent again
    # with the old cookie.  The replay guard refuses the second use.  Use a shared
    # store (e.g. Redis) when running more than one worker.
    verifier = AsyncVerifier.default(audience=ORIGIN, replay_guard=InMemoryReplayGuard())
    async with verifier:  # closes its HTTP client on shutdown
        app.state.verifier = verifier
        yield


app = FastAPI(lifespan=lifespan)
# The frontend sends requests with credentials, so that the nonce cookie travels.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
api = APIRouter(prefix="/api")


def get_verifier(request: Request) -> AsyncVerifier:
    return request.app.state.verifier


Verifier = Annotated[AsyncVerifier, Depends(get_verifier)]


class Nonce(BaseModel):
    nonce: str


class RecoveryRequest(BaseModel):
    email: str
    evt: str = ""


class RecoveryReply(BaseModel):
    message: str
    reset_token: str | None = None


class ResetRequest(BaseModel):
    token: str
    new_password: str


# nonce:start
class CookieNonces:
    """Keeps the nonce in an HttpOnly cookie, for an API without server sessions.

    The cookie holds one nonce, so the form opened last wins.
    """

    def __init__(self, request: Request, response: Response) -> None:
        self.request, self.response = request, response
        # Over HTTPS, the __Host- prefix stops other hosts on the same site, and plain
        # HTTP, from planting a nonce of their choosing.
        self.secure = ORIGIN.startswith("https://")
        self.name = "__Host-evp_nonce" if self.secure else "evp_nonce"
        self._issued: str | None = None
        self._taken = False

    def issue(self) -> str:
        if self._issued is None:
            self._issued = generate_nonce()
            self.response.set_cookie(
                self.name, self._issued, max_age=NONCE_MAX_AGE, **self._attributes()
            )
        return self._issued

    def take(self, nonce: str) -> bool:
        stored = self.request.cookies.get(self.name)
        if self._taken or stored is None or not nonces_equal(stored, nonce):
            return False
        # The request still carries the cookie, so remember that it is used up.
        self._taken, self._issued = True, None
        self.response.delete_cookie(self.name, **self._attributes())
        return True

    def _attributes(self) -> dict[str, Any]:
        return {"path": "/", "httponly": True, "samesite": "strict", "secure": self.secure}


Nonces = Annotated[CookieNonces, Depends(CookieNonces)]


@api.get("/evp/nonce")
async def evp_nonce(nonces: Nonces) -> Nonce:
    return Nonce(nonce=nonces.issue())


async def verify_evt(verifier: AsyncVerifier, nonces: Nonces, *, token: str, email: str) -> bool:
    """Whether ``token`` proves that this browser controls ``email``.

    Without a token, the cookie stays for the next submission.
    """
    try:
        return await verifier.verify_submission(token, nonces=nonces, email=email) is not None
    except EVPError as exc:
        logger.info("EVP token rejected: %s", exc.code)
        return False
    # nonce:end


# recovery:start
@api.post("/password-recovery", response_model_exclude_none=True)
async def password_recovery(
    body: RecoveryRequest,
    verifier: Verifier,
    nonces: Nonces,
    background: BackgroundTasks,
) -> RecoveryReply:
    # Verify before looking the user up, so that the reply, its cookies and its
    # timing do not depend on whether the address is registered.
    verified = await verify_evt(verifier, nonces, token=body.evt, email=body.email)
    user = USERS.get(body.email.lower())
    if user is None or not user.active:
        return RecoveryReply(message=GENERIC_REPLY)
    if verified:
        # The browser proved control of the address: hand over the token that
        # the recovery email would carry.
        return RecoveryReply(message="Address verified", reset_token=make_reset_token(user.email))
    # In the background, so that sending does not make this reply slower.
    background.add_task(send_recovery_email, user.email, make_reset_token(user.email))
    return RecoveryReply(message=GENERIC_REPLY)
    # recovery:end


@api.post("/reset-password")
async def reset_password(body: ResetRequest) -> dict[str, str]:
    email = check_reset_token(body.token)
    user = USERS.get(email) if email else None
    if user is None or not user.active:
        raise HTTPException(status_code=400, detail="Invalid token")
    user.password_hash = hash_password(body.new_password)
    return {"message": "Password updated"}


app.include_router(api)


def send_recovery_email(address: str, token: str) -> None:
    OUTBOX.append((address, token))


def make_reset_token(email: str) -> str:
    claims = {"email": email, "exp": int(time.time()) + RESET_MAX_AGE}
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode()
    return f"{payload}.{_sign(payload)}"


def check_reset_token(token: str) -> str | None:
    payload, _, signature = token.rpartition(".")
    # As bytes: compare_digest refuses non-ASCII str, and the token is user input.
    if not hmac.compare_digest(signature.encode(), _sign(payload).encode()):
        return None
    claims = json.loads(base64.urlsafe_b64decode(payload))
    return claims["email"] if claims["exp"] > time.time() else None


def _sign(payload: str) -> str:
    return hmac.new(RESET_SECRET, payload.encode(), hashlib.sha256).hexdigest()


def hash_password(password: str) -> bytes:
    salt = os.urandom(16)
    return salt + hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
