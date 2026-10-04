"""fastapi-users registration that trusts EVP tokens.

A valid token creates the user with ``is_verified=True``; otherwise the user is
created unverified and fastapi-users' usual verification email flow applies.

Run from this directory::

    uv run uvicorn app:app --port 8000
"""

from __future__ import annotations

import logging
import os
import secrets
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi_users import BaseUserManager, FastAPIUsers, UUIDIDMixin, exceptions, schemas
from fastapi_users.authentication import AuthenticationBackend, CookieTransport, JWTStrategy
from fastapi_users_db_sqlalchemy import SQLAlchemyBaseUserTableUUID, SQLAlchemyUserDatabase
from pydantic import EmailStr
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from starlette.middleware.sessions import SessionMiddleware

from pyevp import AsyncVerifier, EVPError, InMemoryReplayGuard, SessionNonces, token_input

ORIGIN = os.environ.get("EVP_ORIGIN", "http://localhost:8000")
# A random development secret: sessions and logins do not survive restarts.
SECRET = os.environ.get("SECRET") or secrets.token_urlsafe(32)
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///./fastapi_users.db")

logger = logging.getLogger(__name__)


# --- fastapi-users boilerplate ---------------------------------------------------


class Base(DeclarativeBase):
    pass


class User(SQLAlchemyBaseUserTableUUID, Base):
    pass


class UserRead(schemas.BaseUser[uuid.UUID]):
    pass


class UserCreate(schemas.BaseUserCreate):
    pass


engine = create_async_engine(DATABASE_URL)
session_maker = async_sessionmaker(engine, expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    async with session_maker() as session:
        yield session


async def get_user_db(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> AsyncIterator[SQLAlchemyUserDatabase[User, uuid.UUID]]:
    yield SQLAlchemyUserDatabase(session, User)


class UserManager(UUIDIDMixin, BaseUserManager[User, uuid.UUID]):
    reset_password_token_secret = SECRET
    verification_token_secret = SECRET

    async def on_after_register(self, user: User, request: Request | None = None) -> None:
        if not user.is_verified:
            # Without an EVP token, fall back to the usual flow:
            # await self.request_verify(user, request) and email the token.
            logger.info("would send a verification email to %s", user.email)


async def get_user_manager(
    user_db: Annotated[SQLAlchemyUserDatabase[User, uuid.UUID], Depends(get_user_db)],
) -> AsyncIterator[UserManager]:
    yield UserManager(user_db)


auth_backend = AuthenticationBackend(
    name="cookie",
    transport=CookieTransport(cookie_secure=ORIGIN.startswith("https://")),
    get_strategy=lambda: JWTStrategy(secret=SECRET, lifetime_seconds=3600),
)
fastapi_users = FastAPIUsers[User, uuid.UUID](get_user_manager, [auth_backend])
current_verified_user = fastapi_users.current_user(active=True, verified=True)


# --- application -----------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    # Signed-cookie sessions cannot make the nonce single-use on their own.
    verifier = AsyncVerifier.default(audience=ORIGIN, replay_guard=InMemoryReplayGuard())
    async with verifier:  # closes its HTTP client on shutdown
        app.state.verifier = verifier
        yield


app = FastAPI(lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=SECRET)
app.include_router(fastapi_users.get_auth_router(auth_backend), prefix="/auth")


def get_verifier(request: Request) -> AsyncVerifier:
    return request.app.state.verifier


@app.get("/register", response_class=HTMLResponse)
async def register_form(request: Request) -> str:
    nonce = SessionNonces(request.session).issue()
    return f"""<!doctype html>
<form method="post" action="/register">
  <input type="email" name="email" autocomplete="email" required>
  <input type="password" name="password" autocomplete="new-password" required>
  {token_input(nonce)}
  <button>Register</button>
</form>"""


@app.post("/register", response_model=UserRead)
async def register(
    request: Request,
    *,
    verifier: Annotated[AsyncVerifier, Depends(get_verifier)],
    user_manager: Annotated[UserManager, Depends(get_user_manager)],
    email: Annotated[EmailStr, Form()],  # an invalid address is a 422, not a 500
    password: Annotated[str, Form()],
    evt: Annotated[str, Form()] = "",
) -> User:
    verified = False
    try:
        result = await verifier.verify_submission(
            evt, nonces=SessionNonces(request.session), email=email
        )
        verified = result is not None  # None: no token, so is_verified stays false
    except EVPError as exc:
        logger.info("EVP token rejected: %s", exc.code)

    # Built server-side: safe=False keeps is_verified, and nothing else privileged is set.
    user_create = UserCreate(email=email, password=password, is_verified=verified)
    try:
        return await user_manager.create(user_create, safe=False, request=request)
    except exceptions.UserAlreadyExists:
        raise HTTPException(400, "REGISTER_USER_ALREADY_EXISTS") from None
    except exceptions.InvalidPasswordException as exc:
        raise HTTPException(400, exc.reason) from None


@app.get("/me", response_model=UserRead)
async def me(user: Annotated[User, Depends(current_verified_user)]) -> User:
    return user
