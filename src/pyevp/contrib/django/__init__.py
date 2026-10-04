"""Django integration (``pip install pyevp[django]``).

Add ``"pyevp.contrib.django"`` to ``INSTALLED_APPS`` and run ``migrate``.

- ``{% load pyevp %}`` and ``{% evp_token_input %}`` render the hidden token input, and
  :func:`verify_request` / :func:`averify_request` verify what the form submitted.
- :class:`EVPCache` / :class:`AsyncEVPCache` share issuer metadata and key
  sets between workers through Django's cache framework.
- :class:`EVPReplayGuard` / :class:`AsyncEVPReplayGuard` remember accepted
  tokens in a database table.

::

    from pyevp import EVPError, Verifier
    from pyevp.contrib.django import EVPCache, EVPReplayGuard, verify_request

    verifier = Verifier.default(
        audience=settings.EVP_ORIGIN, cache=EVPCache(), replay_guard=EVPReplayGuard()
    )

    # In the view that handles the form:
    try:
        verified = verify_request(request, verifier, email=form.cleaned_data["email"])
    except EVPError:
        verified = None  # fall back to a confirmation email

Caches and databases are looked up on every call, so these can be created at
import time, before Django's settings are configured.

For running an issuer, see :mod:`pyevp.contrib.django.issuer`.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from asgiref.sync import sync_to_async
from django.conf import settings
from django.core.cache import caches
from django.db import IntegrityError, transaction
from django.http import HttpRequest

from pyevp.cache import CacheEntry
from pyevp.nonce import generate_nonce
from pyevp.ports import Clock, system_clock
from pyevp.types import VerifiedEmail
from pyevp.verifier import AsyncVerifier, Verifier

if TYPE_CHECKING:
    from django.contrib.sessions.backends.base import SessionBase

__all__ = [
    "AsyncEVPCache",
    "AsyncEVPReplayGuard",
    "EVPCache",
    "EVPReplayGuard",
    "aget_nonce",
    "averify_request",
    "get_nonce",
    "verify_request",
]

_SESSION_KEY = "evp_nonce"
# The nonce handed out during the current request, so that every form on a page gets it.
_REQUEST_KEY = "_pyevp_nonce"


def get_nonce(request: HttpRequest) -> str:
    """Return the nonce for the forms on this page, keeping it in the session.

    The session holds one nonce, so all forms rendered in a request share it: the
    first call creates it and later calls return the same value.  Opening the
    page in another tab replaces it, and the older tab's forms then fall back to
    your usual flow.  ``{% evp_token_input %}`` calls this for you.

    It replaces the nonce in the session, so in a view that handles a submission,
    call :func:`verify_request` before rendering a form again.

    Every call writes the session, so render the token input only on pages that
    have a form: anywhere else it gives each visitor a session for nothing.
    """
    nonce = request.__dict__.get(_REQUEST_KEY)
    if nonce is None:
        nonce = generate_nonce()
        _session(request)[_SESSION_KEY] = nonce
        request.__dict__[_REQUEST_KEY] = nonce
    return nonce


async def aget_nonce(request: HttpRequest) -> str:
    """:func:`get_nonce` for async views.

    Django refuses session access from async code, including from a template
    tag.  Call this before rendering; ``{% evp_token_input %}`` then reuses the
    nonce without touching the session.
    """
    return await sync_to_async(get_nonce, thread_sensitive=True)(request)


def verify_request(
    request: HttpRequest,
    verifier: Verifier,
    *,
    email: str | None,
    field: str = "evt",
    audience: str | None = None,
) -> VerifiedEmail | None:
    """Verify the token that a form submitted, if it carried one.

    Returns ``None`` when the ``field`` is empty: the browser does not support
    EVP, or the email provider does not issue tokens.  The nonce then stays in
    the session, so a form that is not rendered again (one sent with ``fetch()``)
    can still be verified on the next submission.

    Otherwise the nonce is consumed and the token checked with
    :meth:`pyevp.Verifier.verify`, which raises :class:`~pyevp.EVPError` on
    failure.  If the session has no nonce, for example because it expired, that
    is ``nonce_mismatch``.

    :param email: the address the user submitted, as for :meth:`~pyevp.Verifier.verify`.
    :param field: the name of the hidden input (``{% evp_token_input field=... %}``).
    """
    taken = _take_nonce(request, field)
    if taken is None:
        return None
    token, nonce = taken
    return verifier.verify(token, nonce=nonce, email=email, audience=audience)


async def averify_request(
    request: HttpRequest,
    verifier: AsyncVerifier,
    *,
    email: str | None,
    field: str = "evt",
    audience: str | None = None,
) -> VerifiedEmail | None:
    """:func:`verify_request` for async views and :class:`~pyevp.AsyncVerifier`."""
    taken = await sync_to_async(_take_nonce, thread_sensitive=True)(request, field)
    if taken is None:
        return None
    token, nonce = taken
    return await verifier.verify(token, nonce=nonce, email=email, audience=audience)


def _take_nonce(request: HttpRequest, field: str) -> tuple[str, str] | None:
    token = request.POST.get(field, "")
    if not token:
        return None
    # The nonce is consumed: a form rendered later in this request needs a new one.
    request.__dict__.pop(_REQUEST_KEY, None)
    # Without a nonce in the session, a throwaway one makes the verifier fail with
    # nonce_mismatch, so observers see it like any other rejection.
    nonce = _session(request).pop(_SESSION_KEY, None) or generate_nonce()
    return token, nonce


def _session(request: HttpRequest) -> SessionBase:
    # Added by SessionMiddleware, which Django's types do not model.
    return request.session  # ty: ignore[unresolved-attribute]


def _digest(key: str) -> str:
    # Fixed length, so long URLs stay within Memcached's 250-byte key limit.
    return hashlib.sha256(key.encode()).hexdigest()


# Part of every cache key.  Bump it when the stored value changes shape, so that workers
# running different versions during a deploy ignore each other's entries.
_CACHE_FORMAT = "1:"


def _dump(entry: CacheEntry) -> tuple[object, datetime]:
    # Built-in types only: a pickled CacheEntry would break if the class ever moved.
    return (entry.value, entry.stored_at)


def _load(stored: object) -> CacheEntry | None:
    if isinstance(stored, tuple) and len(stored) == 2 and isinstance(stored[1], datetime):
        return CacheEntry(stored[0], stored[1])
    return None


class _CacheBase:
    def __init__(self, alias: str = "default", *, prefix: str = "evp:") -> None:
        self.alias = alias
        self.prefix = prefix

    def _key(self, key: str) -> str:
        return self.prefix + _CACHE_FORMAT + _digest(key)


class EVPCache(_CacheBase):
    """A :class:`~pyevp.Cache` backed by one of Django's ``CACHES``.

    Use a backend shared between workers (Redis, Memcached, database) for the
    cache to help; ``locmem`` is per process like :class:`~pyevp.InMemoryCache`.
    An evicted entry is simply fetched again.  With :class:`~pyevp.AsyncVerifier`,
    use :class:`AsyncEVPCache`, which does not block the event loop.
    """

    def get(self, key: str) -> CacheEntry | None:
        return _load(caches[self.alias].get(self._key(key)))

    def set(self, key: str, entry: CacheEntry, ttl: timedelta) -> None:
        caches[self.alias].set(self._key(key), _dump(entry), timeout=ttl.total_seconds())


class AsyncEVPCache(_CacheBase):
    """An :class:`~pyevp.AsyncCache` using Django's async cache API (``aget`` / ``aset``).

    Takes the same arguments as :class:`EVPCache` and shares its entries.
    """

    async def get(self, key: str) -> CacheEntry | None:
        return _load(await caches[self.alias].aget(self._key(key)))

    async def set(self, key: str, entry: CacheEntry, ttl: timedelta) -> None:
        await caches[self.alias].aset(self._key(key), _dump(entry), timeout=ttl.total_seconds())


class _GuardBase:
    def __init__(self, using: str = "default", *, clock: Clock = system_clock) -> None:
        self.using = using
        self._clock = clock

    def _mark(self, key: str, expires_at: datetime) -> bool:
        from pyevp.contrib.django.models import UsedToken  # noqa: PLC0415

        connection = transaction.get_connection(self.using)
        # Outside an atomic block but with autocommit off, Django would treat the caller's
        # manual transaction as the outer block: nothing commits and a rollback forgets the
        # token.  (Inside an atomic block autocommit is off too; durable=True handles that.)
        if not connection.in_atomic_block and not connection.get_autocommit():
            raise RuntimeError(_MANUAL.format(using=self.using))
        rows = UsedToken.objects.using(self.using)
        try:
            # Durable: the record is committed here, not with (or rolled back with) the
            # caller's transaction.  Nested in one, Django raises instead.
            with transaction.atomic(using=self.using, durable=True):
                rows.filter(expires_at__lte=_db_time(self._clock())).delete()
                rows.create(key=_digest(key), expires_at=_db_time(expires_at))
        except IntegrityError:
            return False
        except RuntimeError as exc:
            if connection.in_atomic_block:
                raise RuntimeError(_NESTED.format(using=self.using)) from exc
            raise
        return True


_NESTED = (
    "EVPReplayGuard must commit its record on its own, but database {using!r} is inside "
    "an atomic block (ATOMIC_REQUESTS or transaction.atomic()); a rollback there would "
    "forget the token.  Give the guard its own alias for the same database with "
    "ATOMIC_REQUESTS off, e.g. EVPReplayGuard(using='evp'), or verify outside the "
    "transaction."
)


_MANUAL = (
    "EVPReplayGuard must commit its record on its own, but autocommit is off on "
    "database {using!r} (AUTOCOMMIT=False or transaction.set_autocommit(False)); a "
    "rollback there would forget the token.  Give the guard its own alias for the same "
    "database with AUTOCOMMIT on, e.g. EVPReplayGuard(using='evp')."
)


class EVPReplayGuard(_GuardBase):
    """A :class:`~pyevp.ReplayGuard` storing accepted tokens in the database.

    Each token is a row keyed by its digest until the token expires; a second
    insert of the same key fails on the primary key, so concurrent workers
    cannot both accept a token.  Unlike a cache, the table never evicts rows
    early, and database errors propagate, so verification fails closed.
    Expired rows are deleted as new tokens are recorded.

    Each record is committed immediately in its own transaction, so a later
    rollback of the request cannot undo it.  Called inside a transaction on
    the same database (``ATOMIC_REQUESTS``, ``transaction.atomic()``, or with
    autocommit off) it raises ``RuntimeError`` instead; point ``using`` at a
    second alias for the same database with ``ATOMIC_REQUESTS`` off and
    autocommit on.  Django's ``TestCase`` transactions are exempt.

    Requires ``"pyevp.contrib.django"`` in ``INSTALLED_APPS`` and ``migrate``.
    """

    def mark_used(self, key: str, expires_at: datetime) -> bool:
        return self._mark(key, expires_at)


class AsyncEVPReplayGuard(_GuardBase):
    """:class:`EVPReplayGuard` for :class:`~pyevp.AsyncVerifier`.

    The database work runs in Django's thread for synchronous code.
    """

    async def mark_used(self, key: str, expires_at: datetime) -> bool:
        return await sync_to_async(self._mark, thread_sensitive=True)(key, expires_at)


def _db_time(value: datetime) -> datetime:
    # Without USE_TZ, Django stores naive datetimes (and SQLite / MySQL reject aware ones).
    return value if settings.USE_TZ else value.astimezone(UTC).replace(tzinfo=None)
