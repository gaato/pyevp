"""Nonces for the relying party's form.

The RP puts a fresh nonce on the form (``<input ... nonce="...">``) and keeps it, here in
the user's session; the browser binds it into the token it submits.  A
:class:`NonceStore` keeps the nonces a user was shown, and
:meth:`Verifier.verify_submission <pyevp.Verifier.verify_submission>` takes the one a
token presents, once::

    nonces = SessionNonces(session)
    form = f"<input type=email name=email> {token_input(nonces.issue())}"
    ...
    result = verifier.verify_submission(form_data.get("evt"), nonces=nonces, email=...)
"""

from __future__ import annotations

import hmac
import html
import secrets
from datetime import timedelta
from typing import Any, Protocol

from pyevp.ports import Clock, system_clock

__all__ = [
    "AsyncNonceStore",
    "NonceStore",
    "SessionNonces",
    "generate_nonce",
    "nonces_equal",
    "token_input",
]


def generate_nonce(nbytes: int = 32) -> str:
    """Return a URL-safe nonce with ``nbytes`` of entropy (at least 16)."""
    if nbytes < 16:
        raise ValueError("a nonce needs at least 128 bits of entropy")
    return secrets.token_urlsafe(nbytes)


def nonces_equal(a: str, b: str) -> bool:
    """Compare two nonces in constant time."""
    return hmac.compare_digest(a.encode(), b.encode())


class NonceStore(Protocol):
    """Where the nonces a user was shown are kept until a token presents one."""

    def issue(self) -> str:
        """A nonce to put on the forms of the page being rendered."""
        ...

    def take(self, nonce: str) -> bool:
        """Forget ``nonce`` and return whether it was issued and is still unused."""
        ...


class AsyncNonceStore(Protocol):
    """:class:`NonceStore` with asynchronous methods."""

    async def issue(self) -> str: ...

    async def take(self, nonce: str) -> bool: ...


class _Session(Protocol):
    def get(self, key: str, /) -> Any: ...

    def __setitem__(self, key: str, value: Any, /) -> None: ...


class SessionNonces:
    """Keeps a user's unused nonces in their session.

    Works with any session that has ``get`` and item assignment: Flask's ``session``,
    Starlette's ``request.session``, Django's ``request.session``, or a plain ``dict``.
    Up to ``limit`` nonces are kept for ``ttl``, so that forms open in several tabs can
    all be verified; the oldest give way first.  The session holds them as
    ``[[nonce, issued_at], ...]`` under ``key``, which serialises as JSON.

    Use one instance per request: the forms on a page share the nonce of its first
    :meth:`issue`.

    With a session kept in a signed cookie (the default in Flask and Starlette), an
    attacker can send the old cookie again with a captured token, so taking the nonce does
    not stop a replay; a replay guard does (see :doc:`/guides/replay`).
    """

    def __init__(
        self,
        session: _Session,
        *,
        key: str = "evp_nonce",
        limit: int = 5,
        ttl: timedelta = timedelta(minutes=10),
        clock: Clock = system_clock,
    ) -> None:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        self.session = session
        self.key = key
        self.limit = limit
        self.ttl = ttl
        self._clock = clock
        self._issued: str | None = None

    def issue(self) -> str:
        if self._issued is None:
            nonce = generate_nonce()
            entries = [*self._live(), [nonce, self._now()]]
            self.session[self.key] = entries[-self.limit :]
            self._issued = nonce
        return self._issued

    def take(self, nonce: str) -> bool:
        entries = self._live()
        kept = [e for e in entries if not nonces_equal(e[0], nonce)]
        found = len(kept) < len(entries)
        if found or len(entries) != len(self._stored()):
            self.session[self.key] = kept
        if found and self._issued is not None and nonces_equal(self._issued, nonce):
            # A form rendered later in this request needs a nonce of its own.
            self._issued = None
        return found

    def _now(self) -> float:
        return self._clock().timestamp()

    def _stored(self) -> list[Any]:
        stored = self.session.get(self.key)
        return stored if isinstance(stored, list) else []

    def _live(self) -> list[list[Any]]:
        oldest = self._now() - self.ttl.total_seconds()
        return [
            [nonce, issued]
            for entry in self._stored()
            if isinstance(entry, list | tuple)
            and len(entry) == 2
            and isinstance(nonce := entry[0], str)
            and nonce
            and isinstance(issued := entry[1], int | float)
            and not isinstance(issued, bool)
            and issued >= oldest
        ]


class _HTML(str):
    """Markup that templates (Jinja, Django) insert without escaping it again."""

    __slots__ = ()

    def __html__(self) -> str:
        return self


def token_input(nonce: str, *, field: str = "evt") -> str:
    """The hidden input that receives the browser's token, for a form in your page.

    Name the submitted ``field`` when reading the token.  The result is HTML that
    Jinja and Django templates insert as is.
    """
    return _HTML(
        f'<input type="hidden" name="{html.escape(field)}"'
        ' autocomplete="email-verification-token"'
        f' nonce="{html.escape(nonce)}">'
    )
