"""Drivers that run :func:`pyevp.core.verification_steps` against real ports."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Collection, Generator, Iterator
from contextlib import AsyncExitStack, ExitStack, contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import TracebackType
from typing import Any, Self, TypeAlias
from urllib.parse import urlsplit

from pyevp._drive import adrive, drive, is_async, lookup, unreachable
from pyevp.cache import AsyncCache, Cache, CacheEntry, InMemoryCache
from pyevp.core import Effect, FetchJson, MarkUsed, Steps, verification_steps
from pyevp.discovery import canonical_issuer
from pyevp.errors import ErrorCode, EVPError, TokenError
from pyevp.nonce import AsyncNonceStore, NonceStore, generate_nonce
from pyevp.observability import Observer, VerificationEvent, claimed_email_domain
from pyevp.ports import (
    AsyncJsonFetcher,
    AsyncTxtResolver,
    Clock,
    JsonFetcher,
    TxtResolver,
    system_clock,
)
from pyevp.profile import DEFAULT_PROFILE, IssuerFormat, Profile
from pyevp.replay import AsyncReplayGuard, ReplayGuard
from pyevp.token import parse_token
from pyevp.types import VerifiedEmail

__all__ = ["AsyncVerifier", "Verifier"]

logger = logging.getLogger("pyevp")


def _validate_origin(origin: str) -> str:
    parts = urlsplit(origin)
    if (
        parts.scheme not in ("https", "http")
        or not parts.hostname
        or parts.path
        or parts.query
        or parts.fragment
        or parts.username
    ):
        raise ValueError(
            f"audience must be a serialized origin like 'https://rp.example': {origin!r}"
        )
    return origin


def _allowed_issuers(issuers: Collection[str] | None) -> frozenset[str] | None:
    if issuers is None:
        return None
    if isinstance(issuers, str):
        raise TypeError("allowed_issuers must be a collection of issuers, not one string")
    allowed = set()
    for issuer in issuers:
        canonical = canonical_issuer(issuer, IssuerFormat.ANY)
        if canonical is None:
            raise ValueError(f"not an issuer identifier (https:// + host, or a host): {issuer!r}")
        allowed.add(canonical)
    return frozenset(allowed)


class _Unreadable(Exception):
    """The token cannot be parsed, so it has no nonce to take."""


def _presented_nonce(token: str) -> str:
    """The nonce in the token's KB-JWT, before anything is verified; ``""`` if it has none."""
    try:
        nonce = parse_token(token, allow_disclosures=True).kb.claims.get("nonce")
    except EVPError:
        raise _Unreadable from None
    return nonce if isinstance(nonce, str) else ""


@dataclass(frozen=True, slots=True)
class _TakeNonce:
    """Take ``nonce`` from the submission's nonce store.  Reply whether it was there."""

    nonce: str


@dataclass(frozen=True, slots=True)
class _CacheGet:
    """Look ``url`` up in the cache.  Reply with its :class:`CacheEntry` or ``None``."""

    url: str


@dataclass(frozen=True, slots=True)
class _CacheSet:
    """Store ``entry`` for ``url`` in the cache."""

    url: str
    entry: CacheEntry


# TODO(py3.12): back to ``type`` statements once 3.11 support is dropped.
_Effect: TypeAlias = Effect | _TakeNonce | _CacheGet | _CacheSet
_Steps: TypeAlias = Generator[_Effect, Any, VerifiedEmail]
_SYNC = "use AsyncVerifier"


class _Base:
    _resolver: TxtResolver | AsyncTxtResolver
    _fetcher: JsonFetcher | AsyncJsonFetcher
    _cache: Cache | AsyncCache
    _replay_guard: ReplayGuard | AsyncReplayGuard | None

    def __init__(
        self,
        *,
        audience: str,
        profile: Profile,
        allowed_issuers: Collection[str] | None,
        clock: Clock,
        cache_ttl: timedelta,
        min_refresh_interval: timedelta,
        replay_protection: bool,
        observer: Observer | None,
    ) -> None:
        self.audience = _validate_origin(audience)
        self._replay_protection = replay_protection
        self._observer = observer
        self.profile = profile
        self.allowed_issuers = _allowed_issuers(allowed_issuers)
        """Canonical issuers whose tokens are accepted, or ``None`` for any issuer."""
        self._clock = clock
        self._cache_ttl = cache_ttl
        self._min_refresh_interval = min_refresh_interval
        self._refresh_lock = threading.Lock()
        self._refresh_attempts: dict[str, datetime] = {}
        # Ports created by default(); ports passed in belong to the caller.
        self._owned: tuple[object, ...] = ()

    def _steps(self, token: str, nonce: str, email: str | None, audience: str | None) -> _Steps:
        return self._cached(
            verification_steps(
                token,
                audience=_validate_origin(audience) if audience is not None else self.audience,
                nonce=nonce,
                clock=self._clock,
                profile=self.profile,
                email=email,
                replay_protection=self._replay_protection,
                allowed_issuers=self.allowed_issuers,
            )
        )

    def _submission_steps(self, token: str, email: str | None, audience: str | None) -> _Steps:
        try:
            presented = _presented_nonce(token)
        except _Unreadable:
            # Fails verification as malformed, with a nonce that matches nothing.
            return (yield from self._steps(token, generate_nonce(), email, audience))
        # Refused before the token is checked, so that this is the one error reported.
        if not presented or not (yield _TakeNonce(presented)):
            raise TokenError(
                ErrorCode.NONCE_MISMATCH, "KB-JWT nonce was not issued to this user or was used"
            )
        return (yield from self._steps(token, presented, email, audience))

    def _cached(self, steps: Steps) -> _Steps:
        """``steps``, with issuer documents answered from the cache where it can."""
        try:
            effect = next(steps)
            while True:
                if isinstance(effect, FetchJson):
                    entry = self._reuse(effect, (yield _CacheGet(effect.url)))
                    if entry is None:
                        entry = CacheEntry((yield effect), self._clock())
                        yield _CacheSet(effect.url, entry)
                    reply: object = entry.value
                else:
                    reply = yield effect
                effect = steps.send(reply)
        except StopIteration as stop:
            return stop.value
        finally:
            steps.close()

    def _performer(self, nonces: NonceStore | AsyncNonceStore | None = None) -> Callable[..., Any]:
        """Answers the effects, as values or, from asynchronous ports, awaitables.

        Failures of the application's own nonce store, replay guard and cache propagate
        unchanged; only failed lookups become ``ISSUER_UNREACHABLE``.
        """

        def perform(effect: _Effect) -> object:
            match effect:
                case _TakeNonce(nonce=nonce):
                    assert nonces is not None
                    return nonces.take(nonce)
                case MarkUsed():
                    assert self._replay_guard is not None
                    return self._replay_guard.mark_used(effect.key, effect.expires_at)
                case _CacheGet(url=url):
                    return self._cache.get(url)
                case _CacheSet(url=url, entry=entry):
                    return self._cache.set(url, entry, self._cache_ttl)
                case _:
                    return lookup(effect, resolver=self._resolver, fetcher=self._fetcher)

        return perform

    @contextmanager
    def _observed(self, token: str) -> Iterator[Callable[[VerifiedEmail], VerifiedEmail]]:
        """Tell the observer how verifying ``token`` ended, once."""
        started = time.perf_counter()

        def ok(result: VerifiedEmail) -> VerifiedEmail:
            self._notify(token, result, None, started)
            return result

        try:
            yield ok
        except BaseException as exc:  # a cancelled verification ends too
            self._notify(token, None, exc, started)
            raise

    def _notify(
        self, token: str, result: VerifiedEmail | None, error: BaseException | None, started: float
    ) -> None:
        if self._observer is None:
            return
        try:
            self._observer(
                VerificationEvent(
                    ok=result is not None,
                    code=error.code if isinstance(error, EVPError) else None,
                    issuer=result.issuer if result is not None else None,
                    email_domain=claimed_email_domain(token),
                    profile=self.profile.name,
                    duration=timedelta(seconds=time.perf_counter() - started),
                )
            )
        except Exception:
            logger.exception("EVP observer raised; ignoring")

    def _reuse(self, effect: FetchJson, entry: CacheEntry | None) -> CacheEntry | None:
        """Decide whether the cached ``entry`` for ``effect.url`` answers the fetch."""
        if entry is None or not effect.refresh:
            return entry
        # A forced refresh is reserved before fetching, so failed fetches and concurrent
        # verifications count against min_refresh_interval too.  Within it, keep the cached
        # value.
        now = self._clock()
        with self._refresh_lock:
            last = max(entry.stored_at, self._refresh_attempts.get(effect.url, entry.stored_at))
            if now - last < self._min_refresh_interval:
                return entry
            self._refresh_attempts = {
                url: at
                for url, at in self._refresh_attempts.items()
                if now - at < self._min_refresh_interval
            }
            self._refresh_attempts[effect.url] = now
        return None


def _missing_extras(cls: type, what: str) -> ImportError:
    return ImportError(
        f"{cls.__name__}.default() needs {what}: pip install 'pyevp[dns,httpx2]', or pass "
        "resolver= and fetcher= yourself (pyevp.adapters.urllib needs no extra dependencies)"
    )


class Verifier(_Base):
    """Synchronous verifier (Django, Flask, scripts).

    Thread-safe as long as the injected ports and cache are.  A context manager:
    leaving it calls :meth:`close`.

    ``allowed_issuers``, when given, are the only issuers whose tokens are accepted, as
    ``https://`` + host or as a host; any other is ``issuer_not_allowed``, refused before
    anything is looked up.  An empty collection accepts no token.
    """

    _resolver: TxtResolver
    _fetcher: JsonFetcher
    _cache: Cache
    _replay_guard: ReplayGuard | None

    def __init__(
        self,
        *,
        audience: str,
        resolver: TxtResolver,
        fetcher: JsonFetcher,
        profile: Profile = DEFAULT_PROFILE,
        allowed_issuers: Collection[str] | None = None,
        cache: Cache | None = None,
        clock: Clock = system_clock,
        cache_ttl: timedelta = timedelta(minutes=10),
        min_refresh_interval: timedelta = timedelta(minutes=1),
        replay_guard: ReplayGuard | None = None,
        observer: Observer | None = None,
    ) -> None:
        super().__init__(
            audience=audience,
            profile=profile,
            allowed_issuers=allowed_issuers,
            clock=clock,
            cache_ttl=cache_ttl,
            min_refresh_interval=min_refresh_interval,
            replay_protection=replay_guard is not None,
            observer=observer,
        )
        self._resolver = resolver
        self._fetcher = fetcher
        self._replay_guard = replay_guard
        self._cache = cache if cache is not None else InMemoryCache(clock=clock)
        for what, method in (
            ("the resolver", resolver.resolve_txt),
            ("the fetcher", fetcher.fetch_json),
            ("the cache", self._cache.get),
            ("the cache", self._cache.set),
            ("the replay guard", getattr(replay_guard, "mark_used", None)),
        ):
            if is_async(method):
                raise TypeError(f"{what} is asynchronous; {_SYNC}")

    @classmethod
    def default(
        cls,
        *,
        audience: str,
        resolver: TxtResolver | None = None,
        fetcher: JsonFetcher | None = None,
        profile: Profile = DEFAULT_PROFILE,
        allowed_issuers: Collection[str] | None = None,
        cache: Cache | None = None,
        clock: Clock = system_clock,
        cache_ttl: timedelta = timedelta(minutes=10),
        min_refresh_interval: timedelta = timedelta(minutes=1),
        replay_guard: ReplayGuard | None = None,
        observer: Observer | None = None,
    ) -> Self:
        """Build a verifier using dnspython and httpx2 or httpx (``pyevp[dns,httpx2]``).

        ``resolver`` and ``fetcher`` default to those adapters, which :meth:`close` closes;
        the other arguments are the constructor's.
        """
        owned: list[object] = []
        if resolver is None:
            try:
                from pyevp.adapters.dnspython import DnsPythonResolver  # noqa: PLC0415
            except ImportError as exc:
                raise _missing_extras(cls, "dnspython") from exc
            resolver = DnsPythonResolver()
            owned.append(resolver)
        if fetcher is None:
            try:
                from pyevp.adapters.httpx import HttpxFetcher  # noqa: PLC0415
            except ImportError as exc:
                raise _missing_extras(cls, "httpx2 or httpx") from exc
            fetcher = HttpxFetcher()
            owned.append(fetcher)
        verifier = cls(
            audience=audience,
            resolver=resolver,
            fetcher=fetcher,
            profile=profile,
            allowed_issuers=allowed_issuers,
            cache=cache,
            clock=clock,
            cache_ttl=cache_ttl,
            min_refresh_interval=min_refresh_interval,
            replay_guard=replay_guard,
            observer=observer,
        )
        verifier._owned = tuple(owned)
        return verifier

    def close(self) -> None:
        """Close the resolver and fetcher that :meth:`default` created.

        Ports passed in belong to the caller, who closes them.  Safe to call twice.
        """
        owned, self._owned = self._owned, ()
        with ExitStack() as stack:
            for port in owned:
                if callable(close := getattr(port, "close", None)):
                    stack.callback(close)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def verify(
        self, token: str, *, nonce: str, email: str | None, audience: str | None = None
    ) -> VerifiedEmail:
        """Verify a presentation token.

        :param nonce: the nonce this server put on the form.  To take it from where you
            kept it, use :meth:`verify_submission` instead.
        :param email: the address the user submitted; checked against the token.  Pass
            ``None`` explicitly to skip the check and use the asserted address instead.
        :param audience: override the configured origin (multi-host deployments).
        :raises pyevp.TokenError: the token is malformed, stale, mis-bound or badly signed.
        :raises pyevp.PolicyError: the token does not satisfy your policy, e.g. it asserts
            another address or comes from an issuer outside ``allowed_issuers``.  Raised
            before the issuer's signature is checked, so it says nothing about authenticity.
        :raises pyevp.DiscoveryError: the issuer could not be used.  ``ISSUER_UNREACHABLE``
            means its DNS or HTTPS failed and may be transient; other codes mean its
            records, metadata or keys are unusable.
        :raises Exception: anything raised by the cache or the replay guard, unchanged:
            a failure of your own infrastructure, not a verdict on the token.

        Any :class:`~pyevp.EVPError` means "do not trust this token".
        """
        with self._observed(token) as ok:
            return ok(
                drive(
                    self._steps(token, nonce, email, audience),
                    self._performer(),
                    hint=_SYNC,
                    translate=unreachable,
                )
            )

    def verify_submission(
        self,
        token: str | None,
        *,
        nonces: NonceStore,
        email: str | None,
        audience: str | None = None,
    ) -> VerifiedEmail | None:
        """Verify the token a form submitted, taking its nonce from ``nonces``.

        Returns ``None`` when ``token`` is empty: the browser does not support EVP, or
        the email provider does not issue tokens.  Fall back to your usual flow, such as a
        confirmation email; ``nonces`` is left as it was.

        Otherwise the nonce the token presents is taken from ``nonces``, even if the
        token then fails, and the token is checked as by :meth:`verify`.  A nonce that
        ``nonces`` did not issue, or that was used already, is ``nonce_mismatch``.

        :param token: the submitted field, as is.
        :param email: as for :meth:`verify`.
        :raises pyevp.EVPError: as :meth:`verify` does.
        """
        if is_async(nonces.take):
            raise TypeError(f"the nonce store is asynchronous; {_SYNC}")
        if not token:
            return None
        with self._observed(token) as ok:
            return ok(
                drive(
                    self._submission_steps(token, email, audience),
                    self._performer(nonces),
                    hint=_SYNC,
                    translate=unreachable,
                )
            )


class AsyncVerifier(_Base):
    """Asynchronous verifier (FastAPI, Starlette, Django async views).

    An async context manager: leaving it calls :meth:`aclose`.
    """

    _resolver: AsyncTxtResolver
    _fetcher: AsyncJsonFetcher

    def __init__(
        self,
        *,
        audience: str,
        resolver: AsyncTxtResolver,
        fetcher: AsyncJsonFetcher,
        profile: Profile = DEFAULT_PROFILE,
        allowed_issuers: Collection[str] | None = None,
        cache: Cache | AsyncCache | None = None,
        clock: Clock = system_clock,
        cache_ttl: timedelta = timedelta(minutes=10),
        min_refresh_interval: timedelta = timedelta(minutes=1),
        replay_guard: ReplayGuard | AsyncReplayGuard | None = None,
        observer: Observer | None = None,
    ) -> None:
        super().__init__(
            audience=audience,
            profile=profile,
            allowed_issuers=allowed_issuers,
            clock=clock,
            cache_ttl=cache_ttl,
            min_refresh_interval=min_refresh_interval,
            replay_protection=replay_guard is not None,
            observer=observer,
        )
        self._resolver = resolver
        self._fetcher = fetcher
        self._replay_guard = replay_guard
        self._cache = cache if cache is not None else InMemoryCache(clock=clock)

    @classmethod
    def default(
        cls,
        *,
        audience: str,
        resolver: AsyncTxtResolver | None = None,
        fetcher: AsyncJsonFetcher | None = None,
        profile: Profile = DEFAULT_PROFILE,
        allowed_issuers: Collection[str] | None = None,
        cache: Cache | AsyncCache | None = None,
        clock: Clock = system_clock,
        cache_ttl: timedelta = timedelta(minutes=10),
        min_refresh_interval: timedelta = timedelta(minutes=1),
        replay_guard: ReplayGuard | AsyncReplayGuard | None = None,
        observer: Observer | None = None,
    ) -> Self:
        """Build a verifier using dnspython and httpx2 or httpx (``pyevp[dns,httpx2]``).

        ``resolver`` and ``fetcher`` default to those adapters, which :meth:`aclose` closes;
        the other arguments are the constructor's.
        """
        owned: list[object] = []
        if resolver is None:
            try:
                from pyevp.adapters.dnspython import AsyncDnsPythonResolver  # noqa: PLC0415
            except ImportError as exc:
                raise _missing_extras(cls, "dnspython") from exc
            resolver = AsyncDnsPythonResolver()
            owned.append(resolver)
        if fetcher is None:
            try:
                from pyevp.adapters.httpx import AsyncHttpxFetcher  # noqa: PLC0415
            except ImportError as exc:
                raise _missing_extras(cls, "httpx2 or httpx") from exc
            fetcher = AsyncHttpxFetcher()
            owned.append(fetcher)
        verifier = cls(
            audience=audience,
            resolver=resolver,
            fetcher=fetcher,
            profile=profile,
            allowed_issuers=allowed_issuers,
            cache=cache,
            clock=clock,
            cache_ttl=cache_ttl,
            min_refresh_interval=min_refresh_interval,
            replay_guard=replay_guard,
            observer=observer,
        )
        verifier._owned = tuple(owned)
        return verifier

    async def aclose(self) -> None:
        """Close the resolver and fetcher that :meth:`default` created.

        Ports passed in belong to the caller, who closes them.  Safe to call twice.
        """
        owned, self._owned = self._owned, ()
        async with AsyncExitStack() as stack:
            for port in owned:
                if callable(aclose := getattr(port, "aclose", None)):
                    stack.push_async_callback(aclose)
                elif callable(close := getattr(port, "close", None)):
                    stack.callback(close)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def verify(
        self, token: str, *, nonce: str, email: str | None, audience: str | None = None
    ) -> VerifiedEmail:
        """Async counterpart of :meth:`Verifier.verify`."""
        with self._observed(token) as ok:
            steps = self._steps(token, nonce, email, audience)
            return ok(await adrive(steps, self._performer(), translate=unreachable))

    async def verify_submission(
        self,
        token: str | None,
        *,
        nonces: NonceStore | AsyncNonceStore,
        email: str | None,
        audience: str | None = None,
    ) -> VerifiedEmail | None:
        """Async counterpart of :meth:`Verifier.verify_submission`.

        ``nonces`` may be synchronous or asynchronous.
        """
        if not token:
            return None
        with self._observed(token) as ok:
            steps = self._submission_steps(token, email, audience)
            return ok(await adrive(steps, self._performer(nonces), translate=unreachable))
