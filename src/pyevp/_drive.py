"""Drivers that answer the effects a sans-I/O flow yields, synchronously or asynchronously.

A flow is a generator: it yields an effect, is sent the answer, and finally returns its
result.  ``perform`` answers one effect, with a value or, for asynchronous ports, an
awaitable.  The two drivers differ only in what they do with an awaitable: :func:`adrive`
awaits it, and :func:`drive` refuses it, because a synchronous caller cannot wait for it
and taking it as the answer would be wrong (a coroutine is truthy).
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Generator
from typing import Any, TypeAlias, TypeVar

from pyevp.core import FetchJson, ResolveTxt
from pyevp.errors import DiscoveryError, ErrorCode, EVPError
from pyevp.ports import AsyncJsonFetcher, AsyncTxtResolver, JsonFetcher, TxtResolver

E = TypeVar("E")
R = TypeVar("R")

# TODO(py3.12): back to ``type`` statements once 3.11 support is dropped.
Translate: TypeAlias = Callable[[Any, Exception], Exception | None]
"""Maps an exception raised while answering an effect to the one to raise, or ``None``."""


def is_async(function: object) -> bool:
    """Whether calling ``function`` returns a coroutine, as far as can be told beforehand."""
    return inspect.iscoroutinefunction(function) or inspect.iscoroutinefunction(
        getattr(function, "__call__", None)  # noqa: B004  (a callable object)
    )


def drive(
    steps: Generator[E, object, R],
    perform: Callable[[E], object],
    *,
    hint: str,
    translate: Translate | None = None,
) -> R:
    """Run ``steps`` to completion, answering each effect with ``perform``.

    An awaitable answer is a :class:`TypeError` that ends with ``hint``, such as
    ``"use AsyncVerifier"``.
    """
    try:
        effect = next(steps)
        while True:
            reply = _answer(effect, perform, translate)
            if inspect.isawaitable(reply):
                if inspect.iscoroutine(reply):
                    reply.close()
                raise TypeError(
                    f"the port answering {type(effect).__name__.lstrip('_')} returned an "
                    f"awaitable, which a synchronous call cannot wait for; {hint}"
                )
            effect = steps.send(reply)
    except StopIteration as stop:  # the flow's own: a port's is a RuntimeError by now
        return stop.value
    finally:
        steps.close()


async def adrive(
    steps: Generator[E, object, R],
    perform: Callable[[E], object],
    *,
    translate: Translate | None = None,
) -> R:
    """Run ``steps`` to completion, awaiting the answers that are awaitable."""
    try:
        effect = next(steps)
        while True:
            effect = steps.send(await _aanswer(effect, perform, translate))
    except StopIteration as stop:  # the flow's own: a port's is a RuntimeError by now
        return stop.value
    finally:
        steps.close()


def _answer(effect: E, perform: Callable[[E], object], translate: Translate | None) -> object:
    try:
        return perform(effect)
    except Exception as exc:
        raise _failure(effect, exc, translate) from exc


def _failure(effect: object, exc: Exception, translate: Translate | None) -> Exception:
    mapped = translate(effect, exc) if translate is not None else None
    if mapped is not None:
        return mapped
    if isinstance(exc, StopIteration):
        # Would otherwise look like the flow finishing, with the port's value as its result.
        return RuntimeError(f"the port answering {type(effect).__name__} raised StopIteration")
    return exc


async def _aanswer(
    effect: E, perform: Callable[[E], object], translate: Translate | None
) -> object:
    try:
        reply = perform(effect)
        return await reply if inspect.isawaitable(reply) else reply
    except Exception as exc:
        raise _failure(effect, exc, translate) from exc


def lookup(
    effect: object,
    *,
    resolver: TxtResolver | AsyncTxtResolver,
    fetcher: JsonFetcher | AsyncJsonFetcher,
) -> object:
    """Answer a DNS or HTTP lookup with the ports, as a value or an awaitable."""
    if isinstance(effect, ResolveTxt):
        return resolver.resolve_txt(effect.name)
    if isinstance(effect, FetchJson):
        return fetcher.fetch_json(effect.url)
    raise TypeError(f"unexpected effect {effect!r}")


def unreachable(effect: object, exc: Exception) -> DiscoveryError | None:
    """A failed DNS or HTTP request to the issuer, as ``ISSUER_UNREACHABLE``.

    ``None`` for anything else, which then propagates unchanged: a verdict already
    reached (:class:`~pyevp.EVPError`), or a failure of the cache, store or guard.
    """
    if isinstance(exc, EVPError) or not isinstance(effect, ResolveTxt | FetchJson):
        return None
    target = effect.name if isinstance(effect, ResolveTxt) else effect.url
    return DiscoveryError(ErrorCode.ISSUER_UNREACHABLE, f"lookup of {target} failed: {exc}")
