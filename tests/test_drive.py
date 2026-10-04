from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any

import anyio
import pytest

from pyevp._drive import adrive, drive, is_async, unreachable
from pyevp.core import FetchJson, MarkUsed, ResolveTxt
from pyevp.errors import DiscoveryError, ErrorCode, TokenError


def _flow(log: list[str]) -> Generator[object, Any, str]:
    try:
        records = yield ResolveTxt("_email-verification.example.com")
        document = yield FetchJson("https://issuer.example/x", "metadata")
        return f"{records}/{document}"
    finally:
        log.append("closed")


def test_drive_answers_effects_in_order() -> None:
    log: list[str] = []
    answers: dict[type, object] = {ResolveTxt: ["iss=issuer.example"], FetchJson: {"a": 1}}
    result = drive(_flow(log), lambda e: answers[type(e)], hint="h")
    assert result == "['iss=issuer.example']/{'a': 1}"
    assert log == ["closed"]


def test_drive_refuses_and_closes_an_awaitable() -> None:
    log: list[str] = []
    made = []

    async def answer() -> list[str]:
        return []

    def perform(effect: object) -> object:
        made.append(coroutine := answer())
        return coroutine

    with pytest.raises(TypeError, match=r"answering ResolveTxt returned an awaitable.*; use X$"):
        drive(_flow(log), perform, hint="use X")
    assert made[0].cr_frame is None  # closed, so never "never awaited"
    assert log == ["closed"]


def test_adrive_awaits_what_needs_awaiting() -> None:
    async def records() -> list[str]:
        return ["iss=issuer.example"]

    def perform(effect: object) -> object:
        return records() if isinstance(effect, ResolveTxt) else {"a": 1}

    async def main() -> str:
        return await adrive(_flow([]), perform)

    assert anyio.run(main) == "['iss=issuer.example']/{'a': 1}"


@pytest.mark.parametrize("run", ["sync", "async"])
def test_only_lookup_failures_become_issuer_unreachable(run: str) -> None:
    def fail(exc: Exception) -> Any:
        def perform(effect: object) -> object:
            raise exc

        if run == "sync":
            return drive(_flow([]), perform, hint="h", translate=unreachable)
        return anyio.run(lambda: adrive(_flow([]), perform, translate=unreachable))

    with pytest.raises(DiscoveryError) as info:
        fail(OSError("down"))
    assert info.value.code == ErrorCode.ISSUER_UNREACHABLE
    assert isinstance(info.value.__cause__, OSError)
    # A verdict passes through unchanged.
    with pytest.raises(TokenError):
        fail(TokenError(ErrorCode.MALFORMED_TOKEN, "x"))


def test_failures_of_other_effects_propagate_unchanged() -> None:
    assert unreachable(MarkUsed("k", datetime.now(UTC)), OSError("x")) is None


def test_is_async() -> None:
    async def coroutine_function() -> None: ...

    class Callable:
        async def __call__(self) -> None: ...

    assert is_async(coroutine_function)
    assert is_async(Callable())
    assert not is_async(lambda: None)
    assert not is_async(None)


@pytest.mark.parametrize("run", ["sync", "async"])
def test_a_port_raising_stop_iteration_does_not_end_the_flow(run: str) -> None:
    def perform(effect: object) -> object:
        return next(iter([]))  # a bug in the port, not the end of the flow

    def run_flow() -> object:
        if run == "sync":
            return drive(_flow([]), perform, hint="h")
        return anyio.run(lambda: adrive(_flow([]), perform))

    with pytest.raises(RuntimeError, match="raised StopIteration"):
        run_flow()
