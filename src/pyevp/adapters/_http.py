"""Pick an HTTP client library: httpx2 when installed, httpx otherwise.

httpx2 (pydantic's maintained fork) has the same API as httpx but distinct
types, so clients and transports must not be mixed between the two.  The
adapters only rely on the shared API and accept a client from either library.
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import TYPE_CHECKING, TypeAlias

__all__ = ["AsyncClient", "Client", "Response", "http"]


def _load() -> ModuleType:
    for name in ("httpx2", "httpx"):
        try:
            return importlib.import_module(name)
        except ImportError:
            continue
    raise ImportError(
        "PyEVP's HTTP adapters need httpx2 or httpx: pip install 'pyevp[httpx2]' or 'pyevp[httpx]'"
    )


http = _load()
"""The selected module (``httpx2`` or ``httpx``)."""

if TYPE_CHECKING:
    import httpx
    import httpx2

    # TODO(py3.12): back to ``type`` statements once 3.11 support is dropped.
    Client: TypeAlias = httpx.Client | httpx2.Client
    AsyncClient: TypeAlias = httpx.AsyncClient | httpx2.AsyncClient
    Response: TypeAlias = httpx.Response | httpx2.Response
