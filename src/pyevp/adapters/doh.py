"""TXT resolvers over DNS-over-HTTPS JSON APIs (``pip install pyevp[httpx2]`` or ``pyevp[httpx]``).

Useful where plain DNS is unavailable or untrusted (serverless platforms,
locked-down networks).  Only an HTTP client is needed; dnspython is not.

``require_dnssec`` checks the resolver's ``AD`` flag, which only means that the
DoH provider validated the answer: you are trusting that provider over TLS.
Unsigned zones (gmail.com, for example) never pass this check.

If you already use ``dnspython[doh]``, an RFC 8484 resolver is also possible::

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["https://cloudflare-dns.com/dns-query"]
    DnsPythonResolver(resolver)
"""

from __future__ import annotations

from types import TracebackType
from typing import TYPE_CHECKING, Self

from pyevp.adapters._doh import (
    CLOUDFLARE,
    GOOGLE,
    DnssecError,
    DohError,
)
from pyevp.adapters._doh import HEADERS as _HEADERS
from pyevp.adapters._doh import params as _params
from pyevp.adapters._doh import records as _records
from pyevp.adapters._http import http

if TYPE_CHECKING:
    from pyevp.adapters._http import AsyncClient, Client, Response

__all__ = [
    "CLOUDFLARE",
    "GOOGLE",
    "AsyncDohResolver",
    "DnssecError",
    "DohError",
    "DohResolver",
]


def _check(response: Response, name: str) -> object:
    if response.status_code != 200:
        raise DohError(f"DoH lookup of {name} returned HTTP {response.status_code}")
    try:
        return response.json()
    except (ValueError, RecursionError) as exc:
        raise DohError(f"DoH lookup of {name} did not return JSON") from exc


class DohResolver:
    """Synchronous DoH TXT resolver (Google by default; pass ``endpoint=CLOUDFLARE`` etc.)."""

    def __init__(
        self,
        endpoint: str = GOOGLE,
        *,
        client: Client | None = None,
        require_dnssec: bool = False,
        timeout: float = 5.0,
    ) -> None:
        self.endpoint = endpoint
        self._owns_client = client is None
        self._client: Client = client or http.Client(timeout=timeout, follow_redirects=False)
        self._require_dnssec = require_dnssec

    def resolve_txt(self, name: str) -> list[str]:
        response = self._client.get(
            self.endpoint, params=_params(name), headers=_HEADERS, follow_redirects=False
        )
        return _records(_check(response, name), name, self._require_dnssec)

    def close(self) -> None:
        """Close the client this resolver created; a client passed in stays open."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class AsyncDohResolver:
    def __init__(
        self,
        endpoint: str = GOOGLE,
        *,
        client: AsyncClient | None = None,
        require_dnssec: bool = False,
        timeout: float = 5.0,
    ) -> None:
        self.endpoint = endpoint
        self._owns_client = client is None
        self._client: AsyncClient = client or http.AsyncClient(
            timeout=timeout, follow_redirects=False
        )
        self._require_dnssec = require_dnssec

    async def resolve_txt(self, name: str) -> list[str]:
        response = await self._client.get(
            self.endpoint, params=_params(name), headers=_HEADERS, follow_redirects=False
        )
        return _records(_check(response, name), name, self._require_dnssec)

    async def aclose(self) -> None:
        """Close the client this resolver created; a client passed in stays open."""
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()
