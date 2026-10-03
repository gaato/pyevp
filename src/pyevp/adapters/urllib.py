"""A JSON fetcher and a DoH TXT resolver using only the standard library.

Nothing beyond PyEVP's core dependencies is needed, which suits applications
that already pick their own HTTP stack and do not want httpx or dnspython::

    from pyevp import Verifier
    from pyevp.adapters.urllib import UrllibDohResolver, UrllibFetcher

    verifier = Verifier(audience=..., resolver=UrllibDohResolver(), fetcher=UrllibFetcher())

Both are synchronous; async applications should use the httpx adapters.
Like those, they never follow redirects, refuse compressed responses and
cap body sizes.  Proxies from the environment (``HTTPS_PROXY``) are honoured
as usual for urllib; pass ``handlers`` to configure proxies or TLS differently::

    UrllibFetcher(handlers=[urllib.request.HTTPSHandler(context=my_ssl_context)])
"""

from __future__ import annotations

import http.client
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from email.message import Message
from typing import IO
from urllib.parse import urlencode, urlsplit, urlunsplit

from pyevp.adapters import _fetch
from pyevp.adapters._doh import CLOUDFLARE, GOOGLE, DnssecError, DohError, params, records
from pyevp.adapters._doh import HEADERS as _DOH_HEADERS
from pyevp.adapters._fetch import FetchError

# The DoH names are re-exported because pyevp.adapters.doh needs httpx.
__all__ = [
    "CLOUDFLARE",
    "GOOGLE",
    "DnssecError",
    "DohError",
    "FetchError",
    "UrllibDohResolver",
    "UrllibFetcher",
]


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Turn every redirect into an ``HTTPError`` instead of following it."""

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def _opener(handlers: Sequence[urllib.request.BaseHandler]) -> urllib.request.OpenerDirector:
    # Our handler replaces urllib's default redirect handler; drop any the caller passed.
    kept = [h for h in handlers if not isinstance(h, urllib.request.HTTPRedirectHandler)]
    return urllib.request.build_opener(*kept, _NoRedirects())


def _get(
    opener: urllib.request.OpenerDirector,
    url: str,
    headers: Mapping[str, str],
    timeout: float,
    error: type[Exception],
) -> bytes:
    """GET ``url`` and return the raw body of a 200, uncompressed response."""
    request = urllib.request.Request(url, headers=dict(headers), method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            return _read(response, response.status, response.headers, url, error)
    except urllib.error.HTTPError as exc:
        exc.close()
        raise error(f"GET {url} returned HTTP {exc.code}") from None
    # HTTPException covers IncompleteRead from truncated chunked bodies.
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        raise error(f"GET {url} failed: {exc}") from exc


def _read(
    response: IO[bytes], status: int, headers: Message, url: str, error: type[Exception]
) -> bytes:
    if status != 200:
        raise error(f"GET {url} returned HTTP {status}")
    if headers.get("Content-Encoding", "identity").strip().lower() != "identity":
        raise error(f"GET {url} returned a compressed response")
    declared = _content_length(headers)
    if declared is not None and declared > _fetch.MAX_DOCUMENT_BYTES:
        raise error(f"GET {url} response is too large")
    body = response.read(_fetch.MAX_DOCUMENT_BYTES + 1)
    if len(body) > _fetch.MAX_DOCUMENT_BYTES:
        raise error(f"GET {url} response is too large")
    # read(n) returns short when the server closes early; httpx would raise here.
    if declared is not None and len(body) != declared:
        raise error(f"GET {url} response is incomplete")
    return body


def _content_length(headers: Message) -> int | None:
    value = headers.get("Content-Length")
    if value is None or headers.get("Transfer-Encoding"):
        return None
    try:
        length = int(value)
    except ValueError:
        return None
    return length if length >= 0 else None


def _with_query(endpoint: str, extra: Mapping[str, str]) -> str:
    """Append ``extra`` to whatever query ``endpoint`` already has, as httpx's ``params`` do."""
    parts = urlsplit(endpoint)
    query = "&".join(q for q in (parts.query, urlencode(extra)) if q)
    return urlunsplit(parts._replace(query=query))


class UrllibFetcher:
    """Synchronous :class:`~pyevp.JsonFetcher` built on :mod:`urllib.request`.

    Like :class:`~pyevp.adapters.httpx.HttpxFetcher`, it refuses hosts that do not resolve
    exclusively to globally routable addresses unless ``require_global_addresses=False``.
    """

    def __init__(
        self,
        *,
        timeout: float = 5.0,
        handlers: Sequence[urllib.request.BaseHandler] = (),
        require_global_addresses: bool = True,
        resolve_host: _fetch.ResolveHost = _fetch.system_resolve_host,
    ) -> None:
        self._timeout = timeout
        self._opener = _opener(handlers)
        self._require_global = require_global_addresses
        self._resolve_host = resolve_host

    def fetch_json(self, url: str) -> object:
        if self._require_global:
            _fetch.require_global(url, self._resolve_host)
        body = _get(self._opener, url, _fetch.HEADERS, self._timeout, FetchError)
        return _fetch.decode(body, url)


class UrllibDohResolver:
    """Synchronous DoH TXT resolver (Google by default; pass ``CLOUDFLARE`` etc.).

    ``require_dnssec=True`` checks the provider's ``AD`` flag, so it means trusting that
    provider over TLS; unsigned zones (gmail.com, for example) never pass it.
    """

    def __init__(
        self,
        endpoint: str = GOOGLE,
        *,
        require_dnssec: bool = False,
        timeout: float = 5.0,
        handlers: Sequence[urllib.request.BaseHandler] = (),
    ) -> None:
        self.endpoint = endpoint
        self._require_dnssec = require_dnssec
        self._timeout = timeout
        self._opener = _opener(handlers)

    def resolve_txt(self, name: str) -> list[str]:
        url = _with_query(self.endpoint, params(name))
        body = _get(self._opener, url, _DOH_HEADERS, self._timeout, DohError)
        try:
            document = _fetch.decode(body, url)
        except FetchError as exc:
            raise DohError(f"DoH lookup of {name} did not return JSON") from exc
        return records(document, name, self._require_dnssec)
