"""The issuer: answer a browser's requests, mint EVTs, publish metadata.

The issuer answers every endpoint itself; a web framework only passes the request in and
sends the :class:`~pyevp.issuer.IssuerResponse` back.  Which addresses the signed-in user
controls is the one thing it has to be told::

    response = issuer.issuance_response(
        method=..., headers=..., body=...,
        user_emails=lambda: addresses_of(session_user),   # your code, from cookies
    )
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import (
    AsyncIterable,
    Awaitable,
    Callable,
    Collection,
    Generator,
    Iterable,
    Mapping,
    Sequence,
)
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal, TypeAlias, cast
from urllib.parse import unquote, urlsplit

import idna

from pyevp import _httpsig, _jose, discovery
from pyevp._drive import adrive, drive, is_async
from pyevp._httpsig import Headers
from pyevp.core import MarkUsed
from pyevp.issuer.errors import IssuanceError, IssuanceErrorCode
from pyevp.issuer.fedcm import FEDCM_FETCH_DEST, _accounts_document
from pyevp.issuer.keys import SIGNING_ALGORITHMS, Signer, public_jwk
from pyevp.issuer.profile import DEFAULT_ISSUANCE_PROFILE, IssuanceProfile
from pyevp.issuer.response import PUBLIC_CACHE, IssuerResponse
from pyevp.ports import Clock, system_clock
from pyevp.profile import IssuerFormat
from pyevp.replay import AsyncReplayGuard, ReplayGuard

__all__ = [
    "MAX_REQUEST_BODY",
    "AsyncRequestBody",
    "AsyncUserEmails",
    "IssuanceEvent",
    "IssuanceObserver",
    "Issuer",
    "RequestBody",
    "UserEmails",
    "is_valid_email",
]

_logger = logging.getLogger("pyevp")

# WHATWG HTML "valid email address".
_VALID_EMAIL = re.compile(
    r"[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
)
_DIGITS = re.compile(r"[0-9]+")

MAX_REQUEST_BODY = 16 * 1024
"""The largest issuance request body accepted, in bytes.

Larger requests are refused before their signature is checked.  Frameworks need not read
more than one byte beyond this, and nothing at all when ``Content-Length`` exceeds it.
"""


def is_valid_email(value: str) -> bool:
    """Whether ``value`` is a WHATWG HTML valid email address (ASCII only)."""
    return value.isascii() and _VALID_EMAIL.fullmatch(value) is not None


def _email_domain(name: object) -> str:
    """``name`` as a lowercase A-label; ``ValueError`` unless it can be an email domain."""
    if not isinstance(name, str) or "@" in name or name.endswith(".."):
        raise ValueError(f"not a valid email domain: {name!r}")
    domain = discovery.email_domain(f"x@{name}")
    try:
        # Rejects malformed A-labels (xn--…) and names over DNS's length limits.
        idna.encode(domain)
    except idna.IDNAError as exc:
        raise ValueError(f"not a valid email domain: {name!r}") from exc
    if not is_valid_email(f"x@{domain}"):
        raise ValueError(f"not a valid email domain: {name!r}")
    return domain


@dataclass(frozen=True, slots=True)
class IssuanceRequest:
    """A request whose signature, freshness and body have been validated.

    The user has *not* been authenticated yet.
    """

    email: str
    """Exactly as the browser sent it; also what the EVT will assert."""
    holder_jwk: Mapping[str, str]
    """The browser's public key, bound into the EVT as ``cnf.jwk``."""
    alg: str
    created: datetime
    deadline: datetime
    """When the request goes stale, ``created`` plus the maximum age or ``expires``."""
    signature: bytes = field(repr=False)
    signature_base: bytes = field(repr=False)
    """What ``signature`` covers; it identifies the request for the replay guard."""


@dataclass(frozen=True, slots=True)
class IssuanceEvent:
    """What became of one issuance request."""

    ok: bool
    stage: Literal["request", "ownership", "issue"]
    """The stage the request ended at, ``"request"`` (refused by validation), ``"ownership"``
    (the signed-in user does not control the address) or ``"issue"`` (an EVT was signed)."""
    code: IssuanceErrorCode | None
    email_domain: str | None
    detail: str | None = None
    """Why a request was refused, for logs.  It does not repeat the requested address."""


# TODO(py3.12): back to ``type`` statements once 3.11 support is dropped.
IssuanceObserver: TypeAlias = Callable[[IssuanceEvent], None]
"""Receives one event per request; must not block or raise."""

UserEmails: TypeAlias = Iterable[str] | Callable[[], Iterable[str]]
"""The addresses whose mail the signed-in user receives, or a function returning them.

A function is called at most once, and only for a request that is otherwise valid.
"""

AsyncUserEmails: TypeAlias = Iterable[str] | Callable[[], Iterable[str] | Awaitable[Iterable[str]]]
"""Like :data:`UserEmails`; the function may also be ``async``."""

RequestBody: TypeAlias = bytes | Callable[[int], bytes]
"""The request body, or a function reading at most ``n`` bytes of it, such as Django's
``request.read``.  The issuer reads only for a ``POST`` whose ``Content-Length`` allows it, and
then no more than :data:`MAX_REQUEST_BODY` and one byte."""

AsyncRequestBody: TypeAlias = (
    bytes | Callable[[int], bytes | Awaitable[bytes]] | AsyncIterable[bytes]
)
"""Like :data:`RequestBody`; it may also be read asynchronously, or be an asynchronous
iterable of chunks such as Starlette's ``request.stream()``."""


@dataclass(frozen=True, slots=True)
class _ReadBody:
    """Read at most ``limit`` bytes of the body.  Reply with them."""

    limit: int


@dataclass(frozen=True, slots=True)
class _LookupEmails:
    """Look up the signed-in user's addresses.  Reply with them."""


# TODO(py3.12): back to ``type`` statements once 3.11 support is dropped.
_IssuanceEffect: TypeAlias = _ReadBody | _LookupEmails | MarkUsed
_SYNC = "use aissuance_response"


def _read(body: object, limit: int) -> object:
    """``body`` read as :data:`AsyncRequestBody` describes: bytes, or an awaitable of them."""
    if isinstance(body, bytes | bytearray | memoryview):
        return bytes(body)
    if isinstance(body, AsyncIterable):
        return _collect(body, limit)
    if callable(body):
        return body(limit)
    raise TypeError(f"the request body must be bytes or a function reading it, not {body!r}")


async def _collect(chunks: AsyncIterable[bytes], limit: int) -> bytes:
    body = b""
    iterator = aiter(chunks)
    try:
        async for chunk in iterator:
            body += chunk[: limit - len(body)]
            if len(body) >= limit:
                break
    finally:
        if callable(aclose := getattr(iterator, "aclose", None)):
            await aclose()
    return body


def _lookup_emails() -> Generator[_IssuanceEffect, Any, list[str]]:
    emails = yield _LookupEmails()
    _require_iterable(emails)
    return list(emails)


def _owns(email: str, emails: Iterable[str]) -> bool:
    """Whether ``email`` (already valid) is one of ``emails``, compared case-insensitively.

    Addresses EVP cannot carry are ignored: lowercasing a non-ASCII one can turn it into
    someone else's (``\u212aate@`` with a KELVIN SIGN becomes ``kate@``).
    """
    wanted = email.lower()
    return any(isinstance(e, str) and is_valid_email(e) and e.lower() == wanted for e in emails)


def _require_iterable(value: object) -> None:
    if isinstance(value, str | bytes):
        raise TypeError("user_emails must be a collection of addresses, not one string")


class _OwnershipError(IssuanceError):
    def __init__(self, email_domain: str, detail: str) -> None:
        super().__init__(IssuanceErrorCode.AUTHENTICATION_REQUIRED, detail)
        self.email_domain = email_domain


def _require_https_url(value: str, what: str) -> str:
    url = urlsplit(value)
    if url.scheme != "https" or not url.hostname or url.username or url.password:
        raise ValueError(f"{what} must be an https URL, got {value!r}")
    if url.fragment or url.query:
        raise ValueError(f"{what} must not have a query or fragment")
    # Frameworks route the decoded path: an encoded "/" would split it differently, and
    # these characters would be read as route parameters.
    if "%2f" in url.path.lower() or any(c in unquote(url.path) for c in "<>{}"):
        raise ValueError(f"{what} must not encode '/' or contain '<', '>', '{{' or '}}'")
    return value


def _media_type(lines: Iterable[str]) -> str | None:
    values = list(lines)
    if len(values) != 1:
        return None
    return values[0].split(";", 1)[0].strip(" \t").lower()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate member")
        out[key] = value
    return out


def _check_length(lines: Mapping[str, list[str]]) -> None:
    length = lines.get("content-length")
    if length is not None and (
        len(length) != 1
        or not _DIGITS.fullmatch(length[0])
        # int() refuses very long digit strings, and anything this long is too large anyway.
        or len(length[0]) > 9
        or int(length[0]) > MAX_REQUEST_BODY
    ):
        raise IssuanceError(
            IssuanceErrorCode.INVALID_REQUEST, "body too large or malformed Content-Length"
        )


def _parse_body(body: bytes) -> dict[str, Any]:
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object)
        # Lone surrogates from JSON escapes, which nothing downstream expects.
        json.dumps(value, ensure_ascii=False).encode()
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError(f"body is not a JSON object: {exc}") from None
    if not isinstance(value, dict):
        raise ValueError("body is not a JSON object")
    return value


class Issuer:
    """Issues EVTs for the email domains this issuer is authoritative for.

    :param issuer: the issuer identifier, ``https://`` + host (what DNS ``iss=`` names).
    :param issuance_endpoint: the URL browsers POST to.  The request signature is checked
        against this URL, not the ``Host`` header, so it works behind a proxy.
    :param jwks_uri: where :meth:`jwks_document` is served.
    :param signer: the active signing key.
    :param published_keys: further public JWKs to publish: the next key before a rotation,
        and retired keys until every EVT they signed has expired at relying parties.
    :param email_domains: domains EVTs may be issued for, as U-labels or A-labels.  Requests
        for any other domain are refused with ``authentication_required``.  Pass a callable
        returning the current domains when they change at runtime, for example when they live
        in a database.  It is called whenever the domains are needed, may return none, and
        names that are not valid domains are skipped with a warning; in a collection they
        raise ``ValueError``.
    """

    def __init__(
        self,
        *,
        issuer: str,
        issuance_endpoint: str,
        jwks_uri: str,
        signer: Signer,
        email_domains: Collection[str] | Callable[[], Iterable[str]],
        published_keys: Sequence[Mapping[str, Any]] = (),
        signing_alg_values_supported: Sequence[str] = ("Ed25519", "ES256"),
        profile: IssuanceProfile = DEFAULT_ISSUANCE_PROFILE,
        replay_guard: ReplayGuard | AsyncReplayGuard | None = None,
        observer: IssuanceObserver | None = None,
        clock: Clock = system_clock,
    ) -> None:
        if discovery.canonical_issuer(issuer, IssuerFormat.ORIGIN) != issuer:
            raise ValueError(f"issuer must be https:// + a public host, got {issuer!r}")
        self.issuer = issuer
        self.host = issuer.removeprefix("https://")
        self.issuance_endpoint = _require_https_url(issuance_endpoint, "issuance_endpoint")
        self.jwks_uri = _require_https_url(jwks_uri, "jwks_uri")
        if not set(signing_alg_values_supported) <= SIGNING_ALGORITHMS:
            raise ValueError("signing_alg_values_supported must be Ed25519 and/or ES256")
        self.signing_alg_values_supported = tuple(signing_alg_values_supported)
        if signer.alg not in self.signing_alg_values_supported:
            raise ValueError(f"the signer's {signer.alg} is not in signing_alg_values_supported")
        self.signer = signer
        self._jwks = self._build_jwks(signer, published_keys)
        self._domain_source: Callable[[], Iterable[str]] | None = None
        self._domains: frozenset[str] = frozenset()
        if callable(email_domains):
            self._domain_source = cast("Callable[[], Iterable[str]]", email_domains)
        else:
            self._domains = frozenset(_email_domain(d) for d in email_domains)
            if not self._domains:
                raise ValueError("email_domains must not be empty")
        self.profile = profile
        self.replay_guard = replay_guard
        self.observer = observer
        self.clock = clock

    @staticmethod
    def _build_jwks(signer: Signer, published: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        keys = [dict(signer.public_jwk)]
        for key in published:
            kid, alg = key.get("kid"), key.get("alg")
            if not isinstance(kid, str) or not isinstance(alg, str):
                raise ValueError("published keys need kid and alg")
            keys.append(public_jwk(key, kid=kid, alg=alg))
        kids = [k["kid"] for k in keys]
        if len(set(kids)) != len(kids):
            raise ValueError(f"duplicate kid in published keys: {kids}")
        return {"keys": keys}

    @property
    def email_domains(self) -> frozenset[str]:
        """The domains EVTs may be issued for now, as lowercase A-labels."""
        if self._domain_source is None:
            return self._domains
        domains = set()
        for name in self._domain_source():
            try:
                domains.add(_email_domain(name))
            except ValueError:
                _logger.warning("EVP issuer: skipping invalid email domain %r", name)
        return frozenset(domains)

    # --- documents ---

    def metadata_document(self) -> dict[str, Any]:
        """Serve at ``{issuer}/.well-known/email-verification``."""
        return {
            "issuer": self.issuer,
            "issuance_endpoint": self.issuance_endpoint,
            "jwks_uri": self.jwks_uri,
            "signing_alg_values_supported": list(self.signing_alg_values_supported),
            "private_email_supported": False,
        }

    def jwks_document(self) -> dict[str, Any]:
        """Serve at ``jwks_uri``."""
        return {"keys": [dict(k) for k in self._jwks["keys"]]}

    @property
    def issuance_path(self) -> str:
        """The path of :attr:`issuance_endpoint`, to route issuance requests to.

        Decoded, as frameworks match it.  It is the public URL's path: behind a proxy that
        strips a prefix, the application sees another one.
        """
        return unquote(urlsplit(self.issuance_endpoint).path) or "/"

    @property
    def jwks_path(self) -> str:
        """The path of :attr:`jwks_uri`, as for :attr:`issuance_path`."""
        return unquote(urlsplit(self.jwks_uri).path) or "/"

    def metadata_response(self) -> IssuerResponse:
        """:meth:`metadata_document` as a response, cacheable for five minutes."""
        return IssuerResponse.json(200, self.metadata_document(), PUBLIC_CACHE)

    def jwks_response(self) -> IssuerResponse:
        """:meth:`jwks_document` as a response, cacheable for five minutes.

        Publish a new key at least that long, plus how long relying parties cache keys,
        before signing with it.
        """
        return IssuerResponse.json(200, self.jwks_document(), PUBLIC_CACHE)

    def dns_txt_records(self) -> dict[str, str]:
        """The TXT record to publish for each email domain."""
        return {f"_email-verification.{d}": f"iss={self.host}" for d in sorted(self.email_domains)}

    def accounts_response(self, *, headers: Headers, user_emails: UserEmails) -> IssuerResponse:
        """Answer Chrome's FedCM accounts request (see :mod:`pyevp.issuer.fedcm`).

        ``user_emails`` are as for :meth:`issuance_response`.  Only addresses this issuer
        would issue for are listed.
        """
        _require_iterable(user_emails)
        hint = "accounts_response needs the addresses, not an awaitable"
        if callable(user_emails) and is_async(user_emails):
            raise TypeError(hint)
        if _httpsig._field_lines(headers).get("sec-fetch-dest") != [FEDCM_FETCH_DEST]:
            return IssuerResponse.json(400, {"error": "not a FedCM request"})
        emails = drive(_lookup_emails(), self._performer(b"", user_emails), hint=hint)
        domains = self.email_domains
        listed = [
            e
            for e in dict.fromkeys(emails)
            if isinstance(e, str) and is_valid_email(e) and discovery.email_domain(e) in domains
        ]
        if not listed:
            return IssuerResponse.json(401, {"accounts": []})
        return IssuerResponse.json(200, _accounts_document(listed))

    # --- issuance ---

    def issuance_response(
        self, *, method: str, headers: Headers, body: RequestBody, user_emails: UserEmails
    ) -> IssuerResponse:
        """Answer a request to the issuance endpoint.

        Route every method here, with the request's header lines and its body (see
        :data:`RequestBody`).  ``user_emails`` are the addresses of the user signed in to this
        issuer; pass an empty collection when nobody is.  An EVT is issued only for one of
        them.
        """
        _require_iterable(user_emails)
        if is_async(getattr(self.replay_guard, "mark_used", None)):
            raise TypeError(f"the replay guard is asynchronous; {_SYNC}")
        if callable(user_emails) and is_async(user_emails):
            raise TypeError(f"user_emails is asynchronous; {_SYNC}")
        try:
            request = drive(
                self._issuance_steps(method, headers),
                self._performer(body, user_emails),
                hint=_SYNC,
            )
        except IssuanceError as exc:
            return self._refuse(exc)
        return self._grant(request)

    async def aissuance_response(
        self,
        *,
        method: str,
        headers: Headers,
        body: AsyncRequestBody,
        user_emails: AsyncUserEmails,
    ) -> IssuerResponse:
        """:meth:`issuance_response` for asynchronous replay guards, bodies and
        ``user_emails``."""
        _require_iterable(user_emails)
        try:
            request = await adrive(
                self._issuance_steps(method, headers), self._performer(body, user_emails)
            )
        except IssuanceError as exc:
            return self._refuse(exc)
        return self._grant(request)

    def _issuance_steps(
        self, method: str, headers: Headers
    ) -> Generator[_IssuanceEffect, Any, IssuanceRequest]:
        request = yield from self._request(method, headers)
        # Before the replay guard: only signed-in users' requests are worth recording.
        self._authorize(request, (yield from _lookup_emails()))
        if self.replay_guard is not None:
            self._check_replay((yield MarkUsed(*self._replay_key(request))))
        self._check_fresh(request)
        return request

    def _performer(self, body: object, user_emails: object) -> Callable[..., Any]:
        """Answers the effects, as values or, from asynchronous callers, awaitables."""

        def perform(effect: _IssuanceEffect) -> object:
            match effect:
                case _ReadBody(limit=limit):
                    return _read(body, limit)
                case _LookupEmails():
                    return user_emails() if callable(user_emails) else user_emails
                case MarkUsed():
                    assert self.replay_guard is not None
                    return self.replay_guard.mark_used(effect.key, effect.expires_at)

        return perform

    def _issue(self, request: IssuanceRequest) -> str:
        """Sign an EVT for ``request``, whose address the user has been found to control."""
        header = {
            "alg": self._header_alg(self.signer.alg),
            "kid": self.signer.kid,
            "typ": self.profile.evt_type,
        }
        claims = {
            "iss": self.issuer,
            "iat": int(self.clock().timestamp()),
            "cnf": {"jwk": dict(request.holder_jwk)},
            "email": request.email,
            "email_verified": True,
        }
        signing_input = ".".join(
            _jose.b64url_encode(json.dumps(part, separators=(",", ":")).encode())
            for part in (header, claims)
        )
        signature = self.signer.sign(signing_input.encode("ascii"))
        self._notify(IssuanceEvent(True, "issue", None, discovery.email_domain(request.email)))
        return f"{signing_input}.{_jose.b64url_encode(signature)}~"

    # --- internals ---

    def _authorize(self, request: IssuanceRequest, emails: list[str]) -> None:
        if not _owns(request.email, emails):
            detail = "address not the user's" if emails else "no addresses"
            # One answer for every way this can fail, so responses do not reveal accounts.
            raise _OwnershipError(discovery.email_domain(request.email), detail)

    def _refuse(self, exc: IssuanceError) -> IssuerResponse:
        detail = str(exc.args[0])
        _logger.debug("EVP issuer refused a request: %s (%s)", exc.code, detail)
        if isinstance(exc, _OwnershipError):
            event = IssuanceEvent(False, "ownership", exc.code, exc.email_domain, detail)
        else:
            event = IssuanceEvent(False, "request", exc.code, None, detail)
        self._notify(event)
        return exc.to_response()

    def _grant(self, request: IssuanceRequest) -> IssuerResponse:
        return IssuerResponse.json(200, {"issuance_token": self._issue(request)})

    def _header_alg(self, alg: str) -> str:
        return "EdDSA" if alg == "Ed25519" and self.profile.polymorphic_eddsa_header else alg

    def _notify(self, event: IssuanceEvent) -> None:
        if self.observer is None:
            return
        try:
            self.observer(event)
        except Exception:
            _logger.exception("EVP issuance observer failed")

    def _request(
        self, method: str, headers: Headers
    ) -> Generator[_IssuanceEffect, Any, IssuanceRequest]:
        """Validate the request, reading its body only once it is worth reading."""
        if method != "POST":
            raise IssuanceError(IssuanceErrorCode.INVALID_REQUEST, f"method {method} not allowed")
        # Read once: an iterator would be empty when verify_request parses it again.
        headers = _httpsig.header_pairs(headers)
        lines = _httpsig._field_lines(headers)
        # Before anything else is worth doing, and before Content-Type so that an oversized
        # body is refused the same way whatever it claims to be.
        _check_length(lines)
        body = yield _ReadBody(MAX_REQUEST_BODY + 1)
        if not isinstance(body, bytes):
            raise TypeError(f"reading the request body gave {type(body).__name__}, not bytes")
        if len(body) > MAX_REQUEST_BODY:
            raise IssuanceError(IssuanceErrorCode.INVALID_REQUEST, "body too large")
        if _media_type(lines.get("content-type", ())) != "application/json":
            raise IssuanceError(
                IssuanceErrorCode.UNSUPPORTED_MEDIA_TYPE, "Content-Type is not application/json"
            )
        if self.profile.require_sec_fetch_dest and lines.get("sec-fetch-dest") != [
            "email-verification"
        ]:
            raise IssuanceError(
                IssuanceErrorCode.INVALID_REQUEST, "missing or invalid Sec-Fetch-Dest"
            )
        accepted = self.profile.request_algorithms & frozenset(self.signing_alg_values_supported)
        try:
            signed = _httpsig.verify_request(
                method=method,
                endpoint=self.issuance_endpoint,
                headers=headers,
                body=body,
                now=self.clock(),
                max_age=self.profile.max_request_age,
                algorithms=accepted,
                require_key_alg=self.profile.require_request_key_alg,
            )
        except _httpsig.SignatureError as exc:
            if exc.code == "invalid_request":
                raise IssuanceError(IssuanceErrorCode.INVALID_REQUEST, str(exc)) from None
            raise IssuanceError(
                IssuanceErrorCode.INVALID_SIGNATURE, str(exc), signature_error=exc.code
            ) from None

        try:
            document = _parse_body(body)
        except ValueError as exc:
            raise IssuanceError(IssuanceErrorCode.INVALID_REQUEST, str(exc)) from None
        email = document.get("email")
        if not isinstance(email, str) or not is_valid_email(email):
            raise IssuanceError(IssuanceErrorCode.INVALID_REQUEST, "email is missing or invalid")
        private = document.get("private_email", False)
        directed = document.get("directed_email")
        if not isinstance(private, bool) or not isinstance(directed, str | None):
            raise IssuanceError(
                IssuanceErrorCode.INVALID_REQUEST, "private_email or directed_email is malformed"
            )
        if private or directed is not None:
            raise IssuanceError(
                IssuanceErrorCode.PRIVATE_EMAIL_NOT_SUPPORTED, "private email requested"
            )
        if discovery.email_domain(email) not in self.email_domains:
            # Same answer as for an unknown account, so domains cannot be probed either.
            raise IssuanceError.authentication_required("email domain not served")
        return IssuanceRequest(
            email,
            signed.public_jwk,
            signed.alg,
            signed.created,
            signed.deadline,
            signed.signature,
            signed.base,
        )

    def _replay_key(self, request: IssuanceRequest) -> tuple[str, datetime]:
        # Keyed on what was signed, not on the signature: anyone can re-encode an ECDSA
        # signature ((r, s) -> (r, n - s)) into another valid one for the same request.
        key = "issuance:" + hashlib.sha256(request.signature_base).hexdigest()
        return key, request.deadline + timedelta(seconds=1)

    def _check_replay(self, fresh: bool) -> None:
        if not fresh:
            raise IssuanceError(
                IssuanceErrorCode.INVALID_SIGNATURE,
                "request was already used",
                signature_error="invalid_signature",
            )

    def _check_fresh(self, request: IssuanceRequest) -> None:
        # Freshness was judged before the user's addresses were looked up and the guard ran,
        # either of which can be slow.  Still fresh now also means the guard's record (kept a
        # second longer) is still there, so a concurrent copy cannot have missed it.
        if self.clock() > request.deadline:
            raise IssuanceError(
                IssuanceErrorCode.INVALID_SIGNATURE,
                "request expired during validation",
                signature_error="invalid_signature",
            )
