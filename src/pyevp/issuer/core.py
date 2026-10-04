"""The issuer: validate a browser's issuance request, mint an EVT, publish metadata.

Authenticating the user is the application's job and happens between
:meth:`Issuer.parse_request` and :meth:`Issuer.issue`::

    try:
        request = issuer.parse_request(method=..., headers=..., body=...)
        if not session_user_controls(request.email):   # your code, from cookies
            raise IssuanceError.authentication_required()
        response = issuer.success_response(issuer.issue(request))
    except IssuanceError as exc:
        response = exc.to_response()
"""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import re
from collections.abc import Awaitable, Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal, TypeAlias, cast
from urllib.parse import urlsplit

import idna

from pyevp import _httpsig, _jose, discovery
from pyevp._httpsig import Headers
from pyevp.issuer.errors import IssuanceError, IssuanceErrorCode
from pyevp.issuer.fedcm import FEDCM_FETCH_DEST, accounts_document
from pyevp.issuer.keys import SIGNING_ALGORITHMS, Signer, public_jwk
from pyevp.issuer.profile import DEFAULT_ISSUANCE_PROFILE, IssuanceProfile
from pyevp.issuer.response import PUBLIC_CACHE, IssuerResponse
from pyevp.ports import Clock, system_clock
from pyevp.profile import IssuerFormat
from pyevp.replay import AsyncReplayGuard, ReplayGuard

__all__ = [
    "MAX_REQUEST_BODY",
    "AsyncUserEmails",
    "IssuanceEvent",
    "IssuanceObserver",
    "IssuanceRequest",
    "Issuer",
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


def _check_size(lines: Mapping[str, list[str]], body: bytes) -> None:
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
    if len(body) > MAX_REQUEST_BODY:
        raise IssuanceError(IssuanceErrorCode.INVALID_REQUEST, "body too large")


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
        if _httpsig._field_lines(headers).get("sec-fetch-dest") != [FEDCM_FETCH_DEST]:
            return IssuerResponse.json(400, {"error": "not a FedCM request"})
        emails = user_emails() if callable(user_emails) else user_emails
        if inspect.isawaitable(emails):
            if inspect.iscoroutine(emails):
                emails.close()
            raise TypeError("accounts_response needs the addresses, not an awaitable")
        _require_iterable(emails)
        domains = self.email_domains
        listed = [
            e
            for e in dict.fromkeys(cast("Iterable[str]", emails))
            if isinstance(e, str) and is_valid_email(e) and discovery.email_domain(e) in domains
        ]
        if not listed:
            return IssuerResponse.json(401, {"accounts": []})
        return IssuerResponse.json(200, accounts_document(listed))

    # --- issuance ---

    def issuance_response(
        self, *, method: str, headers: Headers, body: bytes, user_emails: UserEmails
    ) -> IssuerResponse:
        """Answer a request to the issuance endpoint.

        Route every method here, with the raw body and the request's header lines.
        ``user_emails`` are the addresses of the user signed in to this issuer; pass an
        empty collection when nobody is.  An EVT is issued only for one of them.
        """
        _require_iterable(user_emails)
        guard = self.replay_guard
        if guard is not None and inspect.iscoroutinefunction(guard.mark_used):
            raise TypeError("use aissuance_response with an asynchronous replay guard")
        try:
            request = self._validate(method, headers, body)
            emails = user_emails() if callable(user_emails) else user_emails
            if inspect.isawaitable(emails):
                if inspect.iscoroutine(emails):
                    emails.close()
                raise TypeError("use aissuance_response with asynchronous user_emails")
            self._authorize(request, emails)
            if guard is not None:
                key, expires_at = self._replay_key(request)
                fresh = cast(ReplayGuard, guard).mark_used(key, expires_at)
                self._check_replay(fresh)
            self._check_fresh(request)
        except IssuanceError as exc:
            return self._refuse(exc)
        return self._grant(request)

    async def aissuance_response(
        self, *, method: str, headers: Headers, body: bytes, user_emails: AsyncUserEmails
    ) -> IssuerResponse:
        """:meth:`issuance_response` for asynchronous replay guards and ``user_emails``."""
        _require_iterable(user_emails)
        try:
            request = self._validate(method, headers, body)
            emails = user_emails() if callable(user_emails) else user_emails
            if inspect.isawaitable(emails):
                emails = await emails
            self._authorize(request, emails)
            if self.replay_guard is not None:
                key, expires_at = self._replay_key(request)
                marked = self.replay_guard.mark_used(key, expires_at)
                fresh = await marked if inspect.isawaitable(marked) else marked
                self._check_replay(fresh)
            self._check_fresh(request)
        except IssuanceError as exc:
            return self._refuse(exc)
        return self._grant(request)

    def parse_request(self, *, method: str, headers: Headers, body: bytes) -> IssuanceRequest:
        """Validate a request with a synchronous (or no) replay guard."""
        guard = self.replay_guard
        if guard is not None and inspect.iscoroutinefunction(guard.mark_used):
            raise TypeError("use aparse_request with an asynchronous replay guard")
        try:
            request = self._validate(method, headers, body)
            if guard is not None:
                key, expires_at = self._replay_key(request)
                fresh = cast(ReplayGuard, guard).mark_used(key, expires_at)
                self._check_replay(fresh)
                self._check_fresh(request)
        except IssuanceError as exc:
            self._rejected(exc)
            raise
        self._accepted(request)
        return request

    async def aparse_request(
        self, *, method: str, headers: Headers, body: bytes
    ) -> IssuanceRequest:
        """Validate a request with a synchronous or asynchronous replay guard."""
        try:
            request = self._validate(method, headers, body)
            if self.replay_guard is not None:
                key, expires_at = self._replay_key(request)
                marked = self.replay_guard.mark_used(key, expires_at)
                fresh = await marked if inspect.isawaitable(marked) else marked
                self._check_replay(fresh)
                self._check_fresh(request)
        except IssuanceError as exc:
            self._rejected(exc)
            raise
        self._accepted(request)
        return request

    def issue(self, request: IssuanceRequest) -> str:
        """Sign an EVT for ``request``.  Call only after authenticating the user."""
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

    @staticmethod
    def success_response(evt: str) -> IssuerResponse:
        return IssuerResponse.json(200, {"issuance_token": evt})

    # --- internals ---

    def _authorize(self, request: IssuanceRequest, user_emails: object) -> None:
        # Before the replay guard: only signed-in users' requests are worth recording.
        _require_iterable(user_emails)
        emails = list(cast("Iterable[str]", user_emails))
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
        return IssuerResponse.json(200, {"issuance_token": self.issue(request)})

    def _header_alg(self, alg: str) -> str:
        return "EdDSA" if alg == "Ed25519" and self.profile.polymorphic_eddsa_header else alg

    def _rejected(self, exc: IssuanceError) -> None:
        detail = str(exc.args[0])
        _logger.debug("EVP issuer refused a request: %s (%s)", exc.code, detail)
        self._notify(IssuanceEvent(False, "request", exc.code, None, detail))

    def _accepted(self, request: IssuanceRequest) -> None:
        self._notify(IssuanceEvent(True, "request", None, discovery.email_domain(request.email)))

    def _notify(self, event: IssuanceEvent) -> None:
        if self.observer is None:
            return
        try:
            self.observer(event)
        except Exception:
            _logger.exception("EVP issuance observer failed")

    def _validate(self, method: str, headers: Headers, body: bytes) -> IssuanceRequest:
        if method != "POST":
            raise IssuanceError(IssuanceErrorCode.INVALID_REQUEST, f"method {method} not allowed")
        # Read once: an iterator would be empty when verify_request parses it again.
        headers = _httpsig.header_pairs(headers)
        lines = _httpsig._field_lines(headers)
        # Before anything else is worth doing, and before Content-Type so that an oversized
        # body is refused the same way whatever it claims to be.
        _check_size(lines, body)
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
