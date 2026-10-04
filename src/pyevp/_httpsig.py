"""HTTP Message Signatures (RFC 9421) with an ``hwk`` Signature-Key, as browsers send them.

Only what EVP issuance needs is implemented: one signature per request, carrying
its public key in ``Signature-Key: <label>=hwk;…`` (draft-hardt-httpbis-signature-key),
over a body bound by ``Content-Digest: sha-256=…`` (RFC 9530).  Derived components
are computed from the issuance endpoint the issuer is configured with, never from
the ``Host`` header, so a signature made for another endpoint does not verify.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, TypeAlias, cast
from urllib.parse import urlsplit

from pyevp import _jose, _sf

__all__ = [
    "Headers",
    "SignatureError",
    "SignedRequest",
    "content_digest",
    "sign_request",
    "verify_request",
]

# TODO(py3.12): back to a ``type`` statement once 3.11 support is dropped.
Headers: TypeAlias = Mapping[str, str] | Iterable[tuple[str, str]]
"""Request headers: a mapping, or ``(name, value)`` pairs that may repeat a name."""

REQUIRED_COMPONENTS = ("@method", "@authority", "@path", "content-digest", "signature-key")
_DERIVED = frozenset({"@method", "@authority", "@path", "@scheme", "@target-uri"})
# Curve -> the fully specified algorithm a key without ``alg`` is taken to use.
_IMPLIED_ALG = {("OKP", "Ed25519"): "Ed25519", ("EC", "P-256"): "ES256"}
_HWK_MEMBERS = {"OKP": ("kty", "crv", "x"), "EC": ("kty", "crv", "x", "y")}


class SignatureError(Exception):
    """Verification failed.  ``code`` is a Signature-Error code (signature-key draft)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class SignedRequest:
    label: str
    alg: str
    public_jwk: dict[str, str]
    """The signer's key as a JWK, always with ``alg``."""
    created: datetime
    deadline: datetime
    """The last moment the request is fresh: ``created`` plus the maximum age, or ``expires``."""
    signature: bytes
    base: bytes
    """The signature base that ``signature`` was verified over."""


def header_pairs(headers: Headers) -> list[tuple[str, str]]:
    """``headers`` as a list, so that an iterator can be read more than once."""
    # A Mapping is also an Iterable of its keys, so narrowing the union confuses type checkers.
    pairs = cast("Mapping[str, str]", headers).items() if isinstance(headers, Mapping) else headers
    return list(pairs)


def _field_lines(headers: Headers) -> dict[str, list[str]]:
    lines: dict[str, list[str]] = {}
    for name, value in header_pairs(headers):
        lines.setdefault(name.lower(), []).append(value.strip(" \t"))
    return lines


def content_digest(body: bytes) -> str:
    return _sf.serialize_dictionary({"sha-256": _sf.Item(hashlib.sha256(body).digest())})


def _check_digest(lines: Sequence[str] | None, body: bytes) -> None:
    if not lines:
        raise SignatureError("invalid_input", "missing Content-Digest")
    try:
        digests = _sf.parse_dictionary(lines)
    except _sf.SFError as exc:
        raise SignatureError("invalid_request", f"malformed Content-Digest: {exc}") from None
    member = digests.get("sha-256")
    if not isinstance(member, _sf.Item) or not isinstance(member.value, bytes):
        raise SignatureError("invalid_request", "Content-Digest has no sha-256 digest")
    if not hmac.compare_digest(member.value, hashlib.sha256(body).digest()):
        raise SignatureError("invalid_signature", "Content-Digest does not match the body")


def _derived(name: str, method: str, endpoint: str) -> str:
    url = urlsplit(endpoint)
    host = (url.hostname or "").lower()
    authority = host if url.port in (None, 443) else f"{host}:{url.port}"
    return {
        "@method": method,
        "@authority": authority,
        "@path": url.path or "/",
        "@scheme": url.scheme.lower(),
        "@target-uri": endpoint,
    }[name]


def _signature_base(
    components: _sf.InnerList,
    *,
    method: str,
    endpoint: str,
    lines: Mapping[str, list[str]],
    required: Sequence[str] = REQUIRED_COMPONENTS,
) -> bytes:
    out: list[str] = []
    seen: set[str] = set()
    for component in components.items:
        name = component.value
        if not isinstance(name, str) or isinstance(name, _sf.Token) or component.params:
            raise SignatureError("invalid_input", f"unsupported component {component!r}")
        if name in seen:
            raise SignatureError("invalid_input", f"component {name!r} is covered twice")
        seen.add(name)
        if name in _DERIVED:
            value = _derived(name, method, endpoint)
        elif name.startswith("@") or name != name.lower():
            raise SignatureError("invalid_input", f"unsupported component {name!r}")
        elif name not in lines:
            raise SignatureError("invalid_input", f"covered field {name!r} is missing")
        else:
            value = ", ".join(lines[name])
        out.append(f'"{name}": {value}')
    if missing := [c for c in required if c not in seen]:
        raise SignatureError("invalid_input", f"components not covered: {', '.join(missing)}")
    out.append(f'"@signature-params": {_sf.serialize_inner_list(components)}')
    try:
        return "\n".join(out).encode("ascii")
    except UnicodeEncodeError:
        raise SignatureError("invalid_input", "covered field is not ASCII") from None


def _hwk_jwk(member: _sf.Item | _sf.InnerList, *, require_alg: bool) -> dict[str, str]:
    if not isinstance(member, _sf.Item) or not isinstance(member.value, _sf.Token):
        raise SignatureError("unsupported_scheme", "Signature-Key member is not a scheme token")
    if member.value != "hwk":
        raise SignatureError("unsupported_scheme", "only the hwk Signature-Key scheme is supported")
    params = member.params
    if "kid" in params:
        raise SignatureError("invalid_key", "hwk keys must not carry kid")
    kty = params.get("kty")
    if not isinstance(kty, str) or kty not in _HWK_MEMBERS:
        raise SignatureError("invalid_key", "unsupported or missing kty")
    jwk: dict[str, str] = {}
    for name in _HWK_MEMBERS[kty]:
        value = params.get(name)
        if not isinstance(value, str) or isinstance(value, _sf.Token):
            raise SignatureError("invalid_key", f"hwk {name} must be a string")
        jwk[name] = value
    alg = params.get("alg")
    if alg is None and not require_alg:
        alg = _IMPLIED_ALG.get((kty, jwk["crv"]))
    if not isinstance(alg, str) or isinstance(alg, _sf.Token):
        raise SignatureError("invalid_key", "hwk alg is missing or not a string")
    jwk["alg"] = alg
    return jwk


def _single_label(lines: Mapping[str, list[str]]) -> tuple[str, Any, Any, Any]:
    parsed = {}
    for name in ("signature-input", "signature", "signature-key"):
        if not lines.get(name):
            raise SignatureError("invalid_signature", f"missing {name} header")
        try:
            parsed[name] = _sf.parse_dictionary(lines[name])
        except _sf.SFError as exc:
            raise SignatureError("invalid_signature", f"malformed {name}: {exc}") from None
    keys = parsed["signature-key"]
    if len(keys) != 1:
        raise SignatureError("invalid_signature", "expected exactly one Signature-Key")
    (label,) = keys
    if label not in parsed["signature-input"] or label not in parsed["signature"]:
        raise SignatureError("invalid_signature", f"no signature labelled {label!r}")
    return label, parsed["signature-input"][label], parsed["signature"][label], keys[label]


def verify_request(
    *,
    method: str,
    endpoint: str,
    headers: Headers,
    body: bytes,
    now: datetime,
    max_age: timedelta,
    algorithms: frozenset[str],
    require_key_alg: bool,
) -> SignedRequest:
    """Verify the signature on a request to ``endpoint`` (the configured issuance URL).

    ``algorithms`` are the fully specified algorithms accepted for the signer's key.
    """
    lines = _field_lines(headers)
    label, components, signature, key_member = _single_label(lines)
    if not isinstance(components, _sf.InnerList):
        raise SignatureError("invalid_signature", "Signature-Input member is not an inner list")
    if not isinstance(signature, _sf.Item) or not isinstance(signature.value, bytes):
        raise SignatureError("invalid_signature", "Signature member is not a byte sequence")

    jwk = _hwk_jwk(key_member, require_alg=require_key_alg)
    alg = jwk["alg"]
    if alg not in algorithms:
        raise SignatureError("unsupported_algorithm", f"signature algorithm {alg!r} not accepted")
    params = components.params
    if "alg" in params and params["alg"] != alg:
        raise SignatureError("invalid_signature", "Signature-Input alg contradicts the key")

    created = params.get("created")
    if not isinstance(created, int) or isinstance(created, bool):
        raise SignatureError("invalid_signature", "Signature-Input has no integer created")
    try:
        created_at = datetime.fromtimestamp(created, UTC)
    except (OverflowError, OSError, ValueError):
        raise SignatureError(
            "invalid_signature", "Signature-Input created is out of range"
        ) from None
    if created_at > now + max_age:
        raise SignatureError("clock_skew", "signature created in the future")
    if created_at < now - max_age:
        raise SignatureError("invalid_signature", "signature is too old")
    expires = params.get("expires")
    if expires is not None and (
        not isinstance(expires, int) or isinstance(expires, bool) or expires < now.timestamp()
    ):
        raise SignatureError("invalid_signature", "signature has expired")
    deadline = created_at + max_age
    if expires is not None and expires < deadline.timestamp():
        deadline = datetime.fromtimestamp(expires, UTC)

    base = _signature_base(components, method=method, endpoint=endpoint, lines=lines)
    if not _jose.verify_raw(base, signature.value, jwk, alg):
        if _jose.import_public(jwk) is None:
            raise SignatureError("invalid_key", "the hwk public key is not valid")
        raise SignatureError("invalid_signature", "HTTP Message Signature verification failed")
    # Only now that the body is known to be what was signed is the digest worth checking.
    _check_digest(lines.get("content-digest"), body)
    return SignedRequest(label, alg, jwk, created_at, deadline, signature.value, base)


def sign_request(
    *,
    method: str,
    endpoint: str,
    body: bytes,
    private_key: Any,
    public_jwk: Mapping[str, Any],
    alg: str,
    created: datetime,
    expires: datetime | None = None,
    label: str = "sig",
    include_alg: bool = True,
    signature_key: str | None = None,
    digest: str | None = None,
) -> dict[str, str]:
    """Return the headers a browser adds to sign an issuance request (for tests).

    ``signature_key`` and ``digest`` replace the generated ``Signature-Key`` and
    ``Content-Digest`` values verbatim.
    """
    if signature_key is None:
        members: dict[str, Any] = {k: public_jwk[k] for k in _HWK_MEMBERS[public_jwk["kty"]]}
        if include_alg:
            members["alg"] = alg
        signature_key = _sf.serialize_dictionary({label: _sf.Item(_sf.Token("hwk"), members)})
    headers = {
        "Content-Type": "application/json",
        "Sec-Fetch-Dest": "email-verification",
        "Content-Digest": content_digest(body) if digest is None else digest,
        "Signature-Key": signature_key,
    }
    params: dict[str, Any] = {"created": int(created.timestamp())}
    if expires is not None:
        params["expires"] = int(expires.timestamp())
    components = _sf.InnerList(tuple(_sf.Item(c) for c in REQUIRED_COMPONENTS), params)
    base = _signature_base(
        components, method=method, endpoint=endpoint, lines=_field_lines(headers)
    )
    signature = _jose.sign_raw(base, private_key, alg)
    headers["Signature-Input"] = _sf.serialize_dictionary({label: components})
    headers["Signature"] = _sf.serialize_dictionary({label: _sf.Item(signature)})
    return headers
