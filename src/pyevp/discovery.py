"""Issuer discovery: pure functions, no I/O."""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlsplit

from pyevp import _jose
from pyevp._email import email_domain
from pyevp.errors import DiscoveryError, ErrorCode
from pyevp.profile import IssuerFormat, Profile
from pyevp.types import IssuerMetadata, JSONObject

__all__ = [
    "METADATA_PATH",
    "canonical_issuer",
    "email_domain",
    "is_public_hostname",
    "metadata_url",
    "parse_txt_records",
    "txt_name_for",
    "validate_jwks",
    "validate_metadata",
]

METADATA_PATH = "/.well-known/email-verification"
"""The path of an issuer's metadata, relative to its identifier."""

_FORBIDDEN_HOST_CHARS = frozenset("/:@?#\\ \t\r\n")
# Special-use names (RFC 6761, RFC 6762, RFC 8375) and the name ICANN reserved for
# private use; none of them can be a public issuer.
_PRIVATE_SUFFIXES = ("localhost", "local", "home.arpa", "internal")


def is_public_hostname(host: str) -> bool:
    """Whether ``host`` may name a public issuer host.

    Rejects IP literals, single-label names and special-use names such as
    ``localhost``, so that a DNS record or metadata document chosen by an attacker
    cannot point the verifier at the relying party's own network.  The addresses a
    public name resolves to are checked by the HTTP adapters before connecting.
    """
    name = host.removeprefix("[").removesuffix("]").rstrip(".").lower()
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        return False
    if "." not in name:
        return False
    return not any(name == s or name.endswith("." + s) for s in _PRIVATE_SUFFIXES)


def txt_name_for(email: str, profile: Profile) -> str:
    return f"{profile.dns_label}.{email_domain(email)}"


def canonical_issuer(value: str, accepted: IssuerFormat) -> str | None:
    """Turn an issuer identifier into its ``https://host`` form.

    Returns ``None`` when ``value`` is not acceptable under ``accepted``.  The
    host is not case-folded: the drafts require byte-for-byte comparison.
    """
    if value.startswith("https://"):
        if accepted is IssuerFormat.HOST:
            return None
        host = value.removeprefix("https://")
    else:
        if accepted is IssuerFormat.ORIGIN:
            return None
        host = value
    if not host or any(c in _FORBIDDEN_HOST_CHARS for c in host) or not host.isascii():
        return None
    if not is_public_hostname(host):
        return None
    return f"https://{host}"


def parse_txt_records(records: Sequence[str]) -> str:
    """Extract the canonical issuer from the TXT records of the discovery name."""
    values = [r.removeprefix("iss=").strip() for r in records if r.startswith("iss=")]
    if len(values) != 1:
        raise DiscoveryError(
            ErrorCode.ISSUER_DISCOVERY_FAILED,
            f"expected exactly one 'iss=' TXT record, found {len(values)}",
        )
    issuer = canonical_issuer(values[0], IssuerFormat.ANY)
    if issuer is None:
        raise DiscoveryError(ErrorCode.ISSUER_DISCOVERY_FAILED, "invalid 'iss=' TXT record")
    return issuer


def metadata_url(issuer: str) -> str:
    """Where ``issuer`` serves its metadata."""
    return issuer + METADATA_PATH


def _require_https_url(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise DiscoveryError(ErrorCode.METADATA_INVALID, f"{field} is missing")
    try:
        parts = urlsplit(value)
        ok = (
            parts.scheme == "https"
            and bool(parts.hostname)
            and is_public_hostname(parts.hostname or "")
        )
    except ValueError:  # e.g. "https://[": urlsplit itself rejects some inputs
        ok = False
    if not ok:
        raise DiscoveryError(
            ErrorCode.METADATA_INVALID, f"{field} is not an https URL on a public host"
        )
    return value


def validate_metadata(document: object, expected_issuer: str) -> IssuerMetadata:
    if not isinstance(document, dict):
        raise DiscoveryError(ErrorCode.METADATA_INVALID, "metadata is not a JSON object")
    if document.get("issuer") != expected_issuer:
        raise DiscoveryError(
            ErrorCode.ISSUER_MISMATCH,
            f"metadata issuer {document.get('issuer')!r} != {expected_issuer!r}",
        )
    algs = document.get("signing_alg_values_supported")
    if algs is not None and not (isinstance(algs, list) and all(isinstance(a, str) for a in algs)):
        raise DiscoveryError(ErrorCode.METADATA_INVALID, "bad signing_alg_values_supported")
    return IssuerMetadata(
        issuer=expected_issuer,
        issuance_endpoint=_require_https_url(
            document.get("issuance_endpoint"), "issuance_endpoint"
        ),
        jwks_uri=_require_https_url(document.get("jwks_uri"), "jwks_uri"),
        signing_alg_values_supported=tuple(algs) if algs is not None else None,
        raw=document,
    )


def validate_jwks(document: object) -> tuple[JSONObject, ...]:
    """Return the usable public keys of a JWK Set; unknown or private entries are dropped."""
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise DiscoveryError(ErrorCode.METADATA_INVALID, "JWKS is not a JWK Set")
    keys = tuple(k for k in document["keys"] if isinstance(k, dict) and _jose.is_public_jwk(k))
    if not keys:
        raise DiscoveryError(ErrorCode.METADATA_INVALID, "JWKS contains no usable public keys")
    return keys
