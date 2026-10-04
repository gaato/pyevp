"""Sans-I/O verification core.

:func:`verification_steps` is a generator that yields :data:`Effect` requests
(DNS / HTTPS lookups) and receives their results via ``send``.  Drivers in
:mod:`pyevp.verifier` run it synchronously or asynchronously; tests can drive it
by hand.  Everything else in this module is a pure function.
"""

from __future__ import annotations

import hashlib
import hmac
import math
from collections.abc import Generator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, TypeAlias

from pyevp import _jose, discovery
from pyevp.errors import DiscoveryError, ErrorCode, PolicyError, TokenError
from pyevp.profile import Profile
from pyevp.token import ParsedToken, compute_sd_hash, parse_token
from pyevp.types import JSONObject, VerifiedEmail

__all__ = [
    "Effect",
    "FetchJson",
    "MarkUsed",
    "ResolveTxt",
    "Steps",
    "check_email",
    "precheck_evt",
    "replay_key",
    "verification_steps",
    "verify_evt_signature",
    "verify_kb",
]


@dataclass(frozen=True, slots=True)
class ResolveTxt:
    """Request the TXT records of ``name``.  Reply with ``list[str]`` (empty if none)."""

    name: str


@dataclass(frozen=True, slots=True)
class FetchJson:
    """Request the JSON document at ``url``.  Reply with the decoded JSON value.

    ``refresh`` asks the driver to bypass its cache (e.g. after key rotation).
    """

    url: str
    kind: Literal["metadata", "jwks"]
    refresh: bool = False


@dataclass(frozen=True, slots=True)
class MarkUsed:
    """Record that a token has been accepted.  Reply ``True`` if it was not seen before.

    ``key`` only needs remembering until ``expires_at``: from that instant on, the
    token fails the freshness checks anyway.  Freshness is judged once, before any
    I/O, so a driver must reject the token (``TOKEN_EXPIRED``) if its clock has
    reached ``expires_at`` after marking: the record may already be gone, and a
    replay would not find it.
    """

    key: str
    expires_at: datetime


# TODO(py3.12): back to a ``type`` statement once 3.11 support is dropped.
Effect: TypeAlias = ResolveTxt | FetchJson | MarkUsed
Steps: TypeAlias = Generator[Effect, Any, VerifiedEmail]


@dataclass(frozen=True, slots=True)
class _EVTClaims:
    email: str
    claimed_issuer: str
    issued_at: datetime
    expires_at: datetime | None
    cnf_jwk: JSONObject


def _numeric_date(claims: JSONObject, name: str, what: str) -> datetime | None:
    value = claims.get(name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TokenError(ErrorCode.MALFORMED_TOKEN, f"{what} {name} is not a NumericDate")
    try:
        if not math.isfinite(value):
            raise ValueError(value)
        return datetime.fromtimestamp(value, UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise TokenError(
            ErrorCode.MALFORMED_TOKEN, f"{what} {name} is not a representable NumericDate"
        ) from exc


def _check_freshness(iat: datetime, now: datetime, profile: Profile, what: str) -> None:
    if iat > now + profile.clock_skew:
        raise TokenError(ErrorCode.TOKEN_NOT_YET_VALID, f"{what} iat is in the future")
    # Expired from iat + max_token_age + clock_skew on, the instant replay records may be
    # dropped (see MarkUsed.expires_at).
    if now - iat >= profile.max_token_age + profile.clock_skew:
        raise TokenError(ErrorCode.TOKEN_EXPIRED, f"{what} is too old")


def _check_header(
    header_alg: str | None, typ: str | None, algs: frozenset[str], types: frozenset[str], what: str
) -> str:
    if header_alg is None or header_alg in _jose.FORBIDDEN_ALGORITHMS or header_alg not in algs:
        raise TokenError(ErrorCode.UNSUPPORTED_ALG, f"{what} alg {header_alg!r} is not accepted")
    if typ not in types:
        raise TokenError(ErrorCode.BAD_TYPE, f"{what} typ {typ!r} is not accepted")
    return header_alg


def precheck_evt(token: ParsedToken, *, now: datetime, profile: Profile) -> _EVTClaims:
    """Check everything about the EVT that does not need the issuer's keys."""
    evt = token.evt
    _check_header(evt.alg, evt.typ, profile.evt_algorithms, profile.evt_types, "EVT")
    kid = evt.header.get("kid")
    if kid is not None and not isinstance(kid, str):
        raise TokenError(ErrorCode.MALFORMED_TOKEN, "EVT kid is not a string")
    if profile.require_kid and not kid:
        raise TokenError(ErrorCode.MALFORMED_TOKEN, "EVT has no kid")

    claims = evt.claims
    email, iss = claims.get("email"), claims.get("iss")
    if not isinstance(email, str) or "@" not in email:
        raise TokenError(ErrorCode.MALFORMED_TOKEN, "EVT email claim is missing or invalid")
    if not isinstance(iss, str):
        raise TokenError(ErrorCode.MALFORMED_TOKEN, "EVT iss claim is missing")
    if claims.get("email_verified") is not True:
        raise PolicyError(ErrorCode.EMAIL_NOT_VERIFIED, "EVT does not assert email_verified")

    iat = _numeric_date(claims, "iat", "EVT")
    if iat is None:
        raise TokenError(ErrorCode.MALFORMED_TOKEN, "EVT iat claim is missing")
    _check_freshness(iat, now, profile, "EVT")
    exp = _numeric_date(claims, "exp", "EVT")
    if exp is None and profile.require_exp:
        raise TokenError(ErrorCode.MALFORMED_TOKEN, "EVT exp claim is missing")
    # Written so that an ``exp`` near datetime.max cannot overflow.
    if exp is not None and now - profile.clock_skew > exp:
        raise TokenError(ErrorCode.TOKEN_EXPIRED, "EVT has expired")

    cnf = claims.get("cnf")
    jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
    if not isinstance(jwk, dict) or not _jose.is_public_jwk(jwk):
        raise TokenError(ErrorCode.MALFORMED_TOKEN, "EVT cnf.jwk is missing or not a public key")

    return _EVTClaims(email=email, claimed_issuer=iss, issued_at=iat, expires_at=exp, cnf_jwk=jwk)


def verify_kb(
    token: ParsedToken,
    *,
    cnf_jwk: JSONObject,
    audience: str,
    nonce: str,
    now: datetime,
    profile: Profile,
) -> datetime:
    """Verify the key-binding JWT against the holder key bound in the EVT.

    Returns the KB-JWT's ``iat``.
    """
    kb = token.kb
    alg = _check_header(kb.alg, kb.typ, profile.kb_algorithms, profile.kb_types, "KB-JWT")
    cnf_alg = cnf_jwk.get("alg")
    if cnf_alg is None and profile.require_cnf_alg:
        raise TokenError(ErrorCode.UNSUPPORTED_ALG, "cnf.jwk has no alg")
    if cnf_alg is not None and (
        cnf_alg != alg if profile.require_cnf_alg else not _jose.algorithms_compatible(cnf_alg, alg)
    ):
        raise TokenError(ErrorCode.UNSUPPORTED_ALG, "KB-JWT alg does not match cnf.jwk alg")
    if not _jose.key_supports(alg, cnf_jwk):
        raise TokenError(ErrorCode.UNSUPPORTED_ALG, f"cnf.jwk cannot verify KB-JWT alg {alg}")
    if not _jose.verify_compact(kb.compact, cnf_jwk, alg):
        raise TokenError(ErrorCode.KB_SIGNATURE_INVALID, "KB-JWT signature is invalid")

    claims = kb.claims
    if claims.get("aud") != audience:
        raise TokenError(ErrorCode.AUDIENCE_MISMATCH, "KB-JWT aud does not match this origin")
    presented = claims.get("nonce")
    # An empty nonce binds the token to nothing, even if the caller expects one.
    if (
        not isinstance(presented, str)
        or not presented
        or not hmac.compare_digest(presented.encode(), nonce.encode())
    ):
        raise TokenError(ErrorCode.NONCE_MISMATCH, "KB-JWT nonce does not match")
    iat = _numeric_date(claims, "iat", "KB-JWT")
    if iat is None:
        raise TokenError(ErrorCode.MALFORMED_TOKEN, "KB-JWT iat claim is missing")
    _check_freshness(iat, now, profile, "KB-JWT")
    sd_hash = claims.get("sd_hash")
    if not isinstance(sd_hash, str) or not hmac.compare_digest(
        sd_hash.encode(), compute_sd_hash(token.sd_hash_input).encode()
    ):
        raise TokenError(ErrorCode.SD_HASH_MISMATCH, "KB-JWT sd_hash does not match the EVT")
    return iat


def verify_evt_signature(token: ParsedToken, keys: Sequence[JSONObject], profile: Profile) -> None:
    """Verify the EVT signature against an issuer JWK Set.

    Raises ``KEY_NOT_FOUND`` when no key could even be tried, so the caller may
    refresh the key set; ``EVT_SIGNATURE_INVALID`` otherwise.
    """
    alg = token.evt.alg
    assert alg is not None  # guaranteed by precheck_evt
    kid = token.evt.header.get("kid") or None
    candidates = [
        k for k in keys if (kid is None or k.get("kid") == kid) and _jose.key_supports(alg, k)
    ]
    if not candidates:
        raise DiscoveryError(ErrorCode.KEY_NOT_FOUND, f"no issuer key for kid={kid!r} alg={alg}")
    if not any(_jose.verify_compact(token.evt.compact, k, alg) for k in candidates):
        raise TokenError(ErrorCode.EVT_SIGNATURE_INVALID, "EVT signature is invalid")


def check_email(asserted: str, submitted: str | None, profile: Profile) -> None:
    if submitted is not None and not profile.emails_match(asserted, submitted.strip()):
        raise PolicyError(ErrorCode.EMAIL_MISMATCH, "token email does not match submitted email")


def _signing_alg_advertised(alg: str, advertised: tuple[str, ...] | None) -> bool:
    if advertised is None:
        return True
    return any(_jose.algorithms_compatible(alg, a) for a in advertised)


def replay_key(token: str | ParsedToken) -> str:
    """Stable identifier of a presentation for replay detection.

    It is derived from the KB-JWT signing input (header and payload), not from the
    whole token: signatures can be re-encoded without the holder key (ECDSA ``s``
    → ``n - s``, non-canonical base64url), while the signing input cannot. The
    payload binds the nonce, audience, ``iat`` and, through ``sd_hash``, the EVT.

    A raw token is parsed first and raises :class:`~pyevp.TokenError` if malformed.
    """
    if isinstance(token, str):
        token = parse_token(token, allow_disclosures=True)
    signing_input = token.kb.compact.rpartition(".")[0]
    return _jose.b64url_encode(hashlib.sha256(signing_input.encode("ascii")).digest())


def verification_steps(
    token: str,
    *,
    audience: str,
    nonce: str,
    now: datetime,
    profile: Profile,
    email: str | None,
    replay_protection: bool = False,
) -> Steps:
    """Full RP verification.  Yields effects; returns :class:`VerifiedEmail`.

    Order matters: everything that can be checked offline (including the
    key-binding signature) is checked before any network effect is requested,
    and the only hosts ever contacted are derived from DNS, never from the token.
    With ``replay_protection`` the token is marked as used once everything else
    has passed, so that garbage tokens cannot fill the replay store.
    """
    parsed = parse_token(token, allow_disclosures=profile.allow_disclosures)
    evt = precheck_evt(parsed, now=now, profile=profile)
    kb_issued_at = verify_kb(
        parsed, cnf_jwk=evt.cnf_jwk, audience=audience, nonce=nonce, now=now, profile=profile
    )
    check_email(evt.email, email, profile)

    try:
        txt_name = discovery.txt_name_for(evt.email, profile)
    except (ValueError, UnicodeError) as exc:
        raise TokenError(ErrorCode.MALFORMED_TOKEN, "EVT email domain is invalid") from exc
    records = yield ResolveTxt(txt_name)
    issuer = discovery.parse_txt_records(records)
    if discovery.canonical_issuer(evt.claimed_issuer, profile.issuer_format) != issuer:
        raise DiscoveryError(
            ErrorCode.ISSUER_MISMATCH,
            f"EVT iss {evt.claimed_issuer!r} is not the issuer delegated by DNS ({issuer})",
        )

    metadata = discovery.validate_metadata(
        (yield FetchJson(discovery.metadata_url(issuer, profile), "metadata")), issuer
    )
    alg = parsed.evt.alg
    assert alg is not None
    if not _signing_alg_advertised(alg, metadata.signing_alg_values_supported):
        raise TokenError(ErrorCode.UNSUPPORTED_ALG, f"issuer does not advertise alg {alg}")

    keys = discovery.validate_jwks((yield FetchJson(metadata.jwks_uri, "jwks")))
    try:
        verify_evt_signature(parsed, keys, profile)
    except (DiscoveryError, TokenError) as exc:
        if exc.code not in (ErrorCode.KEY_NOT_FOUND, ErrorCode.EVT_SIGNATURE_INVALID):
            raise
        # Possibly a key rotation; the driver rate-limits forced refreshes.
        keys = discovery.validate_jwks((yield FetchJson(metadata.jwks_uri, "jwks", refresh=True)))
        verify_evt_signature(parsed, keys, profile)

    if replay_protection:
        expires_at = kb_issued_at + profile.max_token_age + profile.clock_skew
        if not (yield MarkUsed(replay_key(parsed), expires_at)):
            raise TokenError(ErrorCode.TOKEN_REPLAYED, "token has already been used")

    private = parsed.evt.claims.get("is_private_email")
    return VerifiedEmail(
        email=evt.email,
        issuer=issuer,
        issued_at=evt.issued_at,
        expires_at=evt.expires_at,
        is_private_email=private is True,
        claims=parsed.evt.claims,
    )
