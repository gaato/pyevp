"""Verification rules, exercised through the sans-I/O generator and the sync driver."""

from __future__ import annotations

import json
import warnings
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any, Literal, TypeAlias

import anyio
import pytest
from joserfc import jws
from joserfc.errors import SecurityWarning

from pyevp import (
    DEFAULT_PROFILE,
    EmailComparison,
    ErrorCode,
    EVPError,
    Profile,
    Verifier,
    emails_match,
)
from pyevp._jose import b64url_encode
from pyevp.core import FetchJson, MarkUsed, ResolveTxt, verification_steps
from pyevp.testing import FakeBrowser, FakeIssuer, FixedClock, make_async_verifier, make_verifier
from pyevp.token import build_kb, compute_sd_hash, sign_jwt

from .conftest import AUDIENCE, EMAIL


def test_steps_request_dns_then_metadata_then_jwks(
    issuer: FakeIssuer, token: str, nonce: str, clock: FixedClock
) -> None:
    steps = verification_steps(
        token, audience=AUDIENCE, nonce=nonce, clock=clock, profile=DEFAULT_PROFILE, email=None
    )
    assert next(steps) == ResolveTxt("_email-verification.example.com")
    assert steps.send(["iss=issuer.example"]) == FetchJson(issuer.metadata_url, "metadata")
    assert steps.send(issuer.metadata) == FetchJson(issuer.jwks_uri, "jwks")
    with pytest.raises(StopIteration) as stop:
        steps.send(issuer.jwks)
    assert stop.value.value.email == EMAIL
    assert stop.value.value.issuer == "https://issuer.example"


def test_a_token_expiring_while_marked_used_is_refused(
    issuer: FakeIssuer, token: str, nonce: str, clock: FixedClock
) -> None:
    steps = verification_steps(
        token,
        audience=AUDIENCE,
        nonce=nonce,
        clock=clock,
        profile=DEFAULT_PROFILE,
        email=None,
        replay_protection=True,
    )
    next(steps)
    steps.send(["iss=issuer.example"])
    steps.send(issuer.metadata)
    marking = steps.send(issuer.jwks)
    assert isinstance(marking, MarkUsed)
    clock.now = marking.expires_at  # the record may already be gone
    with pytest.raises(EVPError) as exc:
        steps.send(True)
    assert exc.value.code is ErrorCode.TOKEN_EXPIRED


def test_offline_failures_request_no_io(token: str, clock: FixedClock) -> None:
    steps = verification_steps(
        token, audience=AUDIENCE, nonce="wrong", clock=clock, profile=DEFAULT_PROFILE, email=None
    )
    with pytest.raises(EVPError) as exc:
        next(steps)
    assert exc.value.code is ErrorCode.NONCE_MISMATCH


def test_key_rotation_requests_refresh(
    issuer: FakeIssuer, token: str, nonce: str, clock: FixedClock
) -> None:
    stale_jwks = issuer.jwks
    issuer.rotate_key()
    fresh = FakeBrowser(clock=clock)
    token = fresh.present(issuer.issue(EMAIL, fresh.public_jwk), audience=AUDIENCE, nonce=nonce)
    steps = verification_steps(
        token, audience=AUDIENCE, nonce=nonce, clock=clock, profile=DEFAULT_PROFILE, email=None
    )
    next(steps)
    steps.send(["iss=issuer.example"])
    steps.send(issuer.metadata)
    assert steps.send(stale_jwks) == FetchJson(issuer.jwks_uri, "jwks", refresh=True)
    with pytest.raises(StopIteration):
        steps.send(issuer.jwks)


# TODO(py3.12): back to a ``type`` statement once 3.11 support is dropped.
Build: TypeAlias = Callable[[FakeIssuer, FakeBrowser, str, FixedClock], str]


def _kb_with(**overrides: Any) -> Build:
    def build(issuer: FakeIssuer, browser: FakeBrowser, nonce: str, clock: FixedClock) -> str:
        evt = issuer.issue(EMAIL, browser.public_jwk)
        claims = {
            "aud": AUDIENCE,
            "nonce": nonce,
            "iat": int(clock().timestamp()),
            "sd_hash": compute_sd_hash(evt + "~"),
            **overrides,
        }
        return f"{evt}~{sign_jwt({'alg': browser.alg, 'typ': 'kb+jwt'}, claims, browser.key)}"

    return build


# --- negative cases -------------------------------------------------------------


def _present(
    issuer: FakeIssuer,
    browser: FakeBrowser,
    nonce: str,
    *,
    email: str = EMAIL,
    claims: dict[str, Any] | None = None,
    header: dict[str, Any] | None = None,
    audience: str = AUDIENCE,
    issued_at: datetime | None = None,
    typ: str = "kb+jwt",
) -> str:
    evt = issuer.issue(email, browser.public_jwk, claims=claims, header=header)
    return browser.present(evt, audience=audience, nonce=nonce, issued_at=issued_at, typ=typ)


def _tamper_kb_signature(token: str) -> str:
    h, p, sig = token.rsplit(".", 2)
    mid = len(sig) // 2
    return f"{h}.{p}.{sig[:mid]}{'A' if sig[mid] != 'A' else 'B'}{sig[mid + 1 :]}"


def _resign_kb(issuer: FakeIssuer, browser: FakeBrowser, nonce: str, clock: FixedClock) -> str:
    evt = issuer.issue(EMAIL, browser.public_jwk)
    other = FakeBrowser(clock=clock)
    return build_kb(
        evt, private_key=other.key, alg="Ed25519", audience=AUDIENCE, nonce=nonce, issued_at=clock()
    )


def _bad_sd_hash(issuer: FakeIssuer, browser: FakeBrowser, nonce: str, clock: FixedClock) -> str:
    evt1 = issuer.issue(EMAIL, browser.public_jwk)
    evt2 = issuer.issue(EMAIL, browser.public_jwk, claims={"extra": 1})
    kb = browser.present(evt1, audience=AUDIENCE, nonce=nonce).split("~")[1]
    return f"{evt2}~{kb}"


def _forged_evt(issuer: FakeIssuer, browser: FakeBrowser, nonce: str, clock: FixedClock) -> str:
    impostor = FakeIssuer(kid=issuer.kid, clock=clock)
    return _present(impostor, browser, nonce)


def _hs256_evt(issuer: FakeIssuer, browser: FakeBrowser, nonce: str, clock: FixedClock) -> str:
    _, payload, sig = issuer.issue(EMAIL, browser.public_jwk).split(".")
    header = b64url_encode(json.dumps({"alg": "HS256", "typ": "evt+jwt"}).encode())
    return browser.present(f"{header}.{payload}.{sig}", audience=AUDIENCE, nonce=nonce)


CASES: dict[str, tuple[Build, ErrorCode]] = {
    "wrong audience": (
        lambda i, b, n, c: _present(i, b, n, audience="https://evil.example"),
        ErrorCode.AUDIENCE_MISMATCH,
    ),
    "wrong nonce": (lambda i, b, n, c: _present(i, b, "other"), ErrorCode.NONCE_MISMATCH),
    "stale kb": (
        lambda i, b, n, c: _present(i, b, n, issued_at=c() - timedelta(minutes=7)),
        ErrorCode.TOKEN_EXPIRED,
    ),
    "future kb": (
        lambda i, b, n, c: _present(i, b, n, issued_at=c() + timedelta(minutes=2)),
        ErrorCode.TOKEN_NOT_YET_VALID,
    ),
    "stale evt": (
        lambda i, b, n, c: _present(i, b, n, claims={"iat": int(c().timestamp()) - 3600}),
        ErrorCode.TOKEN_EXPIRED,
    ),
    "expired evt": (
        lambda i, b, n, c: _present(i, b, n, claims={"exp": int(c().timestamp()) - 120}),
        ErrorCode.TOKEN_EXPIRED,
    ),
    "kb typ": (lambda i, b, n, c: _present(i, b, n, typ="jwt"), ErrorCode.BAD_TYPE),
    "evt typ": (
        lambda i, b, n, c: _present(i, b, n, header={"typ": "evp-sd-jwt"}),
        ErrorCode.BAD_TYPE,
    ),
    "kb tampered": (
        lambda i, b, n, c: _tamper_kb_signature(_present(i, b, n)),
        ErrorCode.KB_SIGNATURE_INVALID,
    ),
    "kb wrong key": (_resign_kb, ErrorCode.KB_SIGNATURE_INVALID),
    "sd_hash": (_bad_sd_hash, ErrorCode.SD_HASH_MISMATCH),
    "evt forged": (_forged_evt, ErrorCode.EVT_SIGNATURE_INVALID),
    "evt hs256": (_hs256_evt, ErrorCode.UNSUPPORTED_ALG),
    "unknown kid": (
        lambda i, b, n, c: _present(i, b, n, header={"kid": "nope"}),
        ErrorCode.KEY_NOT_FOUND,
    ),
    "iss not delegated": (
        lambda i, b, n, c: _present(i, b, n, claims={"iss": "https://evil.example"}),
        ErrorCode.ISSUER_MISMATCH,
    ),
    "no dns record": (
        lambda i, b, n, c: _present(i, b, n, email="alice@unknown.example"),
        ErrorCode.ISSUER_DISCOVERY_FAILED,
    ),
    "not verified": (
        lambda i, b, n, c: _present(i, b, n, claims={"email_verified": False}),
        ErrorCode.EMAIL_NOT_VERIFIED,
    ),
    **{
        f"evt {name} {value!r}": (
            lambda i, b, n, c, name=name, value=value: _present(i, b, n, claims={name: value}),
            ErrorCode.MALFORMED_TOKEN,
        )
        for name in ("iat", "exp")
        for value in (1e100, float("nan"), float("-inf"), 10**30)
    },
    **{
        f"kb iat {value!r}": (_kb_with(iat=value), ErrorCode.MALFORMED_TOKEN)
        for value in (1e100, float("nan"), 10**30)
    },
    **{
        f"cnf.jwk {member} not a string": (
            lambda i, b, n, c, member=member: _present(
                i, b, n, claims={"cnf": {"jwk": {**b.public_jwk, member: [b.public_jwk[member]]}}}
            ),
            ErrorCode.MALFORMED_TOKEN,
        )
        for member in ("alg", "crv", "kty")
    },
    # Lone surrogates decode from JSON but cannot be encoded as UTF-8.
    "kb nonce lone surrogate": (_kb_with(nonce="\ud800"), ErrorCode.MALFORMED_TOKEN),
    "kb sd_hash lone surrogate": (_kb_with(sd_hash="\udfff"), ErrorCode.MALFORMED_TOKEN),
    "evt email lone surrogate": (
        lambda i, b, n, c: _present(i, b, n, claims={"email": "alice\ud800@example.com"}),
        ErrorCode.MALFORMED_TOKEN,
    ),
    "missing email": (
        lambda i, b, n, c: _present(i, b, n, claims={"email": None}),
        ErrorCode.MALFORMED_TOKEN,
    ),
    "missing cnf": (
        lambda i, b, n, c: _present(i, b, n, claims={"cnf": None}),
        ErrorCode.MALFORMED_TOKEN,
    ),
    "private cnf": (
        lambda i, b, n, c: _present(i, b, n, claims={"cnf": {"jwk": b.key.as_dict(private=True)}}),
        ErrorCode.MALFORMED_TOKEN,
    ),
    "cnf alg mismatch": (
        lambda i, b, n, c: _present(
            i, b, n, claims={"cnf": {"jwk": {**b.public_jwk, "alg": "ES256"}}}
        ),
        ErrorCode.UNSUPPORTED_ALG,
    ),
    "bool iat": (
        lambda i, b, n, c: _present(i, b, n, claims={"iat": True}),
        ErrorCode.MALFORMED_TOKEN,
    ),
}


@pytest.mark.parametrize("case", CASES)
def test_rejects(
    case: str,
    issuer: FakeIssuer,
    browser: FakeBrowser,
    nonce: str,
    clock: FixedClock,
    verifier: Verifier,
) -> None:
    build, code = CASES[case]
    with pytest.raises(EVPError) as exc:
        verifier.verify(build(issuer, browser, nonce, clock), nonce=nonce, email=None)
    assert exc.value.code is code


def test_every_error_code_is_exercised() -> None:
    covered = {code for _, code in CASES.values()} | {
        ErrorCode.EMAIL_MISMATCH,  # test_email_mismatch
        ErrorCode.METADATA_INVALID,  # test_discovery
        ErrorCode.ISSUER_UNREACHABLE,  # test_verifier
        ErrorCode.TOKEN_REPLAYED,  # test_replay
        ErrorCode.ISSUER_NOT_ALLOWED,  # test_verifier
    }
    assert covered == set(ErrorCode)


def _cnf_alg_ed448(kb_alg: Literal["Ed25519", "EdDSA"]) -> Build:
    def build(issuer: FakeIssuer, browser: FakeBrowser, nonce: str, clock: FixedClock) -> str:
        holder = FakeBrowser(alg=kb_alg, clock=clock)  # an Ed25519 key either way
        jwk = {**holder.public_jwk, "alg": "Ed448"}
        evt = issuer.issue(EMAIL, jwk)
        return holder.present(evt, audience=AUDIENCE, nonce=nonce)

    return build


@pytest.mark.parametrize("kb_alg", ["Ed25519", "EdDSA"])
def test_ed448_cnf_does_not_cover_ed25519(
    issuer: FakeIssuer,
    browser: FakeBrowser,
    nonce: str,
    clock: FixedClock,
    verifier: Verifier,
    kb_alg: Literal["Ed25519", "EdDSA"],
) -> None:
    with pytest.raises(EVPError) as exc:
        verifier.verify(
            _cnf_alg_ed448(kb_alg)(issuer, browser, nonce, clock), nonce=nonce, email=None
        )
    assert exc.value.code is ErrorCode.UNSUPPORTED_ALG


def test_exp_at_the_end_of_time(issuer: FakeIssuer, browser: FakeBrowser, nonce: str) -> None:
    verifier = make_verifier(issuer, audience=AUDIENCE)
    token = _present(issuer, browser, nonce, claims={"exp": 253402300799})  # 9999-12-31
    assert verifier.verify(token, nonce=nonce, email=None).email == EMAIL


def test_email_mismatch(verifier: Verifier, token: str, nonce: str) -> None:
    with pytest.raises(EVPError) as exc:
        verifier.verify(token, nonce=nonce, email="mallory@example.com")
    assert exc.value.code is ErrorCode.EMAIL_MISMATCH


@pytest.mark.parametrize(
    ("submitted", "profile", "ok"),
    [
        ("ALICE@example.com", Profile.compat_2026_10(), True),
        (" alice@example.com ", Profile.draft_hardt_02(), True),
        ("ALICE@example.com", Profile.draft_hardt_02(), False),
    ],
)
def test_email_comparison(
    issuer: FakeIssuer, token: str, nonce: str, submitted: str, profile: Profile, ok: bool
) -> None:
    verifier = make_verifier(issuer, audience=AUDIENCE, profile=profile)
    if ok:
        verifier.verify(token, nonce=nonce, email=submitted)
    else:
        with pytest.raises(EVPError):
            verifier.verify(token, nonce=nonce, email=submitted)


def test_is_private_email(issuer: FakeIssuer, browser: FakeBrowser, nonce: str) -> None:
    verifier = make_verifier(issuer, audience=AUDIENCE)
    token = _present(issuer, browser, nonce, claims={"is_private_email": True})
    assert verifier.verify(token, nonce=nonce, email=None).is_private_email


def test_idn_domain_is_not_folded_to_another_domain(
    browser: FakeBrowser, nonce: str, clock: FixedClock
) -> None:
    # Delegated for fass.example only; IDNA2003 would also map faß.example there.
    issuer = FakeIssuer(email_domains=("fass.example",), clock=clock)
    token = browser.present(
        issuer.issue("a@faß.example", browser.public_jwk), audience=AUDIENCE, nonce=nonce
    )
    with pytest.raises(EVPError) as exc:
        make_verifier(issuer, audience=AUDIENCE).verify(token, nonce=nonce, email=None)
    assert exc.value.code is ErrorCode.ISSUER_DISCOVERY_FAILED


@pytest.mark.parametrize(
    ("asserted", "submitted", "ok"),
    [
        ("alice@example.com", "ALICE@EXAMPLE.com", True),
        ("a@Bücher.example", "a@xn--bcher-kva.example", True),
        ("Straße@example.com", "STRASSE@example.com", True),
        ("a@faß.example", "a@fass.example", False),
        ("a@fass.example", "a@FASS.example", True),
        ("a@example.com", "a@example.com.", False),
        ("a@example.com", "b@example.com", False),
        ("a@\u0300x.example", "a@\u0300x.example", False),  # invalid IDNA2008 label
        ("a@example.com", "example.com", False),
    ],
)
def test_case_insensitive_emails_match(asserted: str, submitted: str, ok: bool) -> None:
    profile = Profile.compat_2026_10()
    assert emails_match(asserted, submitted, EmailComparison.CASE_INSENSITIVE) is ok
    assert profile.emails_match(asserted, submitted) is ok


def test_exact_emails_match() -> None:
    profile = Profile.draft_hardt_02()
    assert profile.emails_match("a@example.com", "a@example.com")
    assert not profile.emails_match("a@example.com", "A@example.com")


def test_case_folding_does_not_merge_domains(
    browser: FakeBrowser, nonce: str, clock: FixedClock
) -> None:
    # The holder of a@faß.example must not pass for a@fass.example, another DNS name.
    issuer = FakeIssuer(email_domains=("xn--fa-hia.example",), clock=clock)
    token = browser.present(
        issuer.issue("a@faß.example", browser.public_jwk), audience=AUDIENCE, nonce=nonce
    )
    verifier = make_verifier(issuer, audience=AUDIENCE)
    assert verifier.verify(token, nonce=nonce, email="A@FAß.example").email == "a@faß.example"
    with pytest.raises(EVPError) as exc:
        verifier.verify(token, nonce=nonce, email="a@fass.example")
    assert exc.value.code is ErrorCode.EMAIL_MISMATCH


@pytest.mark.parametrize("profile", [Profile.compat_2026_10(), Profile.draft_hardt_02()])
def test_signed_unencoded_payload_is_refused(
    issuer: FakeIssuer, browser: FakeBrowser, nonce: str, profile: Profile
) -> None:
    # Signed over the payload segment as raw bytes (RFC 7797), while the claims would be
    # read by base64url-decoding it: the signature and the claims must not disagree.
    payload = issuer.issue(EMAIL, browser.public_jwk).split(".")[1]
    header = {"alg": issuer.alg, "kid": issuer.kid, "typ": "evt+jwt", "b64": False, "crit": ["b64"]}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SecurityWarning)
        evt = jws.serialize_compact(header, payload.encode(), issuer.key, algorithms=[issuer.alg])
    assert evt.split(".")[1] == payload
    token = browser.present(evt + "~", audience=AUDIENCE, nonce=nonce)
    with pytest.raises(EVPError) as exc:
        make_verifier(issuer, audience=AUDIENCE, profile=profile).verify(
            token, nonce=nonce, email=EMAIL
        )
    assert exc.value.code is ErrorCode.MALFORMED_TOKEN


def test_holder_key_without_verify_op_is_refused(
    issuer: FakeIssuer, browser: FakeBrowser, nonce: str, verifier: Verifier
) -> None:
    holder = {**browser.public_jwk, "key_ops": ["encrypt"]}
    token = browser.present(issuer.issue(EMAIL, holder), audience=AUDIENCE, nonce=nonce)
    with pytest.raises(EVPError) as exc:
        verifier.verify(token, nonce=nonce, email=None)
    assert exc.value.code is ErrorCode.UNSUPPORTED_ALG


def test_holder_key_with_null_key_ops_is_malformed(
    issuer: FakeIssuer, browser: FakeBrowser, nonce: str
) -> None:
    holder = {**browser.public_jwk, "key_ops": None}
    token = browser.present(issuer.issue(EMAIL, holder), audience=AUDIENCE, nonce=nonce)
    with pytest.raises(EVPError) as exc:
        make_verifier(issuer, audience=AUDIENCE).verify(token, nonce=nonce, email=None)
    assert exc.value.code is ErrorCode.MALFORMED_TOKEN

    async def main() -> None:
        with pytest.raises(EVPError) as exc:
            await make_async_verifier(issuer, audience=AUDIENCE).verify(
                token, nonce=nonce, email=None
            )
        assert exc.value.code is ErrorCode.MALFORMED_TOKEN

    anyio.run(main)


class _EncryptOnlyIssuer(FakeIssuer):
    @property
    def jwks(self) -> dict[str, Any]:
        return {"keys": [{**k, "key_ops": ["encrypt"]} for k in super().jwks["keys"]]}


def test_issuer_key_without_verify_op_is_refused(
    browser: FakeBrowser, nonce: str, clock: FixedClock
) -> None:
    issuer = _EncryptOnlyIssuer(clock=clock)
    with pytest.raises(EVPError) as exc:
        make_verifier(issuer, audience=AUDIENCE).verify(
            _present(issuer, browser, nonce), nonce=nonce, email=None
        )
    assert exc.value.code is ErrorCode.KEY_NOT_FOUND
