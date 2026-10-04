from __future__ import annotations

import json
import re
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import anyio
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from joserfc.jwk import ECKey, OKPKey

from pyevp import EVPError, InMemoryReplayGuard, Profile, Verifier, _httpsig, _jose, _sf, discovery
from pyevp._jose import decode_json_segment
from pyevp.diagnostics import discover
from pyevp.issuer import (
    MAX_REQUEST_BODY,
    IssuanceError,
    IssuanceErrorCode,
    IssuanceEvent,
    IssuanceProfile,
    IssuanceRequest,
    Issuer,
    IssuerResponse,
    SigningKey,
    accounts_document,
    is_valid_email,
    public_jwk,
    web_identity_document,
    web_identity_response,
)
from pyevp.testing import FakeBrowser, FixedClock, InMemoryDns, InMemoryHttp

ISSUER = "https://issuer.example"
ENDPOINT = "https://accounts.issuer.example/email-verification/issuance"
JWKS_URI = "https://accounts.issuer.example/email-verification/jwks"
RP = "https://rp.example"


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock()


def make_issuer(clock: FixedClock, **kwargs: Any) -> Issuer:
    options: dict[str, Any] = {
        "issuer": ISSUER,
        "issuance_endpoint": ENDPOINT,
        "jwks_uri": JWKS_URI,
        "signer": SigningKey.generate(kid="2026-10"),
        "email_domains": ["example.com"],
        "clock": clock,
    }
    options.update(kwargs)
    return Issuer(**options)


class Browser:
    def __init__(self, clock: FixedClock, alg: str = "Ed25519") -> None:
        self.clock = clock
        self.alg = alg
        if alg == "ES256":
            self.key: Any = ECKey.generate_key("P-256", private=True)
        else:
            self.key = OKPKey.generate_key("Ed25519", private=True)

    def request(
        self, email: str = "alice@example.com", *, body: dict[str, Any] | None = None, **kw: Any
    ) -> Any:
        raw = json.dumps(body if body is not None else {"email": email}).encode()
        options: dict[str, Any] = {
            "method": "POST",
            "endpoint": ENDPOINT,
            "body": raw,
            "private_key": self.key,
            "public_jwk": self.key.as_dict(private=False),
            "alg": self.alg,
            "created": self.clock(),
            "include_alg": False,
        }
        options.update(kw)
        headers = _httpsig.sign_request(**options)
        return {"method": "POST", "headers": headers, "body": raw}


def present(evt: str, browser: Browser, nonce: str = "n-1") -> str:
    fake = FakeBrowser(alg="Ed25519" if browser.alg == "Ed25519" else "ES256", clock=browser.clock)
    fake.key = browser.key
    return fake.present(evt, audience=RP, nonce=nonce)


def verifier_for(issuer: Issuer, clock: FixedClock, profile: Profile | None = None) -> Verifier:
    records = {name: [value] for name, value in issuer.dns_txt_records().items()}
    documents: dict[str, object] = {
        f"{ISSUER}/.well-known/email-verification": issuer.metadata_document(),
        JWKS_URI: issuer.jwks_document(),
    }
    kwargs: dict[str, Any] = {} if profile is None else {"profile": profile}
    return Verifier(
        audience=RP,
        resolver=InMemoryDns(records),
        fetcher=InMemoryHttp(documents),
        clock=clock,
        **kwargs,
    )


def error(issuer: Issuer, request: Any) -> IssuanceError:
    with pytest.raises(IssuanceError) as info:
        issuer.parse_request(**request)
    return info.value


def respond(
    issuer: Issuer, request: dict[str, Any], emails: Any = ("alice@example.com",)
) -> IssuerResponse:
    return issuer.issuance_response(**request, user_emails=emails)


def refusal(response: IssuerResponse) -> str:
    assert response.headers["Cache-Control"] == "no-store"
    return json.loads(response.body)["error"]


def token(response: IssuerResponse) -> str:
    assert response.status == 200, response.body
    assert response.headers == {"Content-Type": "application/json", "Cache-Control": "no-store"}
    return json.loads(response.body)["issuance_token"]


# --- end to end ---


@pytest.mark.parametrize(
    ("issuance", "verification"),
    [
        # What Chrome and Gmail do today, checked by the default verifier profile.
        (IssuanceProfile.chrome_153(), Profile.compat_2026_10()),
        # The draft on both sides.
        (IssuanceProfile.draft_hardt_02(), Profile.draft_hardt_02()),
        (IssuanceProfile.draft_hardt_02(), Profile.compat_2026_10()),
    ],
)
@pytest.mark.parametrize("alg", ["Ed25519", "ES256"])
def test_issued_tokens_verify(
    clock: FixedClock, issuance: IssuanceProfile, verification: Profile, alg: str
) -> None:
    issuer = make_issuer(clock, signer=SigningKey.generate(alg, kid="k1"), profile=issuance)
    browser = Browser(clock, alg)
    request = issuer.parse_request(**browser.request(include_alg=True))
    evt = issuer.issue(request)
    assert evt.endswith("~")
    result = verifier_for(issuer, clock, verification).verify(
        present(evt, browser), nonce="n-1", email="alice@example.com"
    )
    assert result.email == "alice@example.com"
    assert result.issuer == ISSUER


def test_chrome_profile_tokens_fail_the_strict_verifier(clock: FixedClock) -> None:
    """Chrome only accepts ``EdDSA`` headers, which draft-hardt-02 forbids."""
    issuer = make_issuer(clock)
    browser = Browser(clock)
    evt = issuer.issue(issuer.parse_request(**browser.request()))
    with pytest.raises(EVPError):
        verifier_for(issuer, clock, Profile.draft_hardt_02()).verify(
            present(evt, browser), nonce="n-1", email=None
        )


@pytest.mark.parametrize(
    ("profile", "header_alg"),
    [(IssuanceProfile.chrome_153(), "EdDSA"), (IssuanceProfile.draft_hardt_02(), "Ed25519")],
)
def test_evt_shape(clock: FixedClock, profile: IssuanceProfile, header_alg: str) -> None:
    issuer = make_issuer(clock, profile=profile)
    browser = Browser(clock)
    evt = issuer.issue(
        issuer.parse_request(**browser.request("Alice@Example.com", include_alg=True))
    )
    header, claims, _ = evt.removesuffix("~").split(".")
    assert decode_json_segment(header) == {"alg": header_alg, "kid": "2026-10", "typ": "evt+jwt"}
    assert decode_json_segment(claims) == {
        "iss": ISSUER,
        "iat": int(clock().timestamp()),
        "cnf": {"jwk": {**browser.key.as_dict(private=False), "alg": "Ed25519"}},
        "email": "Alice@Example.com",
        "email_verified": True,
    }


def test_es256_header_is_unchanged_by_the_chrome_profile(clock: FixedClock) -> None:
    issuer = make_issuer(clock, signer=SigningKey.generate("ES256", kid="k1"))
    evt = issuer.issue(issuer.parse_request(**Browser(clock).request()))
    assert decode_json_segment(evt.split(".")[0])["alg"] == "ES256"


def test_success_response(clock: FixedClock) -> None:
    response = Issuer.success_response("a.b.c~")
    assert response.status == 200
    assert response.headers["Content-Type"] == "application/json"
    assert response.headers["Cache-Control"] == "no-store"
    assert json.loads(response.body) == {"issuance_token": "a.b.c~"}


# --- documents ---


def test_documents_pass_discovery_and_diagnostics(clock: FixedClock) -> None:
    retired = SigningKey.generate("ES256", kid="2026-04")
    issuer = make_issuer(clock, published_keys=[retired.public_jwk])
    metadata = discovery.validate_metadata(issuer.metadata_document(), ISSUER)
    assert metadata.issuance_endpoint == ENDPOINT
    keys = discovery.validate_jwks(issuer.jwks_document())
    assert [k["kid"] for k in keys] == ["2026-10", "2026-04"]
    assert all("d" not in k and k["key_ops"] == ["verify"] for k in keys)
    assert issuer.dns_txt_records() == {"_email-verification.example.com": "iss=issuer.example"}
    assert issuer.metadata_document()["private_email_supported"] is False

    records = {name: [value] for name, value in issuer.dns_txt_records().items()}
    documents: dict[str, object] = {
        f"{ISSUER}/.well-known/email-verification": issuer.metadata_document(),
        JWKS_URI: issuer.jwks_document(),
    }
    report = discover(
        "example.com",
        resolver=InMemoryDns(records),
        fetcher=InMemoryHttp(documents),
        profile=Profile.draft_hardt_02(),
    )
    assert report.ok, report


def test_document_responses_are_publicly_cacheable(clock: FixedClock) -> None:
    issuer = make_issuer(clock)
    for response, document in (
        (issuer.metadata_response(), issuer.metadata_document()),
        (issuer.jwks_response(), issuer.jwks_document()),
    ):
        assert response.status == 200
        assert response.headers == {
            "Content-Type": "application/json",
            "Cache-Control": "public, max-age=300",
        }
        assert json.loads(response.body) == document


def test_rotation_old_tokens_still_verify(clock: FixedClock) -> None:
    old = SigningKey.generate(kid="old")
    browser = Browser(clock)
    before = make_issuer(clock, signer=old)
    evt = before.issue(before.parse_request(**browser.request()))
    after = make_issuer(
        clock, signer=SigningKey.generate(kid="new"), published_keys=[old.public_jwk]
    )
    verifier_for(after, clock).verify(present(evt, browser), nonce="n-1", email=None)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"issuer": "https://issuer.example/"}, "issuer"),
        ({"issuer": "issuer.example"}, "issuer"),
        ({"issuer": "https://issuer.example:8443"}, "issuer"),
        ({"issuance_endpoint": "http://accounts.issuer.example/x"}, "issuance_endpoint"),
        ({"jwks_uri": "https://accounts.issuer.example/jwks?x=1"}, "jwks_uri"),
        ({"email_domains": []}, "email_domains"),
        ({"signing_alg_values_supported": ["EdDSA"]}, "signing_alg_values_supported"),
        ({"signing_alg_values_supported": ["ES256"]}, "signing_alg_values_supported"),
        ({"published_keys": [{"kty": "OKP"}]}, "kid"),
    ],
)
def test_invalid_configuration(clock: FixedClock, kwargs: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        make_issuer(clock, **kwargs)


def test_duplicate_kid(clock: FixedClock) -> None:
    signer = SigningKey.generate(kid="same")
    other = SigningKey.generate(kid="same")
    with pytest.raises(ValueError, match="duplicate kid"):
        make_issuer(clock, signer=signer, published_keys=[other.public_jwk])


def test_signing_key_round_trips_through_jwk() -> None:
    key = SigningKey.generate("ES256", kid="k")
    loaded = SigningKey.from_jwk(key.private_jwk())
    assert loaded.public_jwk == key.public_jwk
    assert key.private_jwk()["d"] not in repr(loaded)


@pytest.mark.parametrize(
    ("key", "alg"),
    [
        (ed25519.Ed25519PrivateKey.generate(), "Ed25519"),
        (ec.generate_private_key(ec.SECP256R1()), "ES256"),
    ],
)
def test_signing_key_from_pem(key: Any, alg: str) -> None:
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    loaded = SigningKey.from_pem(pem.decode(), kid="k")
    assert (loaded.alg, loaded.kid) == (alg, "k")
    assert loaded.public_jwk == public_jwk(
        OKPKey.import_key(key.public_key()).as_dict()
        if alg == "Ed25519"
        else ECKey.import_key(key.public_key()).as_dict(),
        kid="k",
        alg=alg,
    )


@pytest.mark.parametrize(
    ("pem", "message"),
    [
        (
            ec.generate_private_key(ec.SECP384R1()).private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            ),
            "P-384",
        ),
        (
            rsa.generate_private_key(65537, 2048).private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            ),
            "not an Ed25519 or P-256 private key",
        ),
        (
            ed25519.Ed25519PrivateKey.generate()
            .public_key()
            .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
            "not an Ed25519 or P-256 private key",
        ),
    ],
)
def test_signing_key_from_pem_rejects(pem: bytes, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        SigningKey.from_pem(pem, kid="k")


@pytest.mark.parametrize("alg", ["Ed25519", "ES256"])
def test_signing_key_rejects_a_foreign_public_key(alg: str) -> None:
    jwk = SigningKey.generate(alg, kid="k").private_jwk()
    other = SigningKey.generate(alg, kid="k").public_jwk
    jwk.update({m: other[m] for m in ("x", "y") if m in other})
    with pytest.raises(ValueError, match="invalid private key"):
        SigningKey.from_jwk(jwk)


@pytest.mark.parametrize("alg", ["Ed25519", "ES256"])
def test_loaded_signing_key_signs_for_its_public_key(clock: FixedClock, alg: str) -> None:
    signer = SigningKey.from_jwk(SigningKey.generate(alg, kid="k").private_jwk())
    issuer = make_issuer(clock, signer=signer)
    evt = issuer.issue(issuer.parse_request(**Browser(clock).request())).removesuffix("~")
    header_alg = decode_json_segment(evt.split(".")[0])["alg"]
    assert _jose.verify_compact(evt, dict(signer.public_jwk), header_alg)


@pytest.mark.parametrize(
    "jwk",
    [
        {"kty": "OKP", "crv": "Ed25519", "x": "AAAA"},
        {"kty": "OKP", "crv": "Ed448", "d": "AAAA", "x": "AAAA", "kid": "k"},
        {"kty": "OKP", "crv": "Ed25519", "d": "AAAA", "x": "AAAA", "kid": "k", "alg": "EdDSA"},
        {"kty": "OKP", "crv": "Ed25519", "x": "AAAA", "kid": "k"},
        {"kty": "OKP", "crv": "Ed25519", "d": "!!", "x": "AAAA", "kid": "k"},
    ],
)
def test_signing_key_rejects(jwk: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=r"kid|algorithm|private|invalid"):
        SigningKey.from_jwk(jwk)


# --- request validation ---


def test_wrong_method(clock: FixedClock) -> None:
    request = Browser(clock).request()
    assert error(make_issuer(clock), {**request, "method": "GET"}).code == "invalid_request"


def signed(clock: FixedClock, raw: bytes, **kw: Any) -> dict[str, Any]:
    """A signed request carrying ``raw`` exactly."""
    browser = Browser(clock)
    headers = _httpsig.sign_request(
        method="POST",
        endpoint=ENDPOINT,
        body=raw,
        private_key=browser.key,
        public_jwk=browser.key.as_dict(private=False),
        alg="Ed25519",
        created=clock(),
        **kw,
    )
    return {"method": "POST", "headers": headers, "body": raw}


@pytest.mark.parametrize("length", ["16385", "1" * 5000, "-1", "16 384", "١٢", "0x10"])
def test_bad_content_length_is_refused_before_the_signature(clock: FixedClock, length: str) -> None:
    # No signature at all: the size check comes first, so this is not invalid_signature.
    request = {"method": "POST", "headers": {"Content-Length": length}, "body": b""}
    assert error(make_issuer(clock), request).code == "invalid_request"


def test_repeated_content_length_is_refused(clock: FixedClock) -> None:
    request = Browser(clock).request()
    headers = [*request["headers"].items(), ("Content-Length", "26"), ("Content-Length", "26")]
    assert error(make_issuer(clock), {**request, "headers": headers}).code == "invalid_request"


def test_oversized_body_is_refused_before_content_type(clock: FixedClock) -> None:
    request = {"method": "POST", "headers": {}, "body": b"x" * (MAX_REQUEST_BODY + 1)}
    assert error(make_issuer(clock), request).code == "invalid_request"


def test_body_of_the_maximum_size_is_accepted(clock: FixedClock) -> None:
    raw = b'{"email": "alice@example.com"}'
    raw = raw[:-1] + b" " * (MAX_REQUEST_BODY - len(raw)) + b"}"
    request = signed(clock, raw)
    request["headers"]["Content-Length"] = str(len(raw))
    assert make_issuer(clock).parse_request(**request).email == "alice@example.com"


@pytest.mark.parametrize(
    "content_type", [None, "application/x-www-form-urlencoded", "text/plain", "application/jsonx"]
)
def test_content_type(clock: FixedClock, content_type: str | None) -> None:
    request = Browser(clock).request()
    headers = {k: v for k, v in request["headers"].items() if k != "Content-Type"}
    if content_type is not None:
        headers["Content-Type"] = content_type
    exc = error(make_issuer(clock), {**request, "headers": headers})
    assert exc.code == IssuanceErrorCode.UNSUPPORTED_MEDIA_TYPE
    assert exc.to_response().status == 415


def test_content_type_parameters_are_ignored(clock: FixedClock) -> None:
    request = Browser(clock).request()
    request["headers"]["Content-Type"] = "Application/JSON; charset=utf-8"
    make_issuer(clock).parse_request(**request)


def test_legacy_request_token_is_refused(clock: FixedClock) -> None:
    exc = error(
        make_issuer(clock),
        {
            "method": "POST",
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded",
                "Sec-Fetch-Dest": "email-verification",
            },
            "body": b"request_token=eyJ.eyJ.sig",
        },
    )
    assert exc.status == 415


@pytest.mark.parametrize("value", [None, "empty", "document"])
def test_sec_fetch_dest(clock: FixedClock, value: str | None) -> None:
    request = Browser(clock).request()
    del request["headers"]["Sec-Fetch-Dest"]
    if value is not None:
        request["headers"]["Sec-Fetch-Dest"] = value
    exc = error(make_issuer(clock), request)
    assert exc.code == "invalid_request"
    assert exc.to_response().status == 400


def test_bad_signature_sets_signature_error(clock: FixedClock) -> None:
    request = Browser(clock).request()
    request["body"] = json.dumps({"email": "mallory@example.com"}).encode()
    exc = error(make_issuer(clock), request)
    assert exc.code == "invalid_signature"
    response = exc.to_response()
    assert response.status == 400
    assert response.headers["Signature-Error"] == "error=invalid_signature"
    assert json.loads(response.body) == {
        "error": "invalid_signature",
        "error_description": "HTTP Message Signature verification failed",
    }


@pytest.mark.parametrize("created", ["999999999999999", "-999999999999999"])
def test_unrepresentable_created(clock: FixedClock, created: str) -> None:
    request = Browser(clock).request()
    headers = request["headers"]
    headers["Signature-Input"] = re.sub(
        r"created=\d+", f"created={created}", headers["Signature-Input"]
    )
    exc = error(make_issuer(clock), request)
    assert exc.code == "invalid_signature"
    assert exc.signature_error == "invalid_signature"


def _pairs(headers: dict[str, str]) -> Iterator[tuple[str, str]]:
    yield from headers.items()


@pytest.mark.parametrize("wrap", [lambda h: iter(h.items()), _pairs, lambda h: list(h.items())])
def test_headers_may_be_any_iterable(clock: FixedClock, wrap: Any) -> None:
    issuer = make_issuer(clock)
    browser = Browser(clock)
    request = browser.request()
    issuer.parse_request(**{**request, "headers": wrap(request["headers"])})

    async def main() -> None:
        await issuer.aparse_request(**{**request, "headers": wrap(request["headers"])})

    anyio.run(main)


def test_stale_request(clock: FixedClock) -> None:
    request = Browser(clock).request()
    clock.advance(timedelta(seconds=301))
    assert error(make_issuer(clock), request).code == "invalid_signature"


def test_draft_profile_requires_hwk_alg(clock: FixedClock) -> None:
    issuer = make_issuer(clock, profile=IssuanceProfile.draft_hardt_02())
    exc = error(issuer, Browser(clock).request())
    assert exc.signature_error == "invalid_key"
    issuer.parse_request(**Browser(clock).request(include_alg=True))


def test_request_alg_limited_by_metadata(clock: FixedClock) -> None:
    issuer = make_issuer(clock, signing_alg_values_supported=["Ed25519"])
    exc = error(issuer, Browser(clock, "ES256").request())
    assert exc.signature_error == "unsupported_algorithm"


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"email": 1},
        {"email": "not an email"},
        {"email": "alice@exämple.com"},
        {"email": "alice@example.com", "private_email": "yes"},
        {"email": "alice@example.com", "directed_email": 1},
        ["alice@example.com"],
    ],
)
def test_invalid_body(clock: FixedClock, body: Any) -> None:
    exc = error(make_issuer(clock), Browser(clock).request(body=body))
    assert exc.code == "invalid_request"


@pytest.mark.parametrize(
    "raw",
    [
        b'{"email": "alice@example.com", "email": "bob@example.com"}',
        b'{"email": "\\ud800@example.com"}',
        b"\xff",
        b"[" * 10_000,
    ],
)
def test_malformed_json(clock: FixedClock, raw: bytes) -> None:
    assert error(make_issuer(clock), signed(clock, raw)).code == "invalid_request"


@pytest.mark.parametrize(
    "body",
    [
        {"email": "alice@example.com", "private_email": True},
        {"email": "alice@example.com", "directed_email": "x@relay.example"},
    ],
)
def test_private_email_not_supported(clock: FixedClock, body: dict[str, Any]) -> None:
    exc = error(make_issuer(clock), Browser(clock).request(body=body))
    assert exc.code == "private_email_not_supported"
    assert exc.to_response().status == 400


def test_private_email_false_is_fine(clock: FixedClock) -> None:
    body = {"email": "alice@example.com", "private_email": False}
    make_issuer(clock).parse_request(**Browser(clock).request(body=body))


def test_foreign_domain_looks_like_an_unknown_account(clock: FixedClock) -> None:
    issuer = make_issuer(clock)
    foreign = error(issuer, Browser(clock).request("alice@other.example")).to_response()
    unknown = IssuanceError.authentication_required("no session").to_response()
    assert foreign == unknown
    assert unknown.status == 401


def test_domains_compare_case_insensitively(clock: FixedClock) -> None:
    issuer = make_issuer(clock, email_domains=["Example.COM"])
    assert issuer.parse_request(**Browser(clock).request("a@EXAMPLE.com")).email == "a@EXAMPLE.com"


_INVALID_DOMAINS = [
    "bad domain.example",
    "broken..example",
    "example.com..",
    "-dash.example",
    "a@b.example",
    "xn--a.example",
    ("a" * 63 + ".") * 4 + "example",
    "",
    None,
    3,
]


@pytest.mark.parametrize("name", ["ü..example", *_INVALID_DOMAINS])
def test_invalid_domains_are_refused(clock: FixedClock, name: str) -> None:
    with pytest.raises(ValueError):  # noqa: PT011
        make_issuer(clock, email_domains=["example.com", name])


def test_domains_are_stored_as_a_labels(clock: FixedClock) -> None:
    issuer = make_issuer(clock, email_domains=["Bücher.example.", "xn--bcher-kva.example"])
    assert issuer.email_domains == {"xn--bcher-kva.example"}


def test_domains_from_a_callable_follow_changes(
    clock: FixedClock, caplog: pytest.LogCaptureFixture
) -> None:
    domains: list[Any] = []  # data from a database is not always a str
    issuer = make_issuer(clock, email_domains=lambda: domains)
    assert issuer.dns_txt_records() == {}
    assert error(issuer, Browser(clock).request()).code is IssuanceErrorCode.AUTHENTICATION_REQUIRED

    domains[:] = ["Example.COM", "bücher.example", "ü..example", *_INVALID_DOMAINS]
    assert issuer.email_domains == {"example.com", "xn--bcher-kva.example"}
    for name in ["ü..example", *_INVALID_DOMAINS]:
        assert repr(name) in caplog.text
    assert issuer.parse_request(**Browser(clock).request()).email == "alice@example.com"
    assert set(issuer.dns_txt_records()) == {
        "_email-verification.example.com",
        "_email-verification.xn--bcher-kva.example",
    }


@pytest.mark.parametrize(
    ("value", "valid"),
    [
        ("a@b", True),
        ("a.b+c@sub.example.com", True),
        ("a@-b.example", False),
        ("a@b-.example", False),
        ("a@@b", False),
        ("a b@c", False),
        ("a@" + "b" * 64, False),
        ("ä@b", False),
        ("a@b\n", False),
    ],
)
def test_is_valid_email(value: str, valid: bool) -> None:
    assert is_valid_email(value) is valid


# --- replay and observability ---


def test_replay_guard(clock: FixedClock) -> None:
    issuer = make_issuer(clock, replay_guard=InMemoryReplayGuard(clock=clock))
    request = Browser(clock).request()
    issuer.parse_request(**request)
    assert error(issuer, request).code == "invalid_signature"


# The order of the P-256 group; (r, n - s) is as valid as (r, s).
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _malleated(request: dict[str, Any]) -> dict[str, Any]:
    headers = dict(request["headers"])
    ((label, item),) = _sf.parse_dictionary(headers["Signature"]).items()
    assert isinstance(item, _sf.Item)
    assert isinstance(item.value, bytes)
    r, s = item.value[:32], int.from_bytes(item.value[32:])
    twin = r + (P256_N - s).to_bytes(32)
    headers["Signature"] = _sf.serialize_dictionary({label: _sf.Item(twin)})
    assert headers["Signature"] != request["headers"]["Signature"]
    return {**request, "headers": headers}


def test_replay_guard_survives_signature_malleability(clock: FixedClock) -> None:
    request = Browser(clock, "ES256").request()
    twin = _malleated(request)
    make_issuer(clock).parse_request(**twin)  # a valid signature in its own right

    issuer = make_issuer(clock, replay_guard=InMemoryReplayGuard(clock=clock))
    issuer.parse_request(**request)
    assert error(issuer, twin).code == "invalid_signature"

    async def main() -> None:
        issuer = make_issuer(clock, replay_guard=InMemoryReplayGuard(clock=clock))
        await issuer.aparse_request(**twin)
        with pytest.raises(IssuanceError, match="already used"):
            await issuer.aparse_request(**request)

    anyio.run(main)


def test_async_replay_guard(clock: FixedClock) -> None:
    class AsyncGuard:
        def __init__(self) -> None:
            self.inner = InMemoryReplayGuard(clock=clock)

        async def mark_used(self, key: str, expires_at: Any) -> bool:
            return self.inner.mark_used(key, expires_at)

    issuer = make_issuer(clock, replay_guard=AsyncGuard())
    request = Browser(clock).request()
    with pytest.raises(TypeError):
        issuer.parse_request(**request)

    async def main() -> None:
        await issuer.aparse_request(**request)
        with pytest.raises(IssuanceError):
            await issuer.aparse_request(**request)

    anyio.run(main)


def test_request_expiring_in_the_replay_guard_is_refused(clock: FixedClock) -> None:
    # A store that forgets expired keys cannot catch a copy that arrives after the
    # deadline, so a request that outlives it while being marked is refused.
    late = timedelta(seconds=302)  # past max_request_age (300 s) plus the 1 s margin

    class SlowGuard:
        def __init__(self) -> None:
            self.inner = InMemoryReplayGuard(clock=clock)

        def mark_used(self, key: str, expires_at: Any) -> bool:
            clock.advance(late)
            return self.inner.mark_used(key, expires_at)

    issuer = make_issuer(clock, replay_guard=SlowGuard())
    with pytest.raises(IssuanceError, match="expired during validation"):
        issuer.parse_request(**Browser(clock).request())


def test_signature_expires_sets_the_deadline(clock: FixedClock) -> None:
    # Fresh by max_request_age, but past the signature's own expires once marked.
    class SlowGuard:
        def __init__(self) -> None:
            self.inner = InMemoryReplayGuard(clock=clock)
            self.expires_at: Any = None

        def mark_used(self, key: str, expires_at: Any) -> bool:
            self.expires_at = expires_at
            clock.advance(timedelta(seconds=12))
            return self.inner.mark_used(key, expires_at)

    guard = SlowGuard()
    issuer = make_issuer(clock, replay_guard=guard)
    request = Browser(clock).request(expires=clock() + timedelta(seconds=10))
    with pytest.raises(IssuanceError, match="expired during validation"):
        issuer.parse_request(**request)
    assert guard.expires_at == clock() - timedelta(seconds=1)


def test_concurrent_copies_crossing_the_deadline_are_refused(clock: FixedClock) -> None:
    inner = InMemoryReplayGuard(clock=clock)
    arrived = 0
    both_in = anyio.Event()

    class SlowGuard:
        async def mark_used(self, key: str, expires_at: Any) -> bool:
            nonlocal arrived
            arrived += 1
            if arrived == 2:
                clock.advance(timedelta(seconds=302))
                both_in.set()
            await both_in.wait()
            return inner.mark_used(key, expires_at)

    issuer = make_issuer(clock, replay_guard=SlowGuard())
    request = Browser(clock).request()
    outcomes: list[str] = []

    async def attempt() -> None:
        try:
            await issuer.aparse_request(**request)
        except IssuanceError as exc:
            outcomes.append(str(exc))
        else:
            outcomes.append("accepted")

    async def main() -> None:
        async with anyio.create_task_group() as tg:
            tg.start_soon(attempt)
            tg.start_soon(attempt)

    anyio.run(main)
    assert len(outcomes) == 2
    assert "accepted" not in outcomes


def test_observer(clock: FixedClock) -> None:
    events: list[IssuanceEvent] = []
    issuer = make_issuer(clock, observer=events.append)
    browser = Browser(clock)
    issuer.issue(issuer.parse_request(**browser.request()))
    request = browser.request()
    request["method"] = "GET"
    with pytest.raises(IssuanceError):
        issuer.parse_request(**request)
    assert events == [
        IssuanceEvent(True, "request", None, "example.com"),
        IssuanceEvent(True, "issue", None, "example.com"),
        IssuanceEvent(
            False, "request", IssuanceErrorCode.INVALID_REQUEST, None, "method GET not allowed"
        ),
    ]


def test_refusals_are_logged_without_the_address(
    clock: FixedClock, caplog: pytest.LogCaptureFixture
) -> None:
    events: list[IssuanceEvent] = []
    issuer = make_issuer(clock, observer=events.append)
    with caplog.at_level("DEBUG", logger="pyevp"):
        error(issuer, Browser(clock).request("alice@elsewhere.example"))
    assert events[-1].detail == "email domain not served"
    assert "email domain not served" in caplog.text
    assert "alice" not in caplog.text


def test_observer_reports_replays(clock: FixedClock) -> None:
    events: list[IssuanceEvent] = []
    request = Browser(clock).request()
    expected = [
        IssuanceEvent(True, "request", None, "example.com"),
        IssuanceEvent(
            False, "request", IssuanceErrorCode.INVALID_SIGNATURE, None, "request was already used"
        ),
    ]
    guard = InMemoryReplayGuard(clock=clock)
    issuer = make_issuer(clock, observer=events.append, replay_guard=guard)
    issuer.parse_request(**request)
    error(issuer, request)
    assert events == expected

    async def main() -> None:
        events.clear()
        guard = InMemoryReplayGuard(clock=clock)
        issuer = make_issuer(clock, observer=events.append, replay_guard=guard)
        await issuer.aparse_request(**request)
        with pytest.raises(IssuanceError):
            await issuer.aparse_request(**request)

    anyio.run(main)
    assert events == expected


def test_observer_errors_are_swallowed(clock: FixedClock) -> None:
    def broken(event: IssuanceEvent) -> None:
        raise RuntimeError("boom")

    issuer = make_issuer(clock, observer=broken)
    issuer.parse_request(**Browser(clock).request())


def test_issued_token_does_not_verify_for_another_key(clock: FixedClock) -> None:
    issuer = make_issuer(clock)
    browser = Browser(clock)
    evt = issuer.issue(issuer.parse_request(**browser.request()))
    with pytest.raises(EVPError):
        verifier_for(issuer, clock).verify(present(evt, Browser(clock)), nonce="n-1", email=None)


def test_request_repr_hides_signature(clock: FixedClock) -> None:
    request = make_issuer(clock).parse_request(**Browser(clock).request())
    assert isinstance(request, IssuanceRequest)
    assert "signature" not in repr(request)


@pytest.mark.parametrize("alg", ["Ed25519", "EdDSA", "ES256"])
def test_fake_browser_issuance_request(clock: FixedClock, alg: Any) -> None:
    issuer = make_issuer(clock)
    browser = FakeBrowser(alg=alg, clock=clock)
    request = issuer.parse_request(**browser.issuance_request("bob@example.com", endpoint=ENDPOINT))
    evt = issuer.issue(request)
    token = browser.present(evt, audience=RP, nonce="n-1")
    assert (
        verifier_for(issuer, clock).verify(token, nonce="n-1", email=None).email
        == "bob@example.com"
    )
    strict = make_issuer(clock, profile=IssuanceProfile.draft_hardt_02())
    strict.parse_request(
        **browser.issuance_request("bob@example.com", endpoint=ENDPOINT, include_alg=True)
    )
    with pytest.raises(IssuanceError):
        issuer.parse_request(
            **browser.issuance_request(
                "bob@example.com", endpoint=ENDPOINT, extra={"private_email": True}
            )
        )


def test_fedcm_documents() -> None:
    assert web_identity_document(
        accounts_endpoint="https://issuer.example/fedcm/accounts",
        login_url="https://issuer.example/login",
    ) == {
        "accounts_endpoint": "https://issuer.example/fedcm/accounts",
        "login_url": "https://issuer.example/login",
    }
    assert accounts_document(["a@example.com"]) == {
        "accounts": [{"id": "a@example.com", "email": "a@example.com", "name": "a@example.com"}]
    }
    response = web_identity_response(
        accounts_endpoint="https://issuer.example/fedcm/accounts",
        login_url="https://issuer.example/login",
    )
    assert response.headers["Cache-Control"] == "public, max-age=300"
    assert json.loads(response.body)["login_url"] == "https://issuer.example/login"


# --- issuance_response ---


def test_issuance_response_issues_for_the_users_address(clock: FixedClock) -> None:
    issuer = make_issuer(clock)
    browser = Browser(clock)
    evt = token(respond(issuer, browser.request()))
    result = verifier_for(issuer, clock).verify(present(evt, browser), nonce="n-1", email=None)
    assert result.email == "alice@example.com"


@pytest.mark.parametrize("emails", [["Alice@Example.COM"], lambda: iter(["alice@example.com"])])
def test_addresses_compare_case_insensitively(clock: FixedClock, emails: Any) -> None:
    request = Browser(clock).request("ALICE@example.com")
    evt = token(respond(make_issuer(clock), request, emails))
    # The EVT asserts the address as requested.
    assert json.loads(_jose.b64url_decode(evt.split(".")[1]))["email"] == "ALICE@example.com"


@pytest.mark.parametrize(
    "emails",
    [
        [],
        ["bob@example.com"],
        ["\u212aate@example.com"],  # KELVIN SIGN lowercases to "kate@example.com"
        [None, 1, b"kate@example.com"],
    ],
)
def test_other_and_unusable_addresses_are_refused(clock: FixedClock, emails: Any) -> None:
    request = Browser(clock).request("kate@example.com")
    assert refusal(respond(make_issuer(clock), request, emails)) == "authentication_required"


def test_user_addresses_need_a_label_domains(clock: FixedClock) -> None:
    issuer = make_issuer(clock, email_domains=["exämple.com"])
    request = Browser(clock).request("kate@xn--exmple-cua.com")
    assert refusal(respond(issuer, request, ["kate@exämple.com"])) == "authentication_required"
    token(respond(issuer, request, ["kate@xn--exmple-cua.com"]))


@pytest.mark.parametrize("emails", ["alice@example.com", lambda: "alice@example.com"])
def test_a_single_string_is_a_type_error(clock: FixedClock, emails: Any) -> None:
    with pytest.raises(TypeError, match="not one string"):
        respond(make_issuer(clock), Browser(clock).request(), emails)


def test_refusals_cannot_tell_accounts_apart(clock: FixedClock) -> None:
    issuer = make_issuer(clock)
    browser = Browser(clock)
    responses = [
        respond(issuer, browser.request(), []),
        respond(issuer, browser.request(), ["bob@example.com"]),
        respond(issuer, browser.request("alice@elsewhere.example"), ["alice@elsewhere.example"]),
    ]
    assert responses[0].status == 401
    assert all(r == responses[0] for r in responses)


def test_user_emails_are_looked_up_once_and_only_for_valid_requests(clock: FixedClock) -> None:
    calls = 0

    def emails() -> list[str]:
        nonlocal calls
        calls += 1
        return ["alice@example.com"]

    issuer = make_issuer(clock)
    browser = Browser(clock)
    respond(issuer, {**browser.request(), "method": "GET"}, emails)
    respond(issuer, browser.request("alice@elsewhere.example"), emails)
    assert calls == 0
    token(respond(issuer, browser.request(), emails))
    assert calls == 1


def test_wrong_method_is_an_evp_error(clock: FixedClock) -> None:
    response = respond(make_issuer(clock), {**Browser(clock).request(), "method": "GET"})
    assert response.status == 400
    assert refusal(response) == "invalid_request"


def test_async_user_emails(clock: FixedClock) -> None:
    async def emails() -> list[str]:
        return ["alice@example.com"]

    issuer = make_issuer(clock)
    browser = Browser(clock)
    with pytest.raises(TypeError, match="aissuance_response"):
        respond(issuer, browser.request(), emails)

    async def main() -> None:
        token(await issuer.aissuance_response(**browser.request(), user_emails=emails))
        response = await issuer.aissuance_response(**browser.request(), user_emails=[])
        assert refusal(response) == "authentication_required"

    anyio.run(main)


def test_async_replay_guard_needs_aissuance_response(clock: FixedClock) -> None:
    class AsyncGuard:
        def __init__(self) -> None:
            self.inner = InMemoryReplayGuard(clock=clock)

        async def mark_used(self, key: str, expires_at: Any) -> bool:
            return self.inner.mark_used(key, expires_at)

    issuer = make_issuer(clock, replay_guard=AsyncGuard())
    request = Browser(clock).request()
    with pytest.raises(TypeError, match="aissuance_response"):
        respond(issuer, request)

    async def main() -> None:
        token(await issuer.aissuance_response(**request, user_emails=["alice@example.com"]))
        replayed = await issuer.aissuance_response(**request, user_emails=["alice@example.com"])
        assert refusal(replayed) == "invalid_signature"

    anyio.run(main)


def test_refused_ownership_does_not_use_up_the_request(clock: FixedClock) -> None:
    issuer = make_issuer(clock, replay_guard=InMemoryReplayGuard(clock=clock))
    request = Browser(clock).request()
    assert refusal(respond(issuer, request, [])) == "authentication_required"
    token(respond(issuer, request))  # signed in now
    replayed = respond(issuer, request)
    assert refusal(replayed) == "invalid_signature"
    assert replayed.headers["Signature-Error"] == "error=invalid_signature"


def test_issuance_response_events(clock: FixedClock) -> None:
    events: list[IssuanceEvent] = []
    issuer = make_issuer(clock, observer=events.append)
    browser = Browser(clock)
    respond(issuer, browser.request())
    respond(issuer, browser.request(), [])
    respond(issuer, browser.request(), ["bob@example.com"])
    respond(issuer, {**browser.request(), "method": "GET"})
    code = IssuanceErrorCode
    assert events == [
        IssuanceEvent(True, "issue", None, "example.com"),
        IssuanceEvent(
            False, "ownership", code.AUTHENTICATION_REQUIRED, "example.com", "no addresses"
        ),
        IssuanceEvent(
            False,
            "ownership",
            code.AUTHENTICATION_REQUIRED,
            "example.com",
            "address not the user's",
        ),
        IssuanceEvent(False, "request", code.INVALID_REQUEST, None, "method GET not allowed"),
    ]
