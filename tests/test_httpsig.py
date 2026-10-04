from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from joserfc.jwk import ECKey, OKPKey

from pyevp import _httpsig, _jose, _sf

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
ENDPOINT = "https://accounts.issuer.example/email-verification/issuance"
BODY = json.dumps({"email": "alice@example.com"}).encode()
ALGS = frozenset({"Ed25519", "ES256"})


def _key(alg: str) -> Any:
    if alg == "ES256":
        return ECKey.generate_key("P-256", private=True)
    return OKPKey.generate_key("Ed25519", private=True)


def _sign(alg: str = "Ed25519", **kwargs: Any) -> dict[str, str]:
    key = kwargs.pop("key", None) or _key(alg)
    options: dict[str, Any] = {
        "method": "POST",
        "endpoint": ENDPOINT,
        "body": BODY,
        "private_key": key,
        "public_jwk": key.as_dict(private=False),
        "alg": alg,
        "created": NOW,
    }
    options.update(kwargs)
    return _httpsig.sign_request(**options)


def _verify(headers: Any, **kwargs: Any) -> _httpsig.SignedRequest:
    options: dict[str, Any] = {
        "method": "POST",
        "endpoint": ENDPOINT,
        "headers": headers,
        "body": BODY,
        "now": NOW,
        "max_age": timedelta(seconds=300),
        "algorithms": ALGS,
        "require_key_alg": True,
    }
    options.update(kwargs)
    return _httpsig.verify_request(**options)


def _code(headers: Any, **kwargs: Any) -> str:
    with pytest.raises(_httpsig.SignatureError) as info:
        _verify(headers, **kwargs)
    return info.value.code


@pytest.mark.parametrize("alg", ["Ed25519", "ES256"])
def test_round_trip(alg: str) -> None:
    key = _key(alg)
    signed = _verify(_sign(alg, key=key))
    assert signed.alg == alg
    assert signed.label == "sig"
    assert signed.created == NOW
    assert signed.public_jwk == {**key.as_dict(private=False), "alg": alg}
    assert signed.deadline == NOW + timedelta(seconds=300)


@pytest.mark.parametrize(("expires", "deadline"), [(10, 10), (300, 300), (1000, 300)])
def test_deadline_is_the_earlier_of_max_age_and_expires(expires: int, deadline: int) -> None:
    signed = _verify(_sign(expires=NOW + timedelta(seconds=expires)))
    assert signed.deadline == NOW + timedelta(seconds=deadline)


def test_header_names_are_case_insensitive_and_pairs_are_accepted() -> None:
    pairs = [(name.lower(), value) for name, value in _sign().items()]
    assert _verify(pairs).alg == "Ed25519"


def test_key_without_alg_needs_permission() -> None:
    headers = _sign(include_alg=False)
    assert _code(headers) == "invalid_key"
    assert _verify(headers, require_key_alg=False).public_jwk["alg"] == "Ed25519"


def test_rfc9421_ed25519_test_vector() -> None:
    """RFC 9421 appendix B.2.6."""
    signature_input = (
        'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length")'
        ';created=1618884473;keyid="test-key-ed25519"'
    )
    signature = (
        "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPp"
        "BKRCw==:"
    )
    components = _sf.parse_dictionary(signature_input)["sig-b26"]
    assert isinstance(components, _sf.InnerList)
    base = _httpsig._signature_base(
        components,
        method="POST",
        endpoint="https://example.com/foo",
        lines={
            "date": ["Tue, 20 Apr 2021 02:07:55 GMT"],
            "content-type": ["application/json"],
            "content-length": ["18"],
        },
        required=(),
    )
    sig = _sf.parse_dictionary(signature)["sig-b26"]
    assert isinstance(sig, _sf.Item)
    assert isinstance(sig.value, bytes)
    key = {"kty": "OKP", "crv": "Ed25519", "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}
    assert _jose.verify_raw(base, sig.value, key, "Ed25519")


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"endpoint": "https://evil.example/email-verification/issuance"}, "invalid_signature"),
        ({"endpoint": "https://accounts.issuer.example/other"}, "invalid_signature"),
        ({"method": "PUT"}, "invalid_signature"),
        ({"body": b'{"email": "mallory@example.com"}'}, "invalid_signature"),
        ({"now": NOW + timedelta(seconds=301)}, "invalid_signature"),
        ({"now": NOW - timedelta(seconds=301)}, "clock_skew"),
        ({"algorithms": frozenset({"ES256"})}, "unsupported_algorithm"),
    ],
)
def test_request_mismatch(change: dict[str, Any], code: str) -> None:
    assert _code(_sign(), **change) == code


def test_freshness_window_is_inclusive() -> None:
    headers = _sign()
    _verify(headers, now=NOW + timedelta(seconds=300))
    _verify(headers, now=NOW - timedelta(seconds=300))


@pytest.mark.parametrize("name", ["Signature", "Signature-Input", "Signature-Key"])
def test_missing_signature_header(name: str) -> None:
    headers = _sign()
    del headers[name]
    assert _code(headers) == "invalid_signature"


def test_missing_content_digest() -> None:
    headers = _sign()
    del headers["Content-Digest"]
    assert _code(headers) == "invalid_input"


def test_content_digest_is_signed() -> None:
    headers = _sign()
    headers["Content-Digest"] = _httpsig.content_digest(b"{}")
    assert _code(headers, body=b"{}") == "invalid_signature"


@pytest.mark.parametrize(
    "digest", ["sha-512=:AAAA:", 'sha-256="abc"', "sha-256=:AAAA:", "sha-256=(", ""]
)
def test_bad_content_digest_value(digest: str) -> None:
    # The signer covered the digest it sent; the body still has to match it.
    assert _code(_sign(digest=digest)) in {"invalid_request", "invalid_signature"}


def _with_input(headers: dict[str, str], value: str) -> dict[str, str]:
    return {**headers, "Signature-Input": value}


@pytest.mark.parametrize(
    "signature_input",
    [
        'sig=("@method" "@authority" "@path" "content-digest");created=1790856000',
        'sig=("@method" "@method" "@authority" "@path" "content-digest" "signature-key")'
        ";created=1790856000",
        'sig=("@method";req "@authority" "@path" "content-digest" "signature-key")'
        ";created=1790856000",
        'sig=("@query" "@method" "@authority" "@path" "content-digest" "signature-key")'
        ";created=1790856000",
        'sig=("x-missing" "@method" "@authority" "@path" "content-digest" "signature-key")'
        ";created=1790856000",
    ],
)
def test_unsupported_components(signature_input: str) -> None:
    assert _code(_with_input(_sign(), signature_input)) == "invalid_input"


@pytest.mark.parametrize(
    "signature_input",
    [
        'sig=("@method" "@authority" "@path" "content-digest" "signature-key")',
        'sig=("@method" "@authority" "@path" "content-digest" "signature-key");created="1"',
        'sig=("@method" "@authority" "@path" "content-digest" "signature-key");created=?1',
        "sig=:AAAA:",
        "sig=(",
        'other=("@method");created=1790856000',
    ],
)
def test_malformed_signature_input(signature_input: str) -> None:
    assert _code(_with_input(_sign(), signature_input)) == "invalid_signature"


def test_expires_in_the_past() -> None:
    headers = _sign()
    value = headers["Signature-Input"] + f";expires={int(NOW.timestamp()) - 1}"
    assert _code(_with_input(headers, value)) == "invalid_signature"


def test_alg_parameter_must_agree_with_the_key() -> None:
    headers = _sign()
    assert _code(_with_input(headers, headers["Signature-Input"] + ';alg="ES256"')) == (
        "invalid_signature"
    )


@pytest.mark.parametrize(
    ("signature_key", "code"),
    [
        ('sig=jwt;jwt="x"', "unsupported_scheme"),
        ('sig="hwk"', "unsupported_scheme"),
        ('sig=hwk;kty="RSA";n="x";e="AQAB"', "invalid_key"),
        ('sig=hwk;kty="OKP";crv="Ed25519"', "invalid_key"),
        ('sig=hwk;kty="OKP";crv="Ed25519";x=abc;alg="Ed25519"', "invalid_key"),
        ('sig=hwk;kty="OKP";crv="Ed25519";x="abc";alg=Ed25519', "invalid_key"),
        ('sig=hwk;kty="OKP";crv="Ed25519";x="abc";alg="EdDSA"', "unsupported_algorithm"),
        ('sig=hwk;kty="OKP";crv="Ed25519";x="abc";alg="Ed25519";kid="k"', "invalid_key"),
        ('sig=hwk;kty="OKP";crv="Ed25519";x="abc";alg="Ed25519"', "invalid_key"),
        ("sig=hwk, other=hwk", "invalid_signature"),
        ('other=hwk;kty="OKP";crv="Ed25519";x="abc";alg="Ed25519"', "invalid_signature"),
    ],
)
def test_bad_signature_key(signature_key: str, code: str) -> None:
    assert _code({**_sign(), "Signature-Key": signature_key}) == code


def test_key_must_match_the_signature() -> None:
    other = _key("Ed25519").as_dict(private=False)
    headers = _sign()
    headers["Signature-Key"] = f'sig=hwk;kty="OKP";crv="Ed25519";x="{other["x"]}";alg="Ed25519"'
    assert _code(headers) == "invalid_signature"


def test_ed25519_key_cannot_claim_es256() -> None:
    headers = _sign()
    key = headers["Signature-Key"].replace('alg="Ed25519"', 'alg="ES256"')
    assert _code({**headers, "Signature-Key": key}) == "invalid_signature"


def test_chrome_153_shape() -> None:
    """Chrome 153 sends ``crv`` before ``kty`` and no ``alg`` (2026-08 announcement)."""
    key = _key("Ed25519")
    x = key.as_dict(private=False)["x"]
    headers = _sign(key=key, signature_key=f'sig=hwk;crv="Ed25519";kty="OKP";x="{x}"')
    assert _verify(headers, require_key_alg=False).alg == "Ed25519"
