from __future__ import annotations

import json

import pytest

from pyevp import ErrorCode, TokenError, _jose
from pyevp.testing import FakeBrowser, FakeIssuer
from pyevp.token import compute_sd_hash, parse_token, sign_jwt


def test_parse_roundtrip(token: str) -> None:
    parsed = parse_token(token)
    assert parsed.evt.typ == "evt+jwt"
    assert parsed.kb.typ == "kb+jwt"
    assert parsed.disclosures == ()
    assert parsed.sd_hash_input == token.split("~", maxsplit=1)[0] + "~"
    assert parsed.kb.claims["sd_hash"] == compute_sd_hash(parsed.sd_hash_input)


def test_surrounding_whitespace_is_ignored(token: str) -> None:
    assert parse_token(f"  {token}\n").raw == token


@pytest.mark.parametrize(
    "value",
    [
        "",
        "a.b.c",
        "a.b.c~",
        "~a.b.c",
        "not-a-jwt~a.b.c",
        "a.b~a.b.c",
        "x" * 20_000,
        "é.b.c~a.b.c",
    ],
)
def test_malformed(value: str) -> None:
    with pytest.raises(TokenError) as exc:
        parse_token(value)
    assert exc.value.code is ErrorCode.MALFORMED_TOKEN


def test_excessive_nesting(token: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # Python 3.11 raises RecursionError for ~1000 levels, which fit in a token. Newer versions
    # only fail far deeper than MAX_TOKEN_LENGTH allows, so simulate the failure.
    def loads(_: bytes) -> object:
        raise RecursionError

    monkeypatch.setattr(_jose.json, "loads", loads)
    with pytest.raises(TokenError) as exc:
        parse_token(token)
    assert exc.value.code is ErrorCode.MALFORMED_TOKEN


def test_disclosures_rejected_by_default(token: str) -> None:
    evt, kb = token.split("~")
    with pytest.raises(TokenError):
        parse_token(f"{evt}~WyJzYWx0Il0~{kb}")


def test_disclosures_allowed(token: str) -> None:
    evt, kb = token.split("~")
    parsed = parse_token(f"{evt}~WyJzYWx0Il0~{kb}", allow_disclosures=True)
    assert parsed.disclosures == ("WyJzYWx0Il0",)
    assert parsed.sd_hash_input == f"{evt}~WyJzYWx0Il0~"


def test_presenting_an_issuance_token_with_its_tilde(
    issuer: FakeIssuer, browser: FakeBrowser, nonce: str
) -> None:
    evt = issuer.issue("alice@example.com", browser.public_jwk)
    with_tilde = browser.present(evt + "~", audience="https://rp.example", nonce=nonce)
    without = browser.present(evt, audience="https://rp.example", nonce=nonce)
    assert with_tilde == without
    assert parse_token(with_tilde).disclosures == ()


def _with_header(compact: str, **changes: object) -> str:
    header, payload, signature = compact.split(".")
    new = {**_jose.decode_json_segment(header), **changes}
    return ".".join((_jose.b64url_encode(json.dumps(new).encode()), payload, signature))


@pytest.mark.parametrize("part", ["evt", "kb"])
@pytest.mark.parametrize("b64", [False, "false", None])
def test_unencoded_payload_is_rejected(token: str, part: str, b64: object) -> None:
    evt, kb = token.split("~")
    if part == "evt":
        evt = _with_header(evt, b64=b64, crit=["b64"])
    else:
        kb = _with_header(kb, b64=b64, crit=["b64"])
    with pytest.raises(TokenError, match="unencoded payload") as exc:
        parse_token(f"{evt}~{kb}")
    assert exc.value.code is ErrorCode.MALFORMED_TOKEN


def test_explicit_b64_true_is_accepted(token: str) -> None:
    evt, kb = token.split("~")
    assert parse_token(f"{_with_header(evt, b64=True)}~{kb}").evt.header["b64"] is True


def test_sign_jwt_refuses_an_alg_that_is_not_a_string() -> None:
    with pytest.raises(TypeError, match="header alg must be a string"):
        sign_jwt({"alg": ["ES256"]}, {}, None)
