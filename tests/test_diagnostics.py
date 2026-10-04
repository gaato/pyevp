from __future__ import annotations

from typing import Any

import pytest

from pyevp import DiscoveryError, ErrorCode, EVPError, Profile, Verifier
from pyevp.diagnostics import adiscover, discover
from pyevp.testing import (
    AsyncInMemoryDns,
    AsyncInMemoryHttp,
    FakeBrowser,
    FakeIssuer,
    InMemoryDns,
    InMemoryHttp,
    SigningAlg,
)

from .conftest import AUDIENCE, EMAIL


def _ports(*issuers: FakeIssuer) -> tuple[InMemoryDns, InMemoryHttp]:
    records: dict[str, list[str]] = {}
    documents: dict[str, object] = {}
    for issuer in issuers:
        records |= issuer.dns_records()
        documents |= issuer.http_documents()
    return InMemoryDns(records), InMemoryHttp(documents)


def test_healthy_issuer(issuer: FakeIssuer) -> None:
    resolver, fetcher = _ports(issuer)
    report = discover("alice@example.com", resolver=resolver, fetcher=fetcher)
    assert report.ok
    assert report.issuer == "https://issuer.example"
    assert report.records == ("iss=issuer.example",)
    assert [k.kid for k in report.keys] == ["test-key-1"]


def test_accepts_domain_or_email(issuer: FakeIssuer) -> None:
    resolver, fetcher = _ports(issuer)
    assert discover("Example.COM", resolver=resolver, fetcher=fetcher).dns_name == (
        "_email-verification.example.com"
    )


def test_gmail_like_issuer_under_strict_profile() -> None:
    gmail = FakeIssuer.gmail_like()
    resolver, fetcher = _ports(gmail)
    compat = discover("gmail.example", resolver=resolver, fetcher=fetcher)
    strict = discover(
        "gmail.example", resolver=resolver, fetcher=fetcher, profile=Profile.draft_hardt_02()
    )
    assert compat.ok
    # "EdDSA" in the metadata is compatible with the profile's "Ed25519"; Gmail's keys
    # have no kid, though.
    assert strict.problems == ("profile draft-hardt-02 requires kid, but some keys have none",)


def test_kid_required() -> None:
    issuer = FakeIssuer(kid=None)
    resolver, fetcher = _ports(issuer)
    report = discover(
        "example.com", resolver=resolver, fetcher=fetcher, profile=Profile.draft_hardt_02()
    )
    assert report.problems == ("profile draft-hardt-02 requires kid, but some keys have none",)


@pytest.mark.parametrize(
    ("break_it", "problem"),
    [
        (lambda dns, http, i: dns.records.clear(), "expected exactly one"),
        (lambda dns, http, i: http.documents.update({i.metadata_url: {}}), "metadata:"),
        (lambda dns, http, i: http.documents.update({i.jwks_uri: {"keys": []}}), "JWKS:"),
        (
            lambda dns, http, i: http.documents.update(
                {i.jwks_uri: {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]}}
            ),
            "no key in https://issuer.example/jwks.json can verify Ed25519, EdDSA (1 malformed)",
        ),
        (
            lambda dns, http, i: http.documents[i.metadata_url].update(jwks_uri="https://["),
            "metadata: jwks_uri is not an https URL",
        ),
        (
            lambda dns, http, i: http.documents[i.metadata_url].update(
                signing_alg_values_supported=[]
            ),
            "issuer advertises an empty",
        ),
    ],
)
def test_problems(issuer: FakeIssuer, break_it, problem: str) -> None:
    resolver, fetcher = _ports(issuer)
    break_it(resolver, fetcher, issuer)
    report = discover("example.com", resolver=resolver, fetcher=fetcher)
    assert not report.ok
    assert report.problems[0].startswith(problem)


@pytest.mark.parametrize("alg", ["Ed25519", "ES256"])
def test_absent_algorithm_list_matches_the_verifier(alg: SigningAlg) -> None:
    issuer = FakeIssuer(alg=alg)
    resolver, fetcher = _ports(issuer)
    metadata = dict(issuer.metadata)
    del metadata["signing_alg_values_supported"]
    fetcher.documents[issuer.metadata_url] = metadata
    assert discover("example.com", resolver=resolver, fetcher=fetcher).ok

    browser = FakeBrowser(clock=issuer.clock)
    token = browser.present(issuer.issue(EMAIL, browser.public_jwk), audience=AUDIENCE, nonce="n")
    verifier = Verifier(audience=AUDIENCE, resolver=resolver, fetcher=fetcher, clock=issuer.clock)
    assert verifier.verify(token, nonce="n", email=None).email == EMAIL


def test_transport_failure_raises(issuer: FakeIssuer) -> None:
    resolver, _ = _ports(issuer)
    with pytest.raises(DiscoveryError) as exc:
        discover("example.com", resolver=resolver, fetcher=InMemoryHttp({}))
    assert exc.value.code is ErrorCode.ISSUER_UNREACHABLE


@pytest.mark.anyio
async def test_async(issuer: FakeIssuer) -> None:
    report = await adiscover(
        "example.com",
        resolver=AsyncInMemoryDns(issuer.dns_records()),
        fetcher=AsyncInMemoryHttp(issuer.http_documents()),
    )
    assert report.ok


@pytest.mark.parametrize(("advertised", "ok"), [(["EdDSA"], True), (["ES384"], False)])
def test_algorithm_list_matches_the_verifier(advertised: list[str], ok: bool) -> None:
    # Like the verifier, an advertised "EdDSA" covers the strict profile's "Ed25519".
    issuer = FakeIssuer()
    resolver, fetcher = _ports(issuer)
    fetcher.documents[issuer.metadata_url] = issuer.metadata | {
        "signing_alg_values_supported": advertised
    }
    strict = Profile.draft_hardt_02()
    report = discover("example.com", resolver=resolver, fetcher=fetcher, profile=strict)
    assert report.ok is ok

    browser = FakeBrowser(clock=issuer.clock)
    token = browser.present(issuer.issue(EMAIL, browser.public_jwk), audience=AUDIENCE, nonce="n")
    verifier = Verifier(
        audience=AUDIENCE, resolver=resolver, fetcher=fetcher, profile=strict, clock=issuer.clock
    )
    if ok:
        assert verifier.verify(token, nonce="n", email=None).email == EMAIL
    else:
        with pytest.raises(EVPError):
            verifier.verify(token, nonce="n", email=None)


def test_discover_refuses_asynchronous_ports(issuer: FakeIssuer, leash: list[Any]) -> None:
    class Resolver:
        def __init__(self) -> None:
            self.inner = AsyncInMemoryDns(issuer.dns_records())

        def resolve_txt(self, name: str) -> Any:
            leash.append(coroutine := self.inner.resolve_txt(name))
            return coroutine

    resolver: Any = Resolver()
    with pytest.raises(TypeError, match="adiscover"):
        discover("example.com", resolver=resolver, fetcher=InMemoryHttp({}))

    # A port that says it is asynchronous is refused before anything is looked up.
    with pytest.raises(TypeError, match="adiscover"):
        discover("example.com", resolver=resolver.inner, fetcher=InMemoryHttp({}))
