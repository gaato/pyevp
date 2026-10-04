"""Test doubles: a fake issuer, a fake browser and in-memory ports.

These let applications test their EVP integration end-to-end without network
access::

    issuer = FakeIssuer()
    browser = FakeBrowser()
    verifier = make_verifier(issuer, audience="https://rp.example")
    nonces = SessionNonces({})          # a dict stands in for the session
    token = browser.present(issuer.issue("alice@example.com", browser.public_jwk),
                            audience="https://rp.example", nonce=nonces.issue())
    verifier.verify_submission(token, nonces=nonces, email="alice@example.com")
"""

from __future__ import annotations

import json
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, TypeAlias

from joserfc.jwk import ECKey, OKPKey

from pyevp import _httpsig, discovery
from pyevp.cache import AsyncCache, Cache
from pyevp.observability import Observer
from pyevp.profile import DEFAULT_PROFILE, Profile
from pyevp.replay import AsyncReplayGuard, ReplayGuard
from pyevp.token import build_kb, sign_jwt
from pyevp.types import JSONObject
from pyevp.verifier import AsyncVerifier, Verifier

__all__ = [
    "AsyncInMemoryDns",
    "AsyncInMemoryHttp",
    "FakeBrowser",
    "FakeIssuer",
    "FixedClock",
    "InMemoryDns",
    "InMemoryHttp",
    "make_async_verifier",
    "make_verifier",
]

# TODO(py3.12): back to a ``type`` statement once 3.11 support is dropped.
SigningAlg: TypeAlias = Literal["Ed25519", "EdDSA", "ES256"]


def _generate_key(alg: str) -> OKPKey | ECKey:
    if alg in ("Ed25519", "EdDSA"):
        return OKPKey.generate_key("Ed25519", private=True)
    if alg == "ES256":
        return ECKey.generate_key("P-256", private=True)
    raise ValueError(f"unsupported test algorithm {alg!r}")


class FixedClock:
    """A manually advanced clock, usable wherever a ``Clock`` is expected."""

    def __init__(self, now: datetime | None = None) -> None:
        self.now = now or datetime(2026, 10, 1, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


class FakeIssuer:
    """Mints EVTs.  Deviations from the spec can be configured to mimic real issuers.

    :param host: issuer host; the issuer identifier is ``https://{host}``.
    :param kid: key id; ``""`` or ``None`` reproduces Gmail's key-id-less JWKS.
    :param iss_format: how ``iss`` is written in tokens.
    """

    def __init__(
        self,
        host: str = "issuer.example",
        *,
        alg: SigningAlg = "Ed25519",
        kid: str | None = "test-key-1",
        typ: str = "evt+jwt",
        iss_format: Literal["origin", "host"] = "origin",
        email_domains: tuple[str, ...] = ("example.com",),
        clock: FixedClock | None = None,
    ) -> None:
        self.host = host
        self.alg = alg
        self.kid = kid
        self.typ = typ
        self.iss_format = iss_format
        self.email_domains = email_domains
        self.clock = clock or FixedClock()
        self.key = _generate_key(alg)

    @classmethod
    def gmail_like(cls, **kwargs: Any) -> FakeIssuer:
        """Mimic Gmail as deployed in 2026-10: ``EdDSA``, keys without ``kid``."""
        kwargs.setdefault("host", "accounts.google.example")
        kwargs.setdefault("email_domains", ("gmail.example",))
        return cls(alg="EdDSA", kid="", **kwargs)

    @property
    def issuer(self) -> str:
        return f"https://{self.host}"

    @property
    def metadata_url(self) -> str:
        return discovery.metadata_url(self.issuer, DEFAULT_PROFILE)

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/jwks.json"

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "issuance_endpoint": f"{self.issuer}/email-verification/issue",
            "jwks_uri": self.jwks_uri,
            "signing_alg_values_supported": [self.alg],
        }

    @property
    def jwks(self) -> dict[str, Any]:
        jwk: dict[str, Any] = {**self.key.as_dict(private=False), "use": "sig", "alg": self.alg}
        if self.kid:
            jwk["kid"] = self.kid
        return {"keys": [jwk]}

    def dns_records(self) -> dict[str, list[str]]:
        return {
            f"{DEFAULT_PROFILE.dns_label}.{domain}": [f"iss={self.host}"]
            for domain in self.email_domains
        }

    def http_documents(self) -> dict[str, object]:
        return {self.metadata_url: self.metadata, self.jwks_uri: self.jwks}

    def rotate_key(self) -> None:
        self.key = _generate_key(self.alg)

    def issue(
        self,
        email: str,
        holder_jwk: JSONObject,
        *,
        issued_at: datetime | None = None,
        claims: Mapping[str, Any] | None = None,
        header: Mapping[str, Any] | None = None,
    ) -> str:
        """Return a signed EVT.  ``claims`` / ``header`` override or add fields
        (a value of ``None`` removes the field)."""
        iat = issued_at or self.clock()
        body: dict[str, Any] = {
            "iss": self.issuer if self.iss_format == "origin" else self.host,
            "iat": int(iat.timestamp()),
            "cnf": {"jwk": dict(holder_jwk)},
            "email": email,
            "email_verified": True,
        }
        hdr: dict[str, Any] = {"alg": self.alg, "typ": self.typ}
        if self.kid is not None:
            hdr["kid"] = self.kid
        for target, overrides in ((body, claims), (hdr, header)):
            for k, v in (overrides or {}).items():
                if v is None:
                    target.pop(k, None)
                else:
                    target[k] = v
        return sign_jwt(hdr, body, self.key)


class FakeBrowser:
    """Holds the key-binding key and produces presentation tokens."""

    def __init__(self, *, alg: SigningAlg = "Ed25519", clock: FixedClock | None = None) -> None:
        self.alg = alg
        self.clock = clock or FixedClock()
        self.key = _generate_key(alg)

    @property
    def public_jwk(self) -> dict[str, Any]:
        return {**self.key.as_dict(private=False), "alg": self.alg}

    def issuance_request(
        self,
        email: str,
        *,
        endpoint: str,
        include_alg: bool = False,
        extra: Mapping[str, Any] | None = None,
        created: datetime | None = None,
    ) -> dict[str, Any]:
        """A signed issuance request: ``method``, ``headers`` and ``body`` for
        :meth:`Issuer.issuance_response <pyevp.issuer.Issuer.issuance_response>`.

        Like Chrome 153, the ``hwk`` key omits ``alg`` unless ``include_alg`` is set.
        ``extra`` adds members to the JSON body.
        """
        body = json.dumps({"email": email, **(extra or {})}).encode()
        alg = "Ed25519" if self.alg == "EdDSA" else self.alg
        headers = _httpsig.sign_request(
            method="POST",
            endpoint=endpoint,
            body=body,
            private_key=self.key,
            public_jwk=self.key.as_dict(private=False),
            alg=alg,
            created=created or self.clock(),
            include_alg=include_alg,
        )
        return {"method": "POST", "headers": headers, "body": body}

    def present(
        self,
        evt: str,
        *,
        audience: str,
        nonce: str,
        issued_at: datetime | None = None,
        typ: str = "kb+jwt",
    ) -> str:
        return build_kb(
            evt,
            private_key=self.key,
            alg=self.alg,
            audience=audience,
            nonce=nonce,
            issued_at=issued_at or self.clock(),
            typ=typ,
        )


@dataclass
class InMemoryDns:
    records: dict[str, list[str]] = field(default_factory=dict)
    queries: list[str] = field(default_factory=list)

    def resolve_txt(self, name: str) -> list[str]:
        self.queries.append(name)
        return list(self.records.get(name, []))


@dataclass
class AsyncInMemoryDns:
    records: dict[str, list[str]] = field(default_factory=dict)
    queries: list[str] = field(default_factory=list)

    async def resolve_txt(self, name: str) -> list[str]:
        self.queries.append(name)
        return list(self.records.get(name, []))


class _NotFoundError(Exception):
    pass


@dataclass
class InMemoryHttp:
    """Serves documents by URL; a callable value is invoked on each request."""

    documents: dict[str, object] = field(default_factory=dict)
    requests: list[str] = field(default_factory=list)

    def fetch_json(self, url: str) -> object:
        self.requests.append(url)
        if url not in self.documents:
            raise _NotFoundError(f"404 {url}")
        doc = self.documents[url]
        return doc() if callable(doc) else doc


@dataclass
class AsyncInMemoryHttp:
    documents: dict[str, object] = field(default_factory=dict)
    requests: list[str] = field(default_factory=list)

    async def fetch_json(self, url: str) -> object:
        self.requests.append(url)
        if url not in self.documents:
            raise _NotFoundError(f"404 {url}")
        doc = self.documents[url]
        return doc() if callable(doc) else doc


def _live(issuers: tuple[FakeIssuer, ...]) -> tuple[dict[str, list[str]], dict[str, object]]:
    records: dict[str, list[str]] = {}
    documents: dict[str, object] = {}
    for issuer in issuers:
        records |= issuer.dns_records()
        # Callables so that key rotation on the fake issuer is visible.
        documents[issuer.metadata_url] = lambda i=issuer: i.metadata
        documents[issuer.jwks_uri] = lambda i=issuer: i.jwks
    return records, documents


def make_verifier(
    *issuers: FakeIssuer,
    audience: str,
    profile: Profile = DEFAULT_PROFILE,
    allowed_issuers: Collection[str] | None = None,
    clock: FixedClock | None = None,
    cache: Cache | None = None,
    replay_guard: ReplayGuard | None = None,
    observer: Observer | None = None,
) -> Verifier:
    """A :class:`Verifier` wired to in-memory DNS/HTTP serving ``issuers``."""
    records, documents = _live(issuers)
    clock = clock or (issuers[0].clock if issuers else FixedClock())
    return Verifier(
        audience=audience,
        resolver=InMemoryDns(records),
        fetcher=InMemoryHttp(documents),
        profile=profile,
        allowed_issuers=allowed_issuers,
        clock=clock,
        cache=cache,
        replay_guard=replay_guard,
        observer=observer,
    )


def make_async_verifier(
    *issuers: FakeIssuer,
    audience: str,
    profile: Profile = DEFAULT_PROFILE,
    allowed_issuers: Collection[str] | None = None,
    clock: FixedClock | None = None,
    cache: Cache | AsyncCache | None = None,
    replay_guard: ReplayGuard | AsyncReplayGuard | None = None,
    observer: Observer | None = None,
) -> AsyncVerifier:
    records, documents = _live(issuers)
    clock = clock or (issuers[0].clock if issuers else FixedClock())
    return AsyncVerifier(
        audience=audience,
        resolver=AsyncInMemoryDns(records),
        fetcher=AsyncInMemoryHttp(documents),
        profile=profile,
        allowed_issuers=allowed_issuers,
        clock=clock,
        cache=cache,
        replay_guard=replay_guard,
        observer=observer,
    )
