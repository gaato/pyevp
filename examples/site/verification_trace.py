"""Request-local display traces using only public PyEVP ports and checks."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from time import perf_counter

from pyevp.cache import Cache, CacheEntry
from pyevp.core import check_email, precheck_evt, verify_kb
from pyevp.discovery import txt_name_for
from pyevp.errors import ErrorCode, EVPError
from pyevp.ports import AsyncJsonFetcher, AsyncTxtResolver, Clock
from pyevp.profile import Profile
from pyevp.token import ParsedToken


class Step(StrEnum):
    PARSE = "parse"
    BINDING = "binding"
    DNS = "dns"
    METADATA = "metadata"
    JWKS = "jwks"
    CLAIMS = "claims"


LABELS = {
    Step.PARSE: "Parse the token",
    Step.BINDING: "Key binding: audience, nonce, freshness, sd_hash, holder signature",
    Step.DNS: "DNS: _email-verification.<domain>",
    Step.METADATA: "Issuer metadata",
    Step.JWKS: "JWKS",
    Step.CLAIMS: "Issuer signature and claims, including the email match",
}
# Multiple candidates mean the code alone cannot identify the failing stage.
ERROR_STEPS = {
    ErrorCode.MALFORMED_TOKEN: (Step.PARSE, Step.CLAIMS, Step.BINDING, Step.DNS),
    ErrorCode.UNSUPPORTED_ALG: (Step.CLAIMS, Step.BINDING, Step.METADATA),
    ErrorCode.BAD_TYPE: (Step.CLAIMS, Step.BINDING),
    ErrorCode.AUDIENCE_MISMATCH: (Step.BINDING,),
    ErrorCode.NONCE_MISMATCH: (Step.BINDING,),
    ErrorCode.TOKEN_EXPIRED: (Step.CLAIMS, Step.BINDING),
    ErrorCode.TOKEN_NOT_YET_VALID: (Step.CLAIMS, Step.BINDING),
    ErrorCode.TOKEN_REPLAYED: (Step.CLAIMS,),
    ErrorCode.SD_HASH_MISMATCH: (Step.BINDING,),
    ErrorCode.KB_SIGNATURE_INVALID: (Step.BINDING,),
    ErrorCode.ISSUER_DISCOVERY_FAILED: (Step.DNS,),
    ErrorCode.ISSUER_UNREACHABLE: (Step.DNS, Step.METADATA, Step.JWKS),
    ErrorCode.ISSUER_MISMATCH: (Step.DNS, Step.METADATA),
    ErrorCode.METADATA_INVALID: (Step.METADATA, Step.JWKS),
    ErrorCode.KEY_NOT_FOUND: (Step.CLAIMS,),
    ErrorCode.EVT_SIGNATURE_INVALID: (Step.CLAIMS,),
    ErrorCode.EMAIL_NOT_VERIFIED: (Step.CLAIMS,),
    ErrorCode.EMAIL_MISMATCH: (Step.CLAIMS,),
}


@dataclass
class IO:
    target: str
    outcome: str
    elapsed_ms: float


@dataclass
class Trace:
    active: Step | None = None
    fetch_reads: int = 0
    checked_at: datetime | None = None
    io: dict[Step, list[IO]] = field(default_factory=dict)

    def record(self, step: Step, target: str, outcome: str, started: float) -> None:
        self.io.setdefault(step, []).append(IO(target, outcome, (perf_counter() - started) * 1000))

    def steps(
        self,
        error: EVPError | None,
        *,
        parsed: ParsedToken | None,
        now: datetime,
        profile: Profile,
        audience: str,
        nonce: str,
        email: str,
    ) -> list[dict[str, object]]:
        passed = set(Step)
        failed = None
        if error is not None:
            candidates = ERROR_STEPS[error.code]
            failed = self.active if self.active in candidates else candidates[0]
            passed = set(list(Step)[: list(Step).index(failed)])
            if error.code == ErrorCode.NONCE_MISMATCH and not nonce:
                # No nonce of this session was presented: the token was refused before any
                # other check ran, so later stages would only show what never happened.
                passed = {Step.PARSE} if parsed is not None else set()
                failed = Step.BINDING
            elif self.active is None:
                # Public checks disambiguate errors shared by EVT and KB-JWT.
                # They are only repeated for display after the verifier has failed.
                passed = set()
                failed = Step.PARSE
                try:
                    if parsed is not None:
                        passed.add(Step.PARSE)
                        failed = Step.CLAIMS
                        evt = precheck_evt(parsed, now=now, profile=profile)
                        failed = Step.BINDING
                        verify_kb(
                            parsed,
                            cnf_jwk=evt.cnf_jwk,
                            audience=audience,
                            nonce=nonce,
                            now=now,
                            profile=profile,
                        )
                        passed.add(Step.BINDING)
                        failed = Step.CLAIMS
                        check_email(evt.email, email, profile)
                        failed = Step.DNS
                        txt_name_for(evt.email, profile)
                        failed = candidates[0]
                except (EVPError, ValueError, UnicodeError):
                    pass
                assert failed in candidates
        return [
            {
                "id": step,
                "label": label,
                "status": "failed" if step == failed else "passed" if step in passed else "not run",
                "io": self.io.get(step, []),
            }
            for step, label in LABELS.items()
        ]


CURRENT_TRACE: ContextVar[Trace | None] = ContextVar("verification_trace", default=None)


class RecordingClock:
    """Keep the verifier's first timestamp for accurate offline error attribution."""

    def __init__(self, inner: Clock) -> None:
        self.inner = inner

    def __call__(self) -> datetime:
        now = self.inner()
        if (trace := CURRENT_TRACE.get()) is not None and trace.checked_at is None:
            trace.checked_at = now
        return now


class RecordingResolver:
    def __init__(self, inner: AsyncTxtResolver) -> None:
        self.inner = inner

    async def resolve_txt(self, name: str) -> list[str]:
        trace = CURRENT_TRACE.get()
        if trace is not None:
            trace.active = Step.DNS
        started, outcome = perf_counter(), "failed"
        try:
            records = await self.inner.resolve_txt(name)
            outcome = "passed" if records else "no records"
            return records
        finally:
            if trace is not None:
                trace.record(Step.DNS, name, outcome, started)


class RecordingFetcher:
    def __init__(self, inner: AsyncJsonFetcher) -> None:
        self.inner = inner

    async def fetch_json(self, url: str) -> object:
        trace = CURRENT_TRACE.get()
        step = trace.active if trace is not None and trace.active is not None else Step.METADATA
        if trace is not None:
            trace.active = step
        started, outcome = perf_counter(), "failed"
        try:
            result = await self.inner.fetch_json(url)
            outcome = "passed"
            return result
        finally:
            if trace is not None:
                trace.record(step, url, outcome, started)


class TrackingCache:
    """Track the stage on cache reads; preserve the verifier's cache/refresh policy."""

    def __init__(self, inner: Cache) -> None:
        self.inner = inner

    def get(self, key: str) -> CacheEntry | None:
        if (trace := CURRENT_TRACE.get()) is not None:
            trace.active = Step.METADATA if trace.fetch_reads == 0 else Step.JWKS
            trace.fetch_reads += 1
        return self.inner.get(key)

    def set(self, key: str, entry: CacheEntry, ttl: timedelta) -> None:
        self.inner.set(key, entry, ttl)
