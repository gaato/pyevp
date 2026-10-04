"""Relying-party verification for the Email Verification Protocol (EVP)."""

from pyevp._email import emails_match
from pyevp.cache import AsyncCache, Cache, CacheEntry, InMemoryCache, NullCache
from pyevp.errors import DiscoveryError, ErrorCode, EVPError, PolicyError, TokenError
from pyevp.nonce import (
    AsyncNonceStore,
    NonceStore,
    SessionNonces,
    generate_nonce,
    nonces_equal,
    token_input,
)
from pyevp.observability import LoggingObserver, Observer, VerificationEvent
from pyevp.ports import AsyncJsonFetcher, AsyncTxtResolver, Clock, JsonFetcher, TxtResolver
from pyevp.profile import DEFAULT_PROFILE, EmailComparison, IssuerFormat, Profile
from pyevp.replay import AsyncReplayGuard, InMemoryReplayGuard, ReplayGuard
from pyevp.types import IssuerMetadata, VerifiedEmail
from pyevp.verifier import AsyncVerifier, Verifier

__all__ = [
    "DEFAULT_PROFILE",
    "AsyncCache",
    "AsyncJsonFetcher",
    "AsyncNonceStore",
    "AsyncReplayGuard",
    "AsyncTxtResolver",
    "AsyncVerifier",
    "Cache",
    "CacheEntry",
    "Clock",
    "DiscoveryError",
    "EVPError",
    "EmailComparison",
    "ErrorCode",
    "InMemoryCache",
    "InMemoryReplayGuard",
    "IssuerFormat",
    "IssuerMetadata",
    "JsonFetcher",
    "LoggingObserver",
    "NonceStore",
    "NullCache",
    "Observer",
    "PolicyError",
    "Profile",
    "ReplayGuard",
    "SessionNonces",
    "TokenError",
    "TxtResolver",
    "VerificationEvent",
    "VerifiedEmail",
    "Verifier",
    "emails_match",
    "generate_nonce",
    "nonces_equal",
    "token_input",
]
