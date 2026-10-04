"""Exception hierarchy.

Every rejected token raises an :class:`EVPError` with an :class:`ErrorCode`, so that
web frameworks can map it to a form error or an HTTP status without parsing
messages.  Failures of the application's own cache or replay store are not
``EVPError``: they propagate unchanged.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "DiscoveryError",
    "EVPError",
    "ErrorCode",
    "PolicyError",
    "TokenError",
]


class ErrorCode(StrEnum):
    # token structure
    MALFORMED_TOKEN = "malformed_token"
    UNSUPPORTED_ALG = "unsupported_alg"
    BAD_TYPE = "bad_type"
    # key binding / freshness
    AUDIENCE_MISMATCH = "audience_mismatch"
    NONCE_MISMATCH = "nonce_mismatch"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_NOT_YET_VALID = "token_not_yet_valid"
    TOKEN_REPLAYED = "token_replayed"
    SD_HASH_MISMATCH = "sd_hash_mismatch"
    KB_SIGNATURE_INVALID = "kb_signature_invalid"
    # issuer
    ISSUER_DISCOVERY_FAILED = "issuer_discovery_failed"
    ISSUER_UNREACHABLE = "issuer_unreachable"
    ISSUER_MISMATCH = "issuer_mismatch"
    METADATA_INVALID = "metadata_invalid"
    KEY_NOT_FOUND = "key_not_found"
    EVT_SIGNATURE_INVALID = "evt_signature_invalid"
    # policy
    EMAIL_NOT_VERIFIED = "email_not_verified"
    EMAIL_MISMATCH = "email_mismatch"
    ISSUER_NOT_ALLOWED = "issuer_not_allowed"


class EVPError(Exception):
    """Base class for verification failures: the token must not be trusted.

    :class:`TokenError` and :class:`PolicyError` concern what was submitted;
    :class:`DiscoveryError` concerns the issuer.
    """

    code: ErrorCode

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code

    def __str__(self) -> str:
        return f"[{self.code}] {self.args[0]}"


class TokenError(EVPError):
    """The presented token is malformed, stale, mis-bound or badly signed."""


class DiscoveryError(EVPError):
    """The issuer could not be discovered or its metadata / keys are unusable.

    ``ISSUER_UNREACHABLE`` indicates a transport failure that may be transient.
    """


class PolicyError(EVPError):
    """The token does not satisfy the relying party's policy (``email_mismatch``,
    ``issuer_not_allowed``, ...).

    Checked offline, before the issuer's signature, so it says nothing about whether
    the token is authentic.
    """
