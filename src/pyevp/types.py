"""Value types shared across the package."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import TypeAlias

__all__ = ["IssuerMetadata", "JSONObject", "VerifiedEmail"]

# TODO(py3.12): back to a ``type`` statement once 3.11 support is dropped.
JSONObject: TypeAlias = Mapping[str, object]


@dataclass(frozen=True, slots=True)
class IssuerMetadata:
    issuer: str
    issuance_endpoint: str
    jwks_uri: str
    signing_alg_values_supported: tuple[str, ...] | None
    raw: JSONObject


@dataclass(frozen=True, slots=True)
class VerifiedEmail:
    """The result of a successful verification."""

    email: str
    """The address as asserted by the issuer (not normalised)."""
    issuer: str
    """Canonical issuer origin, e.g. ``https://accounts.google.com``."""
    issued_at: datetime
    expires_at: datetime | None
    is_private_email: bool
    claims: JSONObject
    """All issuer-signed claims, for forward compatibility."""
