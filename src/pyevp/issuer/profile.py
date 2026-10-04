"""Issuance profiles: what an issuer accepts from browsers and how it writes EVTs.

Like :mod:`pyevp.profile` on the verifying side, every point where browsers and the
drafts disagree is a field here, and following a change usually means adding a
preset rather than changing an existing one.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from types import MappingProxyType
from typing import Self, TypedDict, Unpack

__all__ = [
    "DEFAULT_ISSUANCE_PROFILE",
    "ISSUANCE_PROFILES",
    "IssuanceProfile",
    "IssuanceProfileChanges",
]


@dataclass(frozen=True, slots=True, kw_only=True)
class IssuanceProfile:
    name: str
    request_algorithms: frozenset[str]
    """Algorithms accepted for the browser's request signature (also limited by metadata)."""
    require_request_key_alg: bool
    """Require ``alg`` in the ``hwk`` Signature-Key; otherwise it is implied by the curve."""
    max_request_age: timedelta
    """How far the signature's ``created`` may lie from now, either way."""
    require_sec_fetch_dest: bool
    evt_type: str = "evt+jwt"
    polymorphic_eddsa_header: bool = False
    """Write ``"alg": "EdDSA"`` in EVT headers signed with Ed25519 (as Gmail did in 2026)."""

    @classmethod
    def chrome_153(cls) -> Self:
        """What Chrome 153+ sends and accepts (verified end to end with 154.0.8037.92).

        Chrome signs requests with ``hwk`` keys that omit ``alg``, and it rejects EVTs
        whose header says ``"alg": "Ed25519"``: it only accepts ``EdDSA``, ``ES256``
        and ``RS256``.  Ed25519-signed EVTs therefore carry ``EdDSA``, as Gmail's do.
        """
        return cls(
            name="chrome-153",
            request_algorithms=frozenset({"Ed25519", "ES256"}),
            require_request_key_alg=False,
            max_request_age=timedelta(seconds=300),
            require_sec_fetch_dest=True,
            polymorphic_eddsa_header=True,
        )

    @classmethod
    def draft_hardt_02(cls) -> Self:
        """Strict reading of draft-hardt-email-verification-02 and signature-key-09."""
        return cls(
            name="draft-hardt-02",
            request_algorithms=frozenset({"Ed25519", "ES256"}),
            require_request_key_alg=True,
            max_request_age=timedelta(seconds=300),
            require_sec_fetch_dest=True,
        )

    @staticmethod
    def named(name: str) -> IssuanceProfile:
        try:
            return ISSUANCE_PROFILES[name]
        except KeyError:
            known = ", ".join(ISSUANCE_PROFILES)
            raise ValueError(f"unknown issuance profile {name!r}; known: {known}") from None

    def replace(self, **changes: Unpack[IssuanceProfileChanges]) -> Self:
        """Return a copy with some fields changed (``dataclasses.replace``)."""
        return dataclasses.replace(self, **changes)


class IssuanceProfileChanges(TypedDict, total=False):
    """The fields of :class:`IssuanceProfile`, as keyword arguments of its ``replace``."""

    name: str
    request_algorithms: frozenset[str]
    require_request_key_alg: bool
    max_request_age: timedelta
    require_sec_fetch_dest: bool
    evt_type: str
    polymorphic_eddsa_header: bool


ISSUANCE_PROFILES: Mapping[str, IssuanceProfile] = MappingProxyType(
    {p.name: p for p in (IssuanceProfile.chrome_153(), IssuanceProfile.draft_hardt_02())}
)

DEFAULT_ISSUANCE_PROFILE = ISSUANCE_PROFILES["chrome-153"]
