"""Verification profiles.

The protocol is still moving (algorithm names, ``iss`` format, ``kid`` rules, …)
and deployed issuers lag behind the drafts.  Every such knob lives here so that
following a spec change usually means adding a new preset rather than changing an
existing one or the verification code.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Self, TypedDict, Unpack

from pyevp._email import EmailComparison, emails_match

__all__ = [
    "DEFAULT_PROFILE",
    "PROFILES",
    "EmailComparison",
    "IssuerFormat",
    "Profile",
    "ProfileChanges",
]


class IssuerFormat(StrEnum):
    """Accepted spellings of an issuer identifier (token ``iss`` / DNS ``iss=``)."""

    HOST = "host"
    """Bare host, e.g. ``accounts.google.com`` (early drafts)."""
    ORIGIN = "origin"
    """HTTPS origin, e.g. ``https://accounts.google.com`` (draft-hardt -02)."""
    ANY = "any"


@dataclass(frozen=True, slots=True, kw_only=True)
class Profile:
    name: str
    evt_types: frozenset[str]
    kb_types: frozenset[str]
    evt_algorithms: frozenset[str]
    kb_algorithms: frozenset[str]
    require_kid: bool
    """When false, an absent or empty ``kid`` tries every compatible issuer key."""
    require_cnf_alg: bool
    """Require ``cnf.jwk.alg`` and that it equals the KB-JWT ``alg``."""
    issuer_format: IssuerFormat
    email_comparison: EmailComparison
    max_token_age: timedelta
    clock_skew: timedelta
    require_exp: bool
    allow_disclosures: bool
    """Accept SD-JWT disclosures between the EVT and the KB-JWT (``MALFORMED_TOKEN`` otherwise).

    They are covered by ``sd_hash`` but never decoded, so they add no claims.
    """
    dns_label: str = "_email-verification"
    metadata_path: str = "/.well-known/email-verification"

    @classmethod
    def compat_2026_10(cls) -> Self:
        """Accept both the -02 draft and what Chrome + Gmail ship as of 2026-10.

        Gmail signs with ``EdDSA`` and publishes keys without ``kid``.
        """
        return cls(
            name="compat-2026-10",
            evt_types=frozenset({"evt+jwt"}),
            kb_types=frozenset({"kb+jwt"}),
            evt_algorithms=frozenset({"Ed25519", "EdDSA", "ES256"}),
            kb_algorithms=frozenset({"Ed25519", "EdDSA", "ES256"}),
            require_kid=False,
            require_cnf_alg=False,
            issuer_format=IssuerFormat.ANY,
            email_comparison=EmailComparison.CASE_INSENSITIVE,
            max_token_age=timedelta(minutes=5),
            clock_skew=timedelta(minutes=1),
            require_exp=False,
            allow_disclosures=False,
        )

    @classmethod
    def draft_hardt_02(cls) -> Self:
        """Strict reading of draft-hardt-email-verification editor's copy (-02)."""
        return cls(
            name="draft-hardt-02",
            evt_types=frozenset({"evt+jwt"}),
            kb_types=frozenset({"kb+jwt"}),
            evt_algorithms=frozenset({"Ed25519", "ES256"}),
            kb_algorithms=frozenset({"Ed25519", "ES256"}),
            require_kid=True,
            require_cnf_alg=True,
            issuer_format=IssuerFormat.ORIGIN,
            email_comparison=EmailComparison.EXACT,
            max_token_age=timedelta(minutes=5),
            clock_skew=timedelta(minutes=1),
            require_exp=False,
            allow_disclosures=False,
        )

    @staticmethod
    def named(name: str) -> Profile:
        """Look up a preset by name (e.g. ``"draft-hardt-02"``)."""
        try:
            return PROFILES[name]
        except KeyError:
            raise ValueError(f"unknown profile {name!r}; known: {', '.join(PROFILES)}") from None

    def emails_match(self, asserted: str, submitted: str) -> bool:
        """Compare two addresses the way verification does (see :class:`EmailComparison`).

        Use it when looking up the account for a verified address, so that lookup and
        verification agree on which addresses are the same.
        """
        return emails_match(asserted, submitted, self.email_comparison)

    def replace(self, **changes: Unpack[ProfileChanges]) -> Self:
        """Return a copy with some fields changed (``dataclasses.replace``)."""
        return dataclasses.replace(self, **changes)


class ProfileChanges(TypedDict, total=False):
    """The fields of :class:`Profile`, as keyword arguments of :meth:`Profile.replace`."""

    name: str
    evt_types: frozenset[str]
    kb_types: frozenset[str]
    evt_algorithms: frozenset[str]
    kb_algorithms: frozenset[str]
    require_kid: bool
    require_cnf_alg: bool
    issuer_format: IssuerFormat
    email_comparison: EmailComparison
    max_token_age: timedelta
    clock_skew: timedelta
    require_exp: bool
    allow_disclosures: bool
    dns_label: str
    metadata_path: str


PROFILES: Mapping[str, Profile] = MappingProxyType(
    {p.name: p for p in (Profile.compat_2026_10(), Profile.draft_hardt_02())}
)
"""All presets by name."""

DEFAULT_PROFILE = PROFILES["compat-2026-10"]
"""The profile verifiers use unless told otherwise."""
