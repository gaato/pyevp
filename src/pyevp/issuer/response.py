"""The framework-neutral HTTP response every issuer endpoint returns."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field

__all__ = ["IssuerResponse"]

_JSON_HEADERS = {"Content-Type": "application/json", "Cache-Control": "no-store"}

# Metadata, JWKS and web-identity change only when the issuer is reconfigured or rotates
# keys.  Five minutes takes load off public endpoints without slowing a rotation much.
PUBLIC_CACHE = {"Cache-Control": "public, max-age=300"}


@dataclass(frozen=True, slots=True)
class IssuerResponse:
    """An HTTP response for the framework to send as is: status, headers and body.

    JSON responses are ``Cache-Control: no-store`` unless they are public documents.
    Use :func:`dataclasses.replace` to change anything before sending it.
    """

    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    @classmethod
    def json(
        cls, status: int, document: object, headers: Mapping[str, str] | None = None
    ) -> IssuerResponse:
        body = json.dumps(document, separators=(",", ":")).encode()
        return cls(status, {**_JSON_HEADERS, **(headers or {})}, body)
