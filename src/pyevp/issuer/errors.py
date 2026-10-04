"""Issuance errors and the HTTP responses they map to (draft-hardt-02, "Error Responses")."""

from __future__ import annotations

from enum import StrEnum

from pyevp.issuer.response import IssuerResponse

__all__ = ["IssuanceError", "IssuanceErrorCode"]


class IssuanceErrorCode(StrEnum):
    INVALID_REQUEST = "invalid_request"
    INVALID_SIGNATURE = "invalid_signature"
    AUTHENTICATION_REQUIRED = "authentication_required"
    PRIVATE_EMAIL_NOT_SUPPORTED = "private_email_not_supported"
    INVALID_DIRECTED_EMAIL = "invalid_directed_email"
    UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type"
    SERVER_ERROR = "server_error"


_STATUS = {
    IssuanceErrorCode.AUTHENTICATION_REQUIRED: 401,
    IssuanceErrorCode.UNSUPPORTED_MEDIA_TYPE: 415,
    IssuanceErrorCode.SERVER_ERROR: 500,
}

# Descriptions are fixed per code: the message passed to IssuanceError is for logs only and
# never reaches the browser, so a response cannot reveal which check failed.
_DESCRIPTIONS = {
    IssuanceErrorCode.INVALID_REQUEST: "Invalid or malformed request",
    IssuanceErrorCode.INVALID_SIGNATURE: "HTTP Message Signature verification failed",
    IssuanceErrorCode.AUTHENTICATION_REQUIRED: (
        "User must be authenticated and control requested email"
    ),
    IssuanceErrorCode.PRIVATE_EMAIL_NOT_SUPPORTED: (
        "Issuer does not support private email addresses"
    ),
    IssuanceErrorCode.INVALID_DIRECTED_EMAIL: "Private email invalid or not linked to this email",
    IssuanceErrorCode.UNSUPPORTED_MEDIA_TYPE: "Content-Type must be application/json",
    IssuanceErrorCode.SERVER_ERROR: "Temporary server error, please try again later",
}


class IssuanceError(Exception):
    """A request the issuer must refuse.  Render it with :meth:`to_response`.

    ``message`` is for logs; the response body only ever carries the fixed
    description of ``code``.
    """

    def __init__(
        self, code: IssuanceErrorCode, message: str, *, signature_error: str | None = None
    ) -> None:
        super().__init__(message)
        self.code = code
        self.signature_error = signature_error
        """``Signature-Error`` code, for ``invalid_signature``."""

    def __str__(self) -> str:
        return f"[{self.code}] {self.args[0]}"

    @property
    def status(self) -> int:
        return _STATUS.get(self.code, 400)

    @classmethod
    def authentication_required(cls, message: str = "not authenticated") -> IssuanceError:
        """The one error for "no session", "unknown address" and "not this user's address".

        Raise it for every such case so that responses cannot be used to probe accounts.
        """
        return cls(IssuanceErrorCode.AUTHENTICATION_REQUIRED, message)

    def to_response(self) -> IssuerResponse:
        headers = {}
        if self.signature_error is not None:
            headers["Signature-Error"] = f"error={self.signature_error}"
        document = {"error": str(self.code), "error_description": _DESCRIPTIONS[self.code]}
        return IssuerResponse.json(self.status, document, headers)
