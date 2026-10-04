"""Issuer side of the Email Verification Protocol.

Run an issuer for your own email domains: :class:`Issuer` answers the browser's
issuance and FedCM accounts requests and serves the metadata and JWKS, as
framework-neutral :class:`IssuerResponse` objects, and lists the DNS records to publish.
"""

from pyevp.discovery import METADATA_PATH
from pyevp.issuer.core import (
    MAX_REQUEST_BODY,
    AsyncUserEmails,
    IssuanceEvent,
    IssuanceObserver,
    Issuer,
    UserEmails,
    is_valid_email,
)
from pyevp.issuer.errors import IssuanceErrorCode
from pyevp.issuer.fedcm import (
    FEDCM_FETCH_DEST,
    WEB_IDENTITY_PATH,
    login_status_headers,
    web_identity_document,
    web_identity_response,
)
from pyevp.issuer.keys import SIGNING_ALGORITHMS, Signer, SigningKey, public_jwk
from pyevp.issuer.profile import DEFAULT_ISSUANCE_PROFILE, ISSUANCE_PROFILES, IssuanceProfile
from pyevp.issuer.response import IssuerResponse

__all__ = [
    "DEFAULT_ISSUANCE_PROFILE",
    "FEDCM_FETCH_DEST",
    "ISSUANCE_PROFILES",
    "MAX_REQUEST_BODY",
    "METADATA_PATH",
    "SIGNING_ALGORITHMS",
    "WEB_IDENTITY_PATH",
    "AsyncUserEmails",
    "IssuanceErrorCode",
    "IssuanceEvent",
    "IssuanceObserver",
    "IssuanceProfile",
    "Issuer",
    "IssuerResponse",
    "Signer",
    "SigningKey",
    "UserEmails",
    "is_valid_email",
    "login_status_headers",
    "public_jwk",
    "web_identity_document",
    "web_identity_response",
]
