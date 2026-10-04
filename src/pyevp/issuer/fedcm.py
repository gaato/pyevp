"""FedCM documents that Chrome requires from an issuer, beyond the EVP draft.

Before Chrome sends an issuance request it checks, through FedCM, that the user is
signed in to the issuer with the address they typed (Chrome 154; see
``content/browser/webid/delegation/email_verification_request.cc``):

1. It fetches ``https://<registrable domain>/.well-known/web-identity`` — for an
   issuer on ``accounts.example.com`` that is ``https://example.com/...`` — and
   reads ``accounts_endpoint`` and ``login_url`` from it.  The document must not
   contain ``provider_urls``, or Chrome ignores the other two members.
2. ``accounts_endpoint`` must be on the issuer's origin.  Chrome requests it with
   the issuer's cookies and ``Sec-Fetch-Dest: webidentity``; the session cookie
   therefore needs ``SameSite=None; Secure``.
3. One of the returned accounts must have the typed address as ``email``
   (compared case-insensitively).

Chrome also skips issuers it knows the user is signed out of (FedCM Login Status
API): send ``Set-Login: logged-in`` on a normal page response after login, or call
``navigator.login.setStatus("logged-in")``, and ``logged-out`` on logout.

:meth:`Issuer.accounts_response <pyevp.issuer.Issuer.accounts_response>` answers the
accounts request, :func:`web_identity_response` serves the well-known document, and
:func:`login_status_headers` gives the ``Set-Login`` header.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from pyevp.issuer.response import PUBLIC_CACHE, IssuerResponse

__all__ = [
    "FEDCM_FETCH_DEST",
    "WEB_IDENTITY_PATH",
    "login_status_headers",
    "web_identity_document",
    "web_identity_response",
]

FEDCM_FETCH_DEST = "webidentity"
"""``Sec-Fetch-Dest`` of Chrome's accounts request; refuse other requests."""

WEB_IDENTITY_PATH = "/.well-known/web-identity"
"""Where Chrome reads :func:`web_identity_document`, on the issuer's registrable domain."""


def web_identity_document(*, accounts_endpoint: str, login_url: str) -> dict[str, Any]:
    """Serve at ``https://<registrable domain>/.well-known/web-identity``."""
    return {"accounts_endpoint": accounts_endpoint, "login_url": login_url}


def web_identity_response(*, accounts_endpoint: str, login_url: str) -> IssuerResponse:
    """:func:`web_identity_document` as a response, cacheable for five minutes."""
    document = web_identity_document(accounts_endpoint=accounts_endpoint, login_url=login_url)
    return IssuerResponse.json(200, document, PUBLIC_CACHE)


def _accounts_document(emails: Iterable[str]) -> dict[str, Any]:
    """The accounts endpoint's document; see :meth:`Issuer.accounts_response`."""
    return {"accounts": [{"id": email, "email": email, "name": email} for email in emails]}


def login_status_headers(*, signed_in: bool) -> dict[str, str]:
    """The FedCM Login Status header to add to a page response after login or logout."""
    return {"Set-Login": "logged-in" if signed_in else "logged-out"}
