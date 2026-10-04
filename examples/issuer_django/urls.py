from __future__ import annotations

import json

from django.conf import settings
from django.http import HttpRequest
from django.urls import include, path
from django.views.generic import TemplateView

from pyevp.contrib.django.issuer import IssuerSite
from pyevp.issuer import Issuer, SigningKey


def _signer() -> SigningKey:
    if settings.EVP_SIGNING_KEY is None:
        return SigningKey.generate(kid="dev")
    with open(settings.EVP_SIGNING_KEY) as file:
        return SigningKey.from_jwk(json.load(file))


issuer = Issuer(
    issuer=settings.EVP_ISSUER,
    issuance_endpoint=f"{settings.EVP_PUBLIC_URL}/email-verification/issuance",
    jwks_uri=f"{settings.EVP_PUBLIC_URL}/email-verification/jwks",
    signer=_signer(),
    email_domains=settings.EVP_EMAIL_DOMAINS,
)


class Site(IssuerSite):
    def user_emails(self, request: HttpRequest) -> list[str]:
        # This example's accounts are created by the operator with the address of their
        # mailbox. A real issuer returns the addresses its mail system delivers to the user.
        user = getattr(request, "user", None)
        return [user.email] if user is not None and user.is_authenticated and user.email else []


evp = Site(issuer)

urlpatterns = [
    # The issuer's endpoints and, when the issuer's host is its own registrable
    # domain, Chrome's FedCM well-known.  Otherwise serve the latter there yourself.
    path("", include(evp.urls)),
    path("accounts/", include("django.contrib.auth.urls")),
    path("", TemplateView.as_view(template_name="home.html")),
]
